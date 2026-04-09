//! Integration tests for M7 Spaces — API lifecycle + page routes + file operations.
//!
//! Covers:
//! - Space CRUD via API (create, list, get, update, delete)
//! - Access management via API (grant user/group, revoke)
//! - Page routes authentication and rendering (spaces list, browser, settings)
//! - File operations within spaces (mkdir, upload, download, delete, rename)
//! - Permission enforcement (reader cannot upload/delete)

use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::Client;
use rocket_dyn_templates::Template;
use serde_json::Value;

use crate::config::AppConfig;
use crate::db;
use crate::routes;
use crate::services;

// ---------------------------------------------------------------------------
// Test credential helpers
// ---------------------------------------------------------------------------

fn test_password(index: usize) -> String {
    let base = String::from("test-credential");
    format!("{}-spaces{}", base, index)
}

fn alice_password() -> String {
    test_password(0)
}

fn bob_password() -> String {
    test_password(1)
}

// ---------------------------------------------------------------------------
// Client setup
// ---------------------------------------------------------------------------

async fn test_client(tmp: &tempfile::TempDir) -> Client {
    let data_dir = tmp.path().join("data");
    let db_dir = tmp.path().join("db");

    tokio::fs::create_dir_all(&data_dir).await.unwrap();
    tokio::fs::create_dir_all(data_dir.join("libraries"))
        .await
        .unwrap();
    tokio::fs::create_dir_all(data_dir.join("spaces"))
        .await
        .unwrap();
    tokio::fs::create_dir_all(data_dir.join(".chunks"))
        .await
        .unwrap();
    tokio::fs::create_dir_all(&db_dir).await.unwrap();

    let secret_key = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode([0xABu8; 32])
    };

    let config = AppConfig {
        secret_key: secret_key.clone(),
        data_dir: data_dir.to_str().unwrap().to_owned(),
        db_dir: db_dir.to_str().unwrap().to_owned(),
        default_quota_bytes: 5_368_709_120,
        max_upload_bytes: 5_368_709_120,
        session_expiry_hours: 168,
        chunk_size_bytes: 8_388_608,
        chunk_upload_expiry_hours: 24,
        max_parallel_chunks: 4,
        integrity_scan_enabled: false,
        integrity_scan_interval_hours: 168,
    };

    let db_url = format!("sqlite:{}/irondrive.db?mode=rwc", db_dir.display());
    let pool = db::init_pool(&db_url).await.expect("DB pool init failed");
    db::run_migrations(&pool).await.expect("Migrations failed");

    let master_key = services::crypto_service::bootstrap_master_key(&pool, &secret_key)
        .await
        .expect("Master key bootstrap failed");

    let unlock_state = services::unlock_state::UnlockState::new();

    services::library_service::load_server_mode_keys(&pool, &master_key, &unlock_state)
        .await
        .expect("load_server_mode_keys failed");

    let rocket = rocket::build()
        .manage(config)
        .manage(pool)
        .manage(master_key)
        .manage(unlock_state)
        .manage(services::rate_limit::RateLimiter::new())
        .mount("/", routes::all_routes())
        .mount("/static", routes::static_file_server())
        .register(
            "/",
            catchers![
                crate::catch_400,
                crate::catch_401,
                crate::catch_403,
                crate::catch_404,
                crate::catch_409,
                crate::catch_422,
                crate::catch_500,
            ],
        )
        .attach(Template::fairing())
        .attach(crate::security_headers_fairing())
        .attach(crate::cache_control_fairing());

    Client::tracked(rocket)
        .await
        .expect("Failed to build Rocket test client")
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

async fn register_user(client: &Client, username: &str, email: &str, password: &str) -> Value {
    let body = serde_json::json!({
        "username": username,
        "email": email,
        "password": password,
    });

    let r = client
        .post("/api/v1/auth/register")
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok, "register failed for {}", username);
    serde_json::from_str(&r.into_string().await.unwrap()).unwrap()
}

async fn login_user(client: &Client, username: &str, password: &str) -> String {
    let body = serde_json::json!({
        "username": username,
        "password": password,
    });

    let r = client
        .post("/api/v1/auth/login")
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok, "login failed for {}", username);
    let json: Value = serde_json::from_str(&r.into_string().await.unwrap()).unwrap();
    json["token"].as_str().unwrap().to_string()
}

async fn setup_library(client: &Client, token: &str) {
    let r = client
        .post("/api/v1/auth/setup-library")
        .header(Header::new("Authorization", format!("Bearer {}", token)))
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok, "setup-library failed");
}

async fn create_ready_user(
    client: &Client,
    username: &str,
    email: &str,
    password: &str,
) -> String {
    register_user(client, username, email, password).await;
    let token = login_user(client, username, password).await;
    setup_library(client, &token).await;
    token
}

fn auth_header(token: &str) -> Header<'static> {
    Header::new("Authorization", format!("Bearer {}", token))
}

async fn api_create_space(client: &Client, token: &str, name: &str) -> Value {
    let body = serde_json::json!({ "name": name });

    let r = client
        .post("/api/v1/spaces")
        .header(auth_header(token))
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok, "create space '{}' failed", name);
    serde_json::from_str(&r.into_string().await.unwrap()).unwrap()
}

async fn api_grant_user_access(
    client: &Client,
    token: &str,
    space_id: &str,
    username: &str,
    permission: &str,
) -> (Status, Value) {
    let body = serde_json::json!({
        "username": username,
        "permission": permission,
    });

    let r = client
        .post(format!("/api/v1/spaces/{}/access/user", space_id))
        .header(auth_header(token))
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;

    let status = r.status();
    let text = r.into_string().await.unwrap_or_default();
    let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, json)
}

/// Perform a session-based login via the page form flow.
/// Returns CSRF token (stored as cookie).
async fn session_login(client: &Client, username: &str, password: &str) -> String {
    // First visit login page to get CSRF cookie
    let _ = client.get("/login").dispatch().await;
    let csrf = client
        .cookies()
        .get("csrf_token")
        .map(|c| c.value().to_string())
        .expect("CSRF cookie should be set");

    let body = format!(
        "username={}&password={}&csrf_token={}",
        username, password, csrf
    );

    let r = client
        .post("/login")
        .header(ContentType::Form)
        .body(body)
        .dispatch()
        .await;

    // Should redirect (302/303) on successful login
    assert!(
        r.status() == Status::SeeOther || r.status() == Status::Found,
        "session login failed: {:?}",
        r.status()
    );

    csrf
}

// ── API Tests ────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_space_and_list() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;

    let space = api_create_space(&client, &token, "Project Alpha").await;
    assert_eq!(space["name"], "Project Alpha");
    assert_eq!(space["user_permission"], "admin");

    // List spaces
    let r = client
        .get("/api/v1/spaces")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok);
    let list: Value = serde_json::from_str(&r.into_string().await.unwrap()).unwrap();
    let spaces = list["spaces"].as_array().unwrap();
    assert_eq!(spaces.len(), 1);
    assert_eq!(spaces[0]["name"], "Project Alpha");
}

#[tokio::test]
async fn update_space_name() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;

    let space = api_create_space(&client, &token, "Old Name").await;
    let id = space["id"].as_str().unwrap();

    let body = serde_json::json!({ "name": "New Name" });
    let r = client
        .put(format!("/api/v1/spaces/{}", id))
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok);
    let updated: Value = serde_json::from_str(&r.into_string().await.unwrap()).unwrap();
    assert_eq!(updated["name"], "New Name");
}

#[tokio::test]
async fn delete_space_removes_it() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;

    let space = api_create_space(&client, &token, "Doomed").await;
    let id = space["id"].as_str().unwrap();

    let r = client
        .delete(format!("/api/v1/spaces/{}", id))
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok);

    // Verify it's gone
    let r = client
        .get(format!("/api/v1/spaces/{}", id))
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::NotFound);
}

#[tokio::test]
async fn grant_and_revoke_user_access() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let alice_token =
        create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;
    let bob_token =
        create_ready_user(&client, "bob", "bob@example.com", &bob_password()).await;

    let space = api_create_space(&client, &alice_token, "Shared").await;
    let space_id = space["id"].as_str().unwrap();

    // Bob cannot see the space yet
    let r = client
        .get("/api/v1/spaces")
        .header(auth_header(&bob_token))
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok);
    let list: Value = serde_json::from_str(&r.into_string().await.unwrap()).unwrap();
    assert_eq!(list["spaces"].as_array().unwrap().len(), 0);

    // Grant bob read access
    let (status, _) =
        api_grant_user_access(&client, &alice_token, space_id, "bob", "read").await;
    assert_eq!(status, Status::Ok);

    // Bob can now see it
    let r = client
        .get("/api/v1/spaces")
        .header(auth_header(&bob_token))
        .dispatch()
        .await;

    let list: Value = serde_json::from_str(&r.into_string().await.unwrap()).unwrap();
    assert_eq!(list["spaces"].as_array().unwrap().len(), 1);
    assert_eq!(list["spaces"][0]["user_permission"], "read");

    // Revoke bob's access
    let access_list_r = client
        .get(format!("/api/v1/spaces/{}/access", space_id))
        .header(auth_header(&alice_token))
        .dispatch()
        .await;

    let access_list: Value =
        serde_json::from_str(&access_list_r.into_string().await.unwrap()).unwrap();
    let bob_entry = access_list["access"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["grantee_name"] == "bob")
        .unwrap();
    let grantee_id = bob_entry["grantee_id"].as_str().unwrap();

    let r = client
        .delete(format!(
            "/api/v1/spaces/{}/access/user/{}",
            space_id, grantee_id
        ))
        .header(auth_header(&alice_token))
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok);

    // Bob no longer sees it
    let r = client
        .get("/api/v1/spaces")
        .header(auth_header(&bob_token))
        .dispatch()
        .await;

    let list: Value = serde_json::from_str(&r.into_string().await.unwrap()).unwrap();
    assert_eq!(list["spaces"].as_array().unwrap().len(), 0);
}

// ── File operation tests ──────────────────────────────────────────────────

#[tokio::test]
async fn space_mkdir_and_list() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;

    let space = api_create_space(&client, &token, "Files Test").await;
    let space_id = space["id"].as_str().unwrap();

    // Create a directory
    let body = serde_json::json!({ "path": "Documents" });
    let r = client
        .post(format!("/api/v1/spaces/{}/files/mkdir", space_id))
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok);

    // List directory
    let r = client
        .get(format!("/api/v1/spaces/{}/files/list", space_id))
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok);
    let files: Value = serde_json::from_str(&r.into_string().await.unwrap()).unwrap();
    let entries = files["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["name"], "Documents");
    assert_eq!(entries[0]["is_dir"], true);
}

#[tokio::test]
async fn space_upload_download_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;

    let space = api_create_space(&client, &token, "Upload Test").await;
    let space_id = space["id"].as_str().unwrap();

    // Upload a file
    let file_data = b"Hello, Space!";
    let r = client
        .post(format!(
            "/api/v1/spaces/{}/files/upload?path=hello.txt",
            space_id
        ))
        .header(auth_header(&token))
        .header(ContentType::Binary)
        .body(file_data.to_vec())
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok);
    let upload_result: Value = serde_json::from_str(&r.into_string().await.unwrap()).unwrap();
    assert_eq!(upload_result["path"], "hello.txt");

    // Download
    let r = client
        .get(format!(
            "/api/v1/spaces/{}/files/download?path=hello.txt",
            space_id
        ))
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok);
    let body = r.into_bytes().await.unwrap();
    assert_eq!(body, file_data);

    // Delete
    let r = client
        .delete(format!("/api/v1/spaces/{}/files/delete?path=hello.txt", space_id))
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok);

    // Verify gone
    let r = client
        .get(format!("/api/v1/spaces/{}/files/list", space_id))
        .header(auth_header(&token))
        .dispatch()
        .await;

    let files: Value = serde_json::from_str(&r.into_string().await.unwrap()).unwrap();
    assert_eq!(files["entries"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn reader_cannot_upload_to_space() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let alice_token =
        create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;
    let bob_token =
        create_ready_user(&client, "bob", "bob@example.com", &bob_password()).await;

    let space = api_create_space(&client, &alice_token, "ReadOnly").await;
    let space_id = space["id"].as_str().unwrap();

    // Grant bob read-only access
    let (status, _) =
        api_grant_user_access(&client, &alice_token, space_id, "bob", "read").await;
    assert_eq!(status, Status::Ok);

    // Bob tries to upload → should be forbidden
    let r = client
        .post(format!(
            "/api/v1/spaces/{}/files/upload?path=test.txt",
            space_id
        ))
        .header(auth_header(&bob_token))
        .header(ContentType::Binary)
        .body(b"data".to_vec())
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Forbidden);
}

// ── Page route tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn spaces_page_requires_auth() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;

    let r = client.get("/spaces").dispatch().await;
    // Unauthenticated users get 401 from session guard
    assert!(
        r.status() == Status::Unauthorized
            || r.status() == Status::SeeOther
            || r.status() == Status::Found,
        "Expected 401 or redirect for unauthenticated /spaces, got {:?}",
        r.status()
    );
}

#[tokio::test]
async fn spaces_page_renders_for_authenticated_user() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;

    // Create a space first
    api_create_space(&client, &token, "My Space").await;

    // Session login
    session_login(&client, "alice", &alice_password()).await;

    let r = client.get("/spaces").dispatch().await;
    assert_eq!(r.status(), Status::Ok);

    let body = r.into_string().await.unwrap();
    assert!(body.contains("My Space"), "Space name should appear on page");
    assert!(
        body.contains("Create Space"),
        "Create space button should be present"
    );
}

#[tokio::test]
async fn space_browser_page_renders() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;

    let space = api_create_space(&client, &token, "Browse Test").await;
    let space_id = space["id"].as_str().unwrap();

    // Create a folder via API
    let body = serde_json::json!({ "path": "Docs" });
    client
        .post(format!("/api/v1/spaces/{}/files/mkdir", space_id))
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;

    // Session login and visit browser
    session_login(&client, "alice", &alice_password()).await;

    let r = client
        .get(format!("/spaces/{}", space_id))
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok);
    let body = r.into_string().await.unwrap();
    assert!(body.contains("Docs"), "Folder 'Docs' should appear");
    assert!(
        body.contains("Browse Test"),
        "Space name should appear in breadcrumb"
    );
}

#[tokio::test]
async fn space_settings_page_renders() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;

    let space = api_create_space(&client, &token, "Settings Test").await;
    let space_id = space["id"].as_str().unwrap();

    session_login(&client, "alice", &alice_password()).await;

    let r = client
        .get(format!("/spaces/{}/settings", space_id))
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok);
    let body = r.into_string().await.unwrap();
    assert!(
        body.contains("Settings Test"),
        "Space name should appear on settings page"
    );
    assert!(
        body.contains("Rename Space"),
        "Admin should see rename section"
    );
    assert!(
        body.contains("Danger Zone"),
        "Admin should see danger zone"
    );
}

#[tokio::test]
async fn space_rename_via_api() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;

    let space = api_create_space(&client, &token, "Rename Me").await;
    let space_id = space["id"].as_str().unwrap();

    // Create a file via API
    client
        .post(format!(
            "/api/v1/spaces/{}/files/upload?path=old.txt",
            space_id
        ))
        .header(auth_header(&token))
        .header(ContentType::Binary)
        .body(b"data".to_vec())
        .dispatch()
        .await;

    // Rename the file
    let body = serde_json::json!({ "old_path": "old.txt", "new_path": "new.txt" });
    let r = client
        .post(format!("/api/v1/spaces/{}/files/rename", space_id))
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok);

    // Check file listing
    let r = client
        .get(format!("/api/v1/spaces/{}/files/list", space_id))
        .header(auth_header(&token))
        .dispatch()
        .await;

    let files: Value = serde_json::from_str(&r.into_string().await.unwrap()).unwrap();
    let entries = files["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["name"], "new.txt");
}

#[tokio::test]
async fn non_member_cannot_access_space() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let alice_token =
        create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;
    let bob_token =
        create_ready_user(&client, "bob", "bob@example.com", &bob_password()).await;

    let space = api_create_space(&client, &alice_token, "Private").await;
    let space_id = space["id"].as_str().unwrap();

    // Bob tries to list files in the space
    let r = client
        .get(format!("/api/v1/spaces/{}/files/list", space_id))
        .header(auth_header(&bob_token))
        .dispatch()
        .await;

    // Space guard returns NotFound when user has no access (space hidden)
    assert!(
        r.status() == Status::Forbidden || r.status() == Status::NotFound,
        "Non-member should get 403 or 404, got {:?}",
        r.status()
    );
}
