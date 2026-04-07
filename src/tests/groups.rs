//! Integration tests for M6 Groups — API + page routes.
//!
//! Covers:
//! - Group CRUD lifecycle (create, read, update, delete)
//! - Membership management (add, remove, role update)
//! - Permission enforcement (owner, manager, member, non-member)
//! - Duplicate / conflict handling
//! - Page routes for authenticated users
//! - CSRF validation on form POSTs
//! - Unauthenticated access → 401

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
    format!("{}-groups{}", base, index)
}

fn alice_password() -> String {
    test_password(0)
}

fn bob_password() -> String {
    test_password(1)
}

fn charlie_password() -> String {
    test_password(2)
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

/// Register + login + setup-library. Returns bearer token.
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

/// Create a group via API. Returns the group JSON.
async fn api_create_group(
    client: &Client,
    token: &str,
    name: &str,
    description: Option<&str>,
) -> Value {
    let body = serde_json::json!({
        "name": name,
        "description": description,
    });

    let r = client
        .post("/api/v1/groups")
        .header(auth_header(token))
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok, "create group '{}' failed", name);
    serde_json::from_str(&r.into_string().await.unwrap()).unwrap()
}

/// Add a member via API.
async fn api_add_member(
    client: &Client,
    token: &str,
    group_id: &str,
    username: &str,
    role: &str,
) -> (Status, Value) {
    let body = serde_json::json!({
        "username": username,
        "role": role,
    });

    let r = client
        .post(format!("/api/v1/groups/{}/members", group_id))
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

/// Get CSRF token from a page visit.
async fn get_csrf_token(client: &Client, path: &str) -> String {
    let _ = client.get(path).dispatch().await;
    client
        .cookies()
        .get("csrf_token")
        .map(|c| c.value().to_string())
        .expect("CSRF cookie should be set after GET")
}

// ── API Tests ────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_group_appears_in_list() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;

    let group = api_create_group(&client, &token, "Devs", Some("Developer team")).await;
    assert_eq!(group["name"], "Devs");
    assert_eq!(group["user_role"], "owner");
    assert_eq!(group["member_count"], 1);

    // List groups
    let r = client
        .get("/api/v1/groups")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok);
    let list: Value = serde_json::from_str(&r.into_string().await.unwrap()).unwrap();
    let groups = list["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["name"], "Devs");
}

#[tokio::test]
async fn create_duplicate_group_name_conflict() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;

    api_create_group(&client, &token, "Dupes", None).await;

    // Try again with same name
    let body = serde_json::json!({ "name": "Dupes" });
    let r = client
        .post("/api/v1/groups")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Conflict);
}

#[tokio::test]
async fn get_group_detail_correct() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;

    let group = api_create_group(&client, &token, "Team", Some("A team")).await;
    let id = group["id"].as_str().unwrap();

    let r = client
        .get(format!("/api/v1/groups/{}", id))
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok);
    let detail: Value = serde_json::from_str(&r.into_string().await.unwrap()).unwrap();
    assert_eq!(detail["name"], "Team");
    assert_eq!(detail["description"], "A team");
    assert_eq!(detail["user_role"], "owner");
}

#[tokio::test]
async fn update_group_name_and_description() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;

    let group = api_create_group(&client, &token, "Old", Some("Old desc")).await;
    let id = group["id"].as_str().unwrap();

    let body = serde_json::json!({ "name": "New", "description": "New desc" });
    let r = client
        .put(format!("/api/v1/groups/{}", id))
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok);
    let updated: Value = serde_json::from_str(&r.into_string().await.unwrap()).unwrap();
    assert_eq!(updated["name"], "New");
    assert_eq!(updated["description"], "New desc");
}

#[tokio::test]
async fn delete_group_removes_it() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;

    let group = api_create_group(&client, &token, "Doomed", None).await;
    let id = group["id"].as_str().unwrap();

    let r = client
        .delete(format!("/api/v1/groups/{}", id))
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok);

    // Verify it's gone
    let r = client
        .get(format!("/api/v1/groups/{}", id))
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::NotFound);
}

#[tokio::test]
async fn add_member_appears_in_list() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let alice_tok =
        create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;
    let _bob_tok = create_ready_user(&client, "bob", "bob@example.com", &bob_password()).await;

    let group = api_create_group(&client, &alice_tok, "Team", None).await;
    let id = group["id"].as_str().unwrap();

    let (status, member) = api_add_member(&client, &alice_tok, id, "bob", "member").await;
    assert_eq!(status, Status::Ok);
    assert_eq!(member["username"], "bob");
    assert_eq!(member["role"], "member");

    // Verify member list
    let r = client
        .get(format!("/api/v1/groups/{}/members", id))
        .header(auth_header(&alice_tok))
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok);
    let list: Value = serde_json::from_str(&r.into_string().await.unwrap()).unwrap();
    let members = list["members"].as_array().unwrap();
    assert_eq!(members.len(), 2); // alice + bob
}

#[tokio::test]
async fn remove_member_gone_from_list() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let alice_tok =
        create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;
    let _bob_tok = create_ready_user(&client, "bob", "bob@example.com", &bob_password()).await;

    let group = api_create_group(&client, &alice_tok, "Team", None).await;
    let id = group["id"].as_str().unwrap();

    let (s, member) = api_add_member(&client, &alice_tok, id, "bob", "member").await;
    assert_eq!(s, Status::Ok);
    let bob_uid = member["user_id"].as_str().unwrap();

    let r = client
        .delete(format!("/api/v1/groups/{}/members/{}", id, bob_uid))
        .header(auth_header(&alice_tok))
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok);

    // Verify bob is gone
    let r = client
        .get(format!("/api/v1/groups/{}/members", id))
        .header(auth_header(&alice_tok))
        .dispatch()
        .await;

    let list: Value = serde_json::from_str(&r.into_string().await.unwrap()).unwrap();
    let members = list["members"].as_array().unwrap();
    assert_eq!(members.len(), 1); // only alice
}

#[tokio::test]
async fn owner_cannot_be_removed() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let alice_tok =
        create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;
    let bob_tok = create_ready_user(&client, "bob", "bob@example.com", &bob_password()).await;

    let group = api_create_group(&client, &alice_tok, "Team", None).await;
    let id = group["id"].as_str().unwrap();
    let owner_id = group["created_by"].as_str().unwrap();

    // Add bob as manager
    api_add_member(&client, &alice_tok, id, "bob", "manager").await;

    // Bob tries to remove alice (owner)
    let r = client
        .delete(format!("/api/v1/groups/{}/members/{}", id, owner_id))
        .header(auth_header(&bob_tok))
        .dispatch()
        .await;

    // Should be rejected
    assert!(
        [Status::Forbidden, Status::BadRequest].contains(&r.status()),
        "Expected 403 or 400 when removing owner, got {}",
        r.status()
    );
}

#[tokio::test]
async fn non_member_cannot_access_group() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let alice_tok =
        create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;
    let bob_tok = create_ready_user(&client, "bob", "bob@example.com", &bob_password()).await;

    let group = api_create_group(&client, &alice_tok, "Secret", None).await;
    let id = group["id"].as_str().unwrap();

    // Bob is not a member — should get 403 or 404
    let r = client
        .get(format!("/api/v1/groups/{}", id))
        .header(auth_header(&bob_tok))
        .dispatch()
        .await;

    assert!(
        [Status::Forbidden, Status::NotFound].contains(&r.status()),
        "Non-member should not access group, got {}",
        r.status()
    );
}

#[tokio::test]
async fn member_cannot_add_or_remove_or_edit() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let alice_tok =
        create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;
    let bob_tok = create_ready_user(&client, "bob", "bob@example.com", &bob_password()).await;
    let _charlie_tok =
        create_ready_user(&client, "charlie", "charlie@example.com", &charlie_password()).await;

    let group = api_create_group(&client, &alice_tok, "Strict", None).await;
    let id = group["id"].as_str().unwrap();

    // Add bob as plain member
    api_add_member(&client, &alice_tok, id, "bob", "member").await;

    // Bob tries to add charlie — should fail
    let (s, _) = api_add_member(&client, &bob_tok, id, "charlie", "member").await;
    assert_eq!(s, Status::Forbidden, "member should not add members");

    // Bob tries to edit group — should fail
    let body = serde_json::json!({ "name": "Hacked", "description": "Nope" });
    let r = client
        .put(format!("/api/v1/groups/{}", id))
        .header(auth_header(&bob_tok))
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Forbidden, "member should not edit group");

    // Bob tries to delete group — should fail
    let r = client
        .delete(format!("/api/v1/groups/{}", id))
        .header(auth_header(&bob_tok))
        .dispatch()
        .await;

    assert_eq!(
        r.status(),
        Status::Forbidden,
        "member should not delete group"
    );
}

#[tokio::test]
async fn unauthenticated_api_returns_401() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;

    let r = client.get("/api/v1/groups").dispatch().await;
    assert_eq!(r.status(), Status::Unauthorized);

    let body = serde_json::json!({ "name": "Nope" });
    let r = client
        .post("/api/v1/groups")
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Unauthorized);
}

// ── Page route tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn groups_page_renders_for_authenticated_user() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;

    let pw = alice_password();
    register_user(&client, "alice", "alice@example.com", &pw).await;
    let token = login_user(&client, "alice", &pw).await;
    setup_library(&client, &token).await;

    // Login via page form to get session cookie
    let csrf = get_csrf_token(&client, "/login").await;
    let r = client
        .post("/login")
        .header(ContentType::Form)
        .body(format!("username=alice&password={}&csrf_token={}", pw, csrf))
        .dispatch()
        .await;
    assert_eq!(r.status(), Status::SeeOther);

    // Now visit /groups
    let r = client.get("/groups").dispatch().await;
    assert_eq!(r.status(), Status::Ok);
    let body = r.into_string().await.unwrap_or_default();
    assert!(
        body.contains("Groups") || body.contains("groups"),
        "Groups page should render"
    );
}

#[tokio::test]
async fn group_detail_page_renders() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;

    let pw = alice_password();
    register_user(&client, "alice", "alice@example.com", &pw).await;
    let token = login_user(&client, "alice", &pw).await;
    setup_library(&client, &token).await;

    // Create a group via API
    let group = api_create_group(&client, &token, "TestGroup", Some("Test")).await;
    let id = group["id"].as_str().unwrap();

    // Login via page form
    let csrf = get_csrf_token(&client, "/login").await;
    client
        .post("/login")
        .header(ContentType::Form)
        .body(format!("username=alice&password={}&csrf_token={}", pw, csrf))
        .dispatch()
        .await;

    let r = client.get(format!("/groups/{}", id)).dispatch().await;
    assert_eq!(r.status(), Status::Ok);
    let body = r.into_string().await.unwrap_or_default();
    assert!(
        body.contains("TestGroup"),
        "Detail page should show group name"
    );
    assert!(
        body.contains("alice"),
        "Detail page should show owner username"
    );
}

#[tokio::test]
async fn unauthenticated_groups_page_redirects() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;

    let r = client.get("/groups").dispatch().await;
    assert!(
        [Status::SeeOther, Status::Unauthorized, Status::NotFound].contains(&r.status()),
        "Unauthenticated /groups should redirect or error, got {}",
        r.status()
    );
}

#[tokio::test]
async fn csrf_required_on_group_form_posts() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;

    let pw = alice_password();
    register_user(&client, "alice", "alice@example.com", &pw).await;
    let token = login_user(&client, "alice", &pw).await;
    setup_library(&client, &token).await;

    // Login via page form
    let csrf = get_csrf_token(&client, "/login").await;
    client
        .post("/login")
        .header(ContentType::Form)
        .body(format!("username=alice&password={}&csrf_token={}", pw, csrf))
        .dispatch()
        .await;

    // POST /groups/create without csrf_token field → 422 (missing field)
    let r = client
        .post("/groups/create")
        .header(ContentType::Form)
        .body("name=Bad&description=No+CSRF")
        .dispatch()
        .await;

    assert_eq!(
        r.status(),
        Status::UnprocessableEntity,
        "Missing CSRF field should be 422"
    );
}

#[tokio::test]
async fn manager_can_add_members_and_edit() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let alice_tok =
        create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;
    let bob_tok = create_ready_user(&client, "bob", "bob@example.com", &bob_password()).await;
    let _charlie_tok =
        create_ready_user(&client, "charlie", "charlie@example.com", &charlie_password()).await;

    let group = api_create_group(&client, &alice_tok, "Team", None).await;
    let id = group["id"].as_str().unwrap();

    // Alice adds Bob as manager
    let (s, _) = api_add_member(&client, &alice_tok, id, "bob", "manager").await;
    assert_eq!(s, Status::Ok);

    // Bob (manager) can add charlie
    let (s, _) = api_add_member(&client, &bob_tok, id, "charlie", "member").await;
    assert_eq!(s, Status::Ok, "manager should be able to add members");

    // Bob (manager) can edit the group
    let body = serde_json::json!({ "name": "Updated Team", "description": "By Bob" });
    let r = client
        .put(format!("/api/v1/groups/{}", id))
        .header(auth_header(&bob_tok))
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok, "manager should be able to edit");

    // But Bob (manager) cannot delete the group
    let r = client
        .delete(format!("/api/v1/groups/{}", id))
        .header(auth_header(&bob_tok))
        .dispatch()
        .await;

    assert_eq!(
        r.status(),
        Status::Forbidden,
        "manager should not be able to delete"
    );
}

#[tokio::test]
async fn update_member_role() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let alice_tok =
        create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;
    let _bob_tok = create_ready_user(&client, "bob", "bob@example.com", &bob_password()).await;

    let group = api_create_group(&client, &alice_tok, "Team", None).await;
    let id = group["id"].as_str().unwrap();

    let (s, member) = api_add_member(&client, &alice_tok, id, "bob", "member").await;
    assert_eq!(s, Status::Ok);
    let bob_uid = member["user_id"].as_str().unwrap();

    // Promote bob to manager
    let body = serde_json::json!({ "role": "manager" });
    let r = client
        .put(format!("/api/v1/groups/{}/members/{}", id, bob_uid))
        .header(auth_header(&alice_tok))
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok);
    let updated: Value = serde_json::from_str(&r.into_string().await.unwrap()).unwrap();
    assert_eq!(updated["role"], "manager");
}

#[tokio::test]
async fn add_duplicate_member_conflict() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let alice_tok =
        create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;
    let _bob_tok = create_ready_user(&client, "bob", "bob@example.com", &bob_password()).await;

    let group = api_create_group(&client, &alice_tok, "Team", None).await;
    let id = group["id"].as_str().unwrap();

    let (s, _) = api_add_member(&client, &alice_tok, id, "bob", "member").await;
    assert_eq!(s, Status::Ok);

    // Try adding bob again
    let (s, _) = api_add_member(&client, &alice_tok, id, "bob", "member").await;
    assert_eq!(s, Status::Conflict, "adding duplicate member should conflict");
}

#[tokio::test]
async fn add_nonexistent_user_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let alice_tok =
        create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;

    let group = api_create_group(&client, &alice_tok, "Team", None).await;
    let id = group["id"].as_str().unwrap();

    let (s, _) = api_add_member(&client, &alice_tok, id, "ghost", "member").await;
    assert_eq!(s, Status::NotFound, "nonexistent user should be 404");
}

#[tokio::test]
async fn member_can_self_leave() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let alice_tok =
        create_ready_user(&client, "alice", "alice@example.com", &alice_password()).await;
    let bob_tok = create_ready_user(&client, "bob", "bob@example.com", &bob_password()).await;

    let group = api_create_group(&client, &alice_tok, "Team", None).await;
    let id = group["id"].as_str().unwrap();

    let (s, member) = api_add_member(&client, &alice_tok, id, "bob", "member").await;
    assert_eq!(s, Status::Ok);
    let bob_uid = member["user_id"].as_str().unwrap();

    // Bob removes himself
    let r = client
        .delete(format!("/api/v1/groups/{}/members/{}", id, bob_uid))
        .header(auth_header(&bob_tok))
        .dispatch()
        .await;

    assert_eq!(r.status(), Status::Ok, "member should be able to self-leave");
}
