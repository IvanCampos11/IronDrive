//! Integration tests for the M5 filesystem library endpoints.
//!
//! These tests spin up a full Rocket test client (with DB, crypto, unlock state)
//! and exercise the HTTP endpoints end-to-end:
//!
//! - List / Info / Usage on empty library
//! - Upload → Download roundtrip (including integrity header verification)
//! - Mkdir, Rename, Delete
//! - Path traversal rejection at the HTTP layer
//! - Auth / setup guards
//! - Upload size limits
//! - Integrity checking via query parameter

use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::Client;
use rocket::serde::json::serde_json;
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
    format!("{}-user{}", base, index)
}

fn alice_password() -> String {
    test_password(0)
}

fn bob_password() -> String {
    test_password(1)
}

// ---------------------------------------------------------------------------
// Test client builder
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
        max_upload_bytes: 1_048_576, // 1 MiB for tests
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
        .attach(Template::fairing());

    Client::tracked(rocket)
        .await
        .expect("Failed to build Rocket test client")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn register_user(client: &Client, username: &str, email: &str, password: &str) -> Value {
    let body = serde_json::json!({
        "username": username,
        "email": email,
        "password": password,
    });

    let response = client
        .post("/api/v1/auth/register")
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok, "register failed");
    let text = response.into_string().await.unwrap();
    serde_json::from_str(&text).unwrap()
}

async fn login_user(client: &Client, username: &str, password: &str) -> String {
    let body = serde_json::json!({
        "username": username,
        "password": password,
    });

    let response = client
        .post("/api/v1/auth/login")
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok, "login failed");
    let text = response.into_string().await.unwrap();
    let json: Value = serde_json::from_str(&text).unwrap();
    json["token"].as_str().unwrap().to_string()
}

async fn setup_library(client: &Client, token: &str) -> Value {
    let response = client
        .post("/api/v1/auth/setup-library")
        .header(Header::new("Authorization", format!("Bearer {}", token)))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok, "setup-library failed");
    let text = response.into_string().await.unwrap();
    serde_json::from_str(&text).unwrap()
}

/// Register + login + setup-library. Returns the bearer token.
async fn create_ready_user(client: &Client, username: &str, email: &str, password: &str) -> String {
    register_user(client, username, email, password).await;
    let token = login_user(client, username, password).await;
    setup_library(client, &token).await;
    token
}

fn auth_header(token: &str) -> Header<'static> {
    Header::new("Authorization", format!("Bearer {}", token))
}

// ---------------------------------------------------------------------------
// Tests — Auth & Setup Guards
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_without_auth_returns_401() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;

    let response = client.get("/api/v1/library/list").dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized);
}

#[tokio::test]
async fn list_before_setup_returns_403() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();

    register_user(&client, "alice", "alice@example.com", &pw).await;
    let token = login_user(&client, "alice", &pw).await;
    // NOT calling setup_library

    let response = client
        .get("/api/v1/library/list")
        .header(auth_header(&token))
        .dispatch()
        .await;

    // SetupComplete guard returns 403 when setup_complete is false
    assert_eq!(response.status(), Status::Forbidden);
}

#[tokio::test]
async fn upload_without_auth_returns_401() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;

    let response = client
        .post("/api/v1/library/upload?path=file.txt")
        .body("hello")
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Unauthorized);
}

#[tokio::test]
async fn download_without_auth_returns_401() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;

    let response = client
        .get("/api/v1/library/download?path=file.txt")
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Unauthorized);
}

// ---------------------------------------------------------------------------
// Tests — List
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_empty_library_root() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    let response = client
        .get("/api/v1/library/list")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let text = response.into_string().await.unwrap();
    let json: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["path"], "");
    assert!(json["entries"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn list_after_upload_shows_file() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    // Upload a file
    let response = client
        .post("/api/v1/library/upload?path=hello.txt")
        .header(auth_header(&token))
        .body("Hello, IronDrive!")
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    // List root
    let response = client
        .get("/api/v1/library/list")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    let entries = json["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["name"], "hello.txt");
    assert_eq!(entries[0]["is_dir"], false);
    assert_eq!(entries[0]["size"], 17); // "Hello, IronDrive!".len()
    assert_eq!(entries[0]["mime_type"], "text/plain");
    assert!(entries[0]["disk_size"].as_u64().unwrap() > 17);
    assert!(entries[0]["modified"].is_string());
}

#[tokio::test]
async fn list_shows_directories_first() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    // Create dir
    let response = client
        .post("/api/v1/library/mkdir")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(serde_json::json!({"path": "photos"}).to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    // Upload file
    client
        .post("/api/v1/library/upload?path=readme.txt")
        .header(auth_header(&token))
        .body("readme")
        .dispatch()
        .await;

    // List
    let response = client
        .get("/api/v1/library/list")
        .header(auth_header(&token))
        .dispatch()
        .await;

    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    let entries = json["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["name"], "photos");
    assert_eq!(entries[0]["is_dir"], true);
    assert_eq!(entries[1]["name"], "readme.txt");
    assert_eq!(entries[1]["is_dir"], false);
}

#[tokio::test]
async fn list_subdirectory() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    // Upload files in a subdirectory
    client
        .post("/api/v1/library/upload?path=docs/a.txt")
        .header(auth_header(&token))
        .body("aaa")
        .dispatch()
        .await;

    client
        .post("/api/v1/library/upload?path=docs/b.txt")
        .header(auth_header(&token))
        .body("bbb")
        .dispatch()
        .await;

    let response = client
        .get("/api/v1/library/list?path=docs")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    let entries = json["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["name"], "a.txt");
    assert_eq!(entries[1]["name"], "b.txt");
}

#[tokio::test]
async fn list_nonexistent_directory_returns_404() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    let response = client
        .get("/api/v1/library/list?path=nonexistent")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NotFound);
}

#[tokio::test]
async fn list_hides_irondrive_meta() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    // The .irondrive.meta file was created by setup_library.
    // Listing should not show it.
    let response = client
        .get("/api/v1/library/list")
        .header(auth_header(&token))
        .dispatch()
        .await;

    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    let entries = json["entries"].as_array().unwrap();

    // No entries should have .irondrive.meta
    for entry in entries {
        assert_ne!(entry["name"], ".irondrive.meta");
    }
}

// ---------------------------------------------------------------------------
// Tests — Upload / Download Roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upload_and_download_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    let plaintext = "Hello, encrypted world! 🔐";

    // Upload
    let response = client
        .post("/api/v1/library/upload?path=greeting.txt")
        .header(auth_header(&token))
        .body(plaintext)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let upload_json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();

    assert_eq!(upload_json["path"], "greeting.txt");
    assert_eq!(upload_json["size"], plaintext.len() as u64);
    assert!(upload_json["disk_size"].as_u64().unwrap() > plaintext.len() as u64);
    assert_eq!(upload_json["mime_type"], "text/plain");
    assert!(upload_json["checksum_sha256"].is_string());
    let upload_checksum = upload_json["checksum_sha256"].as_str().unwrap();

    // Download
    let response = client
        .get("/api/v1/library/download?path=greeting.txt")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);

    // Check integrity header
    let integrity_header = response
        .headers()
        .get_one("X-IronDrive-Integrity")
        .expect("missing X-IronDrive-Integrity header");

    assert_eq!(integrity_header, upload_checksum);

    // Check Content-Disposition
    let disposition = response
        .headers()
        .get_one("Content-Disposition")
        .expect("missing Content-Disposition header");
    assert!(disposition.contains("greeting.txt"));

    // Check body
    let body = response.into_string().await.unwrap();
    assert_eq!(body, plaintext);
}

#[tokio::test]
async fn upload_empty_file_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    let response = client
        .post("/api/v1/library/upload?path=empty.bin")
        .header(auth_header(&token))
        .body(Vec::<u8>::new())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    assert_eq!(json["size"], 0);

    let response = client
        .get("/api/v1/library/download?path=empty.bin")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let body = response.into_bytes().await.unwrap();
    assert!(body.is_empty());
}

#[tokio::test]
async fn upload_creates_parent_directories() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    let response = client
        .post("/api/v1/library/upload?path=a/b/c/deep.txt")
        .header(auth_header(&token))
        .body("deep file")
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);

    // Verify we can list the intermediate directory
    let response = client
        .get("/api/v1/library/list?path=a/b/c")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    let entries = json["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["name"], "deep.txt");
}

#[tokio::test]
async fn upload_overwrites_existing_file() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    // Upload v1
    client
        .post("/api/v1/library/upload?path=file.txt")
        .header(auth_header(&token))
        .body("version 1")
        .dispatch()
        .await;

    // Upload v2
    client
        .post("/api/v1/library/upload?path=file.txt")
        .header(auth_header(&token))
        .body("version 2")
        .dispatch()
        .await;

    // Download
    let response = client
        .get("/api/v1/library/download?path=file.txt")
        .header(auth_header(&token))
        .dispatch()
        .await;

    let body = response.into_string().await.unwrap();
    assert_eq!(body, "version 2");
}

#[tokio::test]
async fn upload_with_write_verify() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    let response = client
        .post("/api/v1/library/upload?path=verified.txt&verify=true")
        .header(auth_header(&token))
        .body("verified content")
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);

    let response = client
        .get("/api/v1/library/download?path=verified.txt")
        .header(auth_header(&token))
        .dispatch()
        .await;

    let body = response.into_string().await.unwrap();
    assert_eq!(body, "verified content");
}

#[tokio::test]
async fn download_nonexistent_file_returns_404() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    let response = client
        .get("/api/v1/library/download?path=ghost.txt")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NotFound);
}

#[tokio::test]
async fn download_directory_returns_400() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    client
        .post("/api/v1/library/mkdir")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(serde_json::json!({"path": "mydir"}).to_string())
        .dispatch()
        .await;

    let response = client
        .get("/api/v1/library/download?path=mydir")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::BadRequest);
}

// ---------------------------------------------------------------------------
// Tests — Mkdir
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mkdir_creates_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    let response = client
        .post("/api/v1/library/mkdir")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(serde_json::json!({"path": "documents"}).to_string())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    assert_eq!(json["path"], "documents");

    // List should show it
    let response = client
        .get("/api/v1/library/list")
        .header(auth_header(&token))
        .dispatch()
        .await;

    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    let entries = json["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["name"], "documents");
    assert_eq!(entries[0]["is_dir"], true);
}

#[tokio::test]
async fn mkdir_nested() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    let response = client
        .post("/api/v1/library/mkdir")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(serde_json::json!({"path": "a/b/c"}).to_string())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);

    // List the nested dir
    let response = client
        .get("/api/v1/library/list?path=a/b")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    let entries = json["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["name"], "c");
}

#[tokio::test]
async fn mkdir_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    for _ in 0..3 {
        let response = client
            .post("/api/v1/library/mkdir")
            .header(auth_header(&token))
            .header(ContentType::JSON)
            .body(serde_json::json!({"path": "photos"}).to_string())
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
    }
}

// ---------------------------------------------------------------------------
// Tests — Delete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_file() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    client
        .post("/api/v1/library/upload?path=to-delete.txt")
        .header(auth_header(&token))
        .body("bye")
        .dispatch()
        .await;

    let response = client
        .delete("/api/v1/library/delete?path=to-delete.txt")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);

    // Verify it's gone
    let response = client
        .get("/api/v1/library/download?path=to-delete.txt")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NotFound);
}

#[tokio::test]
async fn delete_directory_recursive() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    // Create nested structure
    client
        .post("/api/v1/library/upload?path=dir/sub/file.txt")
        .header(auth_header(&token))
        .body("deep")
        .dispatch()
        .await;

    // Delete the top-level dir
    let response = client
        .delete("/api/v1/library/delete?path=dir")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);

    // Verify the whole tree is gone
    let response = client
        .get("/api/v1/library/list?path=dir")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NotFound);
}

#[tokio::test]
async fn delete_nonexistent_returns_404() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    let response = client
        .delete("/api/v1/library/delete?path=ghost.txt")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NotFound);
}

// ---------------------------------------------------------------------------
// Tests — Rename
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rename_file() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    client
        .post("/api/v1/library/upload?path=old.txt")
        .header(auth_header(&token))
        .body("content")
        .dispatch()
        .await;

    let response = client
        .post("/api/v1/library/rename")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(serde_json::json!({"old_path": "old.txt", "new_path": "new.txt"}).to_string())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    assert_eq!(json["old_path"], "old.txt");
    assert_eq!(json["new_path"], "new.txt");

    // Old path gone
    let response = client
        .get("/api/v1/library/download?path=old.txt")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::NotFound);

    // New path works
    let response = client
        .get("/api/v1/library/download?path=new.txt")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let body = response.into_string().await.unwrap();
    assert_eq!(body, "content");
}

#[tokio::test]
async fn rename_move_to_subdirectory() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    client
        .post("/api/v1/library/upload?path=file.txt")
        .header(auth_header(&token))
        .body("moving")
        .dispatch()
        .await;

    let response = client
        .post("/api/v1/library/rename")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(
            serde_json::json!({"old_path": "file.txt", "new_path": "subdir/file.txt"}).to_string(),
        )
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);

    let response = client
        .get("/api/v1/library/download?path=subdir/file.txt")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
}

#[tokio::test]
async fn rename_conflict_when_dest_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    client
        .post("/api/v1/library/upload?path=a.txt")
        .header(auth_header(&token))
        .body("aaa")
        .dispatch()
        .await;

    client
        .post("/api/v1/library/upload?path=b.txt")
        .header(auth_header(&token))
        .body("bbb")
        .dispatch()
        .await;

    let response = client
        .post("/api/v1/library/rename")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(serde_json::json!({"old_path": "a.txt", "new_path": "b.txt"}).to_string())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Conflict);
}

// ---------------------------------------------------------------------------
// Tests — Info
// ---------------------------------------------------------------------------

#[tokio::test]
async fn info_for_file() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    client
        .post("/api/v1/library/upload?path=info-test.pdf")
        .header(auth_header(&token))
        .body("pdf-content")
        .dispatch()
        .await;

    let response = client
        .get("/api/v1/library/info?path=info-test.pdf")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    assert_eq!(json["name"], "info-test.pdf");
    assert_eq!(json["is_dir"], false);
    assert_eq!(json["size"], 11); // "pdf-content".len()
    assert_eq!(json["mime_type"], "application/pdf");
    assert!(json["modified"].is_string());
    assert!(json["integrity"].is_null()); // not requested
}

#[tokio::test]
async fn info_for_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    client
        .post("/api/v1/library/mkdir")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(serde_json::json!({"path": "my-dir"}).to_string())
        .dispatch()
        .await;

    let response = client
        .get("/api/v1/library/info?path=my-dir")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    assert_eq!(json["name"], "my-dir");
    assert_eq!(json["is_dir"], true);
    assert!(json["size"].is_null());
    assert!(json["mime_type"].is_null());
}

#[tokio::test]
async fn info_for_library_root() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    let response = client
        .get("/api/v1/library/info")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    assert_eq!(json["is_dir"], true);
}

#[tokio::test]
async fn info_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    let response = client
        .get("/api/v1/library/info?path=nope.txt")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NotFound);
}

#[tokio::test]
async fn info_with_integrity_check() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    client
        .post("/api/v1/library/upload?path=checked.txt")
        .header(auth_header(&token))
        .body("verify me")
        .dispatch()
        .await;

    let response = client
        .get("/api/v1/library/info?path=checked.txt&integrity=true")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    assert_eq!(json["integrity"], "ok");
}

// ---------------------------------------------------------------------------
// Tests — Usage
// ---------------------------------------------------------------------------

#[tokio::test]
async fn usage_empty_library() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    let response = client
        .get("/api/v1/library/usage")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    assert_eq!(json["disk_bytes"], 0);
    assert_eq!(json["file_count"], 0);
    assert_eq!(json["dir_count"], 0);
}

#[tokio::test]
async fn usage_with_files() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    client
        .post("/api/v1/library/upload?path=file1.txt")
        .header(auth_header(&token))
        .body("aaaa")
        .dispatch()
        .await;

    client
        .post("/api/v1/library/upload?path=sub/file2.txt")
        .header(auth_header(&token))
        .body("bbbb")
        .dispatch()
        .await;

    let response = client
        .get("/api/v1/library/usage")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    assert_eq!(json["file_count"], 2);
    assert_eq!(json["dir_count"], 1); // "sub"
    assert!(json["disk_bytes"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn usage_subdirectory_only() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    client
        .post("/api/v1/library/upload?path=root-file.txt")
        .header(auth_header(&token))
        .body("root")
        .dispatch()
        .await;

    client
        .post("/api/v1/library/upload?path=sub/inner.txt")
        .header(auth_header(&token))
        .body("inner")
        .dispatch()
        .await;

    let response = client
        .get("/api/v1/library/usage?path=sub")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    assert_eq!(json["file_count"], 1);
    assert_eq!(json["dir_count"], 0);
}

// ---------------------------------------------------------------------------
// Tests — Path Traversal Guards (HTTP layer)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upload_rejects_path_traversal() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    let response = client
        .post("/api/v1/library/upload?path=../escape.txt")
        .header(auth_header(&token))
        .body("bad")
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::BadRequest);
}

#[tokio::test]
async fn download_rejects_path_traversal() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    let response = client
        .get("/api/v1/library/download?path=../etc/passwd")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::BadRequest);
}

#[tokio::test]
async fn delete_rejects_path_traversal() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    let response = client
        .delete("/api/v1/library/delete?path=../other")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::BadRequest);
}

#[tokio::test]
async fn mkdir_rejects_path_traversal() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    let response = client
        .post("/api/v1/library/mkdir")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(serde_json::json!({"path": "../escape"}).to_string())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::BadRequest);
}

#[tokio::test]
async fn rename_rejects_path_traversal_in_source() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    let response = client
        .post("/api/v1/library/rename")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(serde_json::json!({"old_path": "../escape.txt", "new_path": "safe.txt"}).to_string())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::BadRequest);
}

#[tokio::test]
async fn rename_rejects_path_traversal_in_dest() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    client
        .post("/api/v1/library/upload?path=legit.txt")
        .header(auth_header(&token))
        .body("ok")
        .dispatch()
        .await;

    let response = client
        .post("/api/v1/library/rename")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(serde_json::json!({"old_path": "legit.txt", "new_path": "../escape.txt"}).to_string())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::BadRequest);
}

// ---------------------------------------------------------------------------
// Tests — User isolation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn users_cannot_see_each_others_files() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let alice_pw = alice_password();
    let bob_pw = bob_password();

    let alice_token = create_ready_user(&client, "alice", "alice@example.com", &alice_pw).await;
    let bob_token = create_ready_user(&client, "bob", "bob@example.com", &bob_pw).await;

    // Alice uploads a file
    client
        .post("/api/v1/library/upload?path=alice-secret.txt")
        .header(auth_header(&alice_token))
        .body("alice's secret")
        .dispatch()
        .await;

    // Bob's library should be empty
    let response = client
        .get("/api/v1/library/list")
        .header(auth_header(&bob_token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    assert!(json["entries"].as_array().unwrap().is_empty());

    // Bob uploads his own file
    client
        .post("/api/v1/library/upload?path=bob-file.txt")
        .header(auth_header(&bob_token))
        .body("bob's file")
        .dispatch()
        .await;

    // Alice should only see her file
    let response = client
        .get("/api/v1/library/list")
        .header(auth_header(&alice_token))
        .dispatch()
        .await;

    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    let entries = json["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["name"], "alice-secret.txt");
}

// ---------------------------------------------------------------------------
// Tests — Integrity header verification on download
// ---------------------------------------------------------------------------

#[tokio::test]
async fn download_integrity_header_matches_known_sha256() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    // Upload known content
    let content = "hello";
    let response = client
        .post("/api/v1/library/upload?path=known.txt")
        .header(auth_header(&token))
        .body(content)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);

    // Download and check
    let response = client
        .get("/api/v1/library/download?path=known.txt")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);

    let integrity = response
        .headers()
        .get_one("X-IronDrive-Integrity")
        .unwrap()
        .to_string();

    let body = response.into_string().await.unwrap();
    assert_eq!(body, content);

    // Compute expected SHA-256 of "hello"
    // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    assert_eq!(
        integrity,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
}

#[tokio::test]
async fn upload_and_download_integrity_values_match() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    // Upload
    let response = client
        .post("/api/v1/library/upload?path=checksum-test.bin")
        .header(auth_header(&token))
        .body(vec![0xDE, 0xAD, 0xBE, 0xEF])
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let upload_json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    let upload_checksum = upload_json["checksum_sha256"].as_str().unwrap().to_string();

    // Download
    let response = client
        .get("/api/v1/library/download?path=checksum-test.bin")
        .header(auth_header(&token))
        .dispatch()
        .await;

    let download_checksum = response
        .headers()
        .get_one("X-IronDrive-Integrity")
        .unwrap()
        .to_string();

    assert_eq!(upload_checksum, download_checksum);
}

// ---------------------------------------------------------------------------
// Tests — List with integrity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_with_integrity_shows_ok_for_valid_files() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    client
        .post("/api/v1/library/upload?path=good.txt")
        .header(auth_header(&token))
        .body("intact data")
        .dispatch()
        .await;

    let response = client
        .get("/api/v1/library/list?integrity=true")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    let entries = json["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["integrity"], "ok");
}

// ---------------------------------------------------------------------------
// Tests — MIME types in responses
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upload_response_includes_mime_type() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    let response = client
        .post("/api/v1/library/upload?path=photo.jpg")
        .header(auth_header(&token))
        .body(vec![0xFF, 0xD8, 0xFF]) // fake JPEG bytes
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    assert_eq!(json["mime_type"], "image/jpeg");
}

#[tokio::test]
async fn download_content_type_matches_extension() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    client
        .post("/api/v1/library/upload?path=data.json")
        .header(auth_header(&token))
        .body(r#"{"key": "value"}"#)
        .dispatch()
        .await;

    let response = client
        .get("/api/v1/library/download?path=data.json")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let content_type = response.content_type().unwrap();
    assert_eq!(content_type.to_string(), "application/json");
}

#[tokio::test]
async fn download_unknown_extension_returns_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    client
        .post("/api/v1/library/upload?path=data.xyz123")
        .header(auth_header(&token))
        .body("mystery")
        .dispatch()
        .await;

    let response = client
        .get("/api/v1/library/download?path=data.xyz123")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let content_type = response.content_type().unwrap();
    assert_eq!(content_type.to_string(), "application/octet-stream");
}

// ---------------------------------------------------------------------------
// Tests — Full workflow
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_workflow_upload_list_info_rename_download_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let token = create_ready_user(&client, "alice", "alice@example.com", &pw).await;

    // 1. Upload
    let response = client
        .post("/api/v1/library/upload?path=docs/report.pdf")
        .header(auth_header(&token))
        .body("PDF content here")
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    // 2. List parent
    let response = client
        .get("/api/v1/library/list?path=docs")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    assert_eq!(json["entries"].as_array().unwrap().len(), 1);
    assert_eq!(json["entries"][0]["name"], "report.pdf");

    // 3. Info
    let response = client
        .get("/api/v1/library/info?path=docs/report.pdf")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    assert_eq!(json["name"], "report.pdf");
    assert_eq!(json["mime_type"], "application/pdf");

    // 4. Rename
    let response = client
        .post("/api/v1/library/rename")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(
            serde_json::json!({
                "old_path": "docs/report.pdf",
                "new_path": "docs/final-report.pdf"
            })
            .to_string(),
        )
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    // 5. Download via new name
    let response = client
        .get("/api/v1/library/download?path=docs/final-report.pdf")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let body = response.into_string().await.unwrap();
    assert_eq!(body, "PDF content here");

    // 6. Usage
    let response = client
        .get("/api/v1/library/usage")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    assert_eq!(json["file_count"], 1);
    assert_eq!(json["dir_count"], 1); // "docs"

    // 7. Delete the directory
    let response = client
        .delete("/api/v1/library/delete?path=docs")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    // 8. Verify empty
    let response = client
        .get("/api/v1/library/usage")
        .header(auth_header(&token))
        .dispatch()
        .await;
    let json: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    assert_eq!(json["file_count"], 0);
    assert_eq!(json["dir_count"], 0);
    assert_eq!(json["disk_bytes"], 0);
}
