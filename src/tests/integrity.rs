//! Integration tests for M5.7 — Background Services & Integrity Events.
//!
//! Covers:
//!  - Upload → corrupt on disk → file-hash catches it (key-free)
//!  - scan_library detects corrupted / truncated files → events recorded
//!  - acknowledge_event removes from unacknowledged list
//!  - Session cleanup removes expired sessions
//!  - Chunk cleanup removes expired staging dirs
//!  - Integrity API routes (list, acknowledge, notifications, admin scan)

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
// Test credential helpers (same pattern as library_fs / setup_flow)
// ---------------------------------------------------------------------------

fn test_password(index: usize) -> String {
    let base = String::from("test-credential");
    format!("{}-user{}", base, index)
}

fn alice_password() -> String {
    test_password(0)
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

/// Register (first user → admin) + login + setup-library.
/// Returns `(token, library_id)`.
async fn create_ready_admin(
    client: &Client,
    username: &str,
    email: &str,
    password: &str,
) -> (String, String) {
    register_user(client, username, email, password).await;
    let token = login_user(client, username, password).await;
    let lib = setup_library(client, &token).await;
    let library_id = lib["library_id"].as_str().unwrap().to_string();
    (token, library_id)
}

fn auth_header(token: &str) -> Header<'static> {
    Header::new("Authorization", format!("Bearer {}", token))
}

/// Find the single encrypted file on disk inside the library directory.
/// After uploading `path=hello.txt`, the file lives at
/// `<data_dir>/libraries/<library_id>/hello.txt`.
fn library_file_path(tmp: &tempfile::TempDir, library_id: &str, rel: &str) -> std::path::PathBuf {
    tmp.path()
        .join("data")
        .join("libraries")
        .join(library_id)
        .join(rel)
}

// ---------------------------------------------------------------------------
// Tests — Integrity scanning & events (service-level via admin API)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scan_clean_library_finds_no_failures() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let (token, library_id) = create_ready_admin(&client, "alice", "alice@example.com", &pw).await;

    // Upload a file
    let resp = client
        .post("/api/v1/library/upload?path=clean.txt")
        .header(auth_header(&token))
        .body("all good here")
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    // Admin scan — should find 0 failures
    let resp = client
        .post(format!(
            "/api/v1/admin/integrity/scan?target_type=library&target_id={}",
            library_id
        ))
        .header(auth_header(&token))
        .header(Header::new("X-Requested-With", "XMLHttpRequest"))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let json: Value = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    assert_eq!(json["files_scanned"], 1);
    assert_eq!(json["failures_found"], 0);
}

#[tokio::test]
async fn corrupt_file_detected_by_scan() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let (token, library_id) = create_ready_admin(&client, "alice", "alice@example.com", &pw).await;

    // Upload
    let resp = client
        .post("/api/v1/library/upload?path=important.txt")
        .header(auth_header(&token))
        .body("important data")
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    // Corrupt the encrypted file on disk
    let file_path = library_file_path(&tmp, &library_id, "important.txt");
    let original = tokio::fs::read(&file_path).await.unwrap();
    let mut corrupted = original;
    // Flip bytes in the middle (past the magic + nonce header)
    let mid = corrupted.len() / 2;
    corrupted[mid] ^= 0xFF;
    corrupted[mid + 1] ^= 0xFF;
    tokio::fs::write(&file_path, &corrupted).await.unwrap();

    // Admin scan — should detect the corruption
    let resp = client
        .post(format!(
            "/api/v1/admin/integrity/scan?target_type=library&target_id={}",
            library_id
        ))
        .header(auth_header(&token))
        .header(Header::new("X-Requested-With", "XMLHttpRequest"))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let json: Value = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    assert_eq!(json["files_scanned"], 1);
    assert_eq!(json["failures_found"], 1);

    // Verify the event was recorded — list via user endpoint
    let resp = client
        .get("/api/v1/library/integrity/events")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let json: Value = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    let events = json["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["target_type"], "library");
    assert_eq!(events[0]["target_id"], library_id);
    assert!(events[0]["file_path"].as_str().unwrap().contains("important.txt"));
    assert_eq!(events[0]["detected_by"], "background_scan");
    assert_eq!(events[0]["acknowledged"], 0);
}

#[tokio::test]
async fn truncated_file_detected_by_scan() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let (token, library_id) = create_ready_admin(&client, "alice", "alice@example.com", &pw).await;

    // Upload
    let resp = client
        .post("/api/v1/library/upload?path=data.bin")
        .header(auth_header(&token))
        .body("this file will be truncated")
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    // Truncate the encrypted file to a few bytes
    let file_path = library_file_path(&tmp, &library_id, "data.bin");
    tokio::fs::write(&file_path, &[0x49, 0x44, 0x01, 0x00])
        .await
        .unwrap();

    // Admin scan
    let resp = client
        .post(format!(
            "/api/v1/admin/integrity/scan?target_type=library&target_id={}",
            library_id
        ))
        .header(auth_header(&token))
        .header(Header::new("X-Requested-With", "XMLHttpRequest"))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let json: Value = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    assert_eq!(json["files_scanned"], 1);
    assert_eq!(json["failures_found"], 1);
}

#[tokio::test]
async fn acknowledge_event_removes_from_notifications() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let (token, library_id) = create_ready_admin(&client, "alice", "alice@example.com", &pw).await;

    // Upload + corrupt
    let resp = client
        .post("/api/v1/library/upload?path=bad.txt")
        .header(auth_header(&token))
        .body("will corrupt")
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let file_path = library_file_path(&tmp, &library_id, "bad.txt");
    let mut data = tokio::fs::read(&file_path).await.unwrap();
    let mid = data.len() / 2;
    data[mid] ^= 0xFF;
    tokio::fs::write(&file_path, &data).await.unwrap();

    // Scan to generate an event
    let resp = client
        .post(format!(
            "/api/v1/admin/integrity/scan?target_type=library&target_id={}",
            library_id
        ))
        .header(auth_header(&token))
        .header(Header::new("X-Requested-With", "XMLHttpRequest"))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    // Notifications should have 1 unacknowledged event
    let resp = client
        .get("/api/v1/users/me/notifications")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let json: Value = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    assert_eq!(json["count"], 1);
    let event_id = json["events"][0]["id"].as_str().unwrap().to_string();

    // Acknowledge it
    let resp = client
        .post(format!(
            "/api/v1/library/integrity/events/{}/acknowledge",
            event_id
        ))
        .header(auth_header(&token))
        .header(Header::new("X-Requested-With", "XMLHttpRequest"))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let json: Value = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    assert_eq!(json["acknowledged"], true);

    // Notifications should now be empty
    let resp = client
        .get("/api/v1/users/me/notifications")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let json: Value = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    assert_eq!(json["count"], 0);
    assert!(json["events"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn list_events_via_admin_endpoint() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let (token, library_id) = create_ready_admin(&client, "alice", "alice@example.com", &pw).await;

    // Upload + corrupt
    client
        .post("/api/v1/library/upload?path=x.txt")
        .header(auth_header(&token))
        .body("x")
        .dispatch()
        .await;

    let file_path = library_file_path(&tmp, &library_id, "x.txt");
    let mut data = tokio::fs::read(&file_path).await.unwrap();
    let mid = data.len() / 2;
    data[mid] ^= 0xFF;
    tokio::fs::write(&file_path, &data).await.unwrap();

    // Scan
    client
        .post(format!(
            "/api/v1/admin/integrity/scan?target_type=library&target_id={}",
            library_id
        ))
        .header(auth_header(&token))
        .header(Header::new("X-Requested-With", "XMLHttpRequest"))
        .dispatch()
        .await;

    // Admin list events
    let resp = client
        .get(format!(
            "/api/v1/admin/integrity/events?target_type=library&target_id={}",
            library_id
        ))
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let json: Value = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    let events = json["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["target_id"], library_id);
}

#[tokio::test]
async fn admin_scan_requires_target_id() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let (token, _) = create_ready_admin(&client, "alice", "alice@example.com", &pw).await;

    let resp = client
        .post("/api/v1/admin/integrity/scan?target_type=library")
        .header(auth_header(&token))
        .header(Header::new("X-Requested-With", "XMLHttpRequest"))
        .dispatch()
        .await;

    assert_eq!(resp.status(), Status::UnprocessableEntity);
}

#[tokio::test]
async fn admin_list_events_requires_target_id() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let (token, _) = create_ready_admin(&client, "alice", "alice@example.com", &pw).await;

    let resp = client
        .get("/api/v1/admin/integrity/events?target_type=library")
        .header(auth_header(&token))
        .dispatch()
        .await;

    assert_eq!(resp.status(), Status::UnprocessableEntity);
}

#[tokio::test]
async fn integrity_events_endpoint_without_auth_returns_401() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;

    let resp = client
        .get("/api/v1/library/integrity/events")
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Unauthorized);
}

#[tokio::test]
async fn notifications_endpoint_without_auth_returns_401() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;

    let resp = client
        .get("/api/v1/users/me/notifications")
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Unauthorized);
}

// ---------------------------------------------------------------------------
// Tests — Session cleanup
// ---------------------------------------------------------------------------

#[tokio::test]
async fn session_cleanup_removes_expired_sessions() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();

    // Register + login to create a user in the DB
    register_user(&client, "alice", "alice@example.com", &pw).await;
    let token = login_user(&client, "alice", &pw).await;

    // The login above created a valid session.  Verify it works.
    let resp = client
        .post("/api/v1/auth/setup-library")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    // Now insert an already-expired session directly via the DB pool.
    // We need the pool from Rocket state.
    let rocket = client.rocket();
    let pool = rocket
        .state::<crate::db::DbPool>()
        .expect("DbPool not in managed state");

    let expired_at = chrono::Utc::now().naive_utc() - chrono::Duration::hours(1);
    crate::models::session::Session::create(pool, "nonexistent-user", "expired-hash-abc", expired_at)
        .await
        .unwrap();

    // Verify there's at least 2 sessions now (the real one + the expired one)
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions")
        .fetch_one(pool)
        .await
        .unwrap();
    assert!(count.0 >= 2, "Expected at least 2 sessions, got {}", count.0);

    // Run cleanup
    let removed = crate::models::session::Session::delete_expired(pool)
        .await
        .unwrap();
    assert_eq!(removed, 1, "Should have removed exactly 1 expired session");

    // The valid session should still work
    let resp = client
        .get("/api/v1/library/integrity/events")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
}

// ---------------------------------------------------------------------------
// Tests — Chunk cleanup
// ---------------------------------------------------------------------------

#[tokio::test]
async fn chunk_cleanup_removes_expired_uploads() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let (token, library_id) =
        create_ready_admin(&client, "alice", "alice@example.com", &pw).await;

    let rocket = client.rocket();
    let pool = rocket
        .state::<crate::db::DbPool>()
        .expect("DbPool in state");
    let config = rocket
        .state::<AppConfig>()
        .expect("AppConfig in state");

    // Insert an already-expired chunked upload row directly.
    let upload_id = uuid::Uuid::new_v4().to_string();
    let expired_at = (chrono::Utc::now() - chrono::Duration::hours(1))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    sqlx::query(
        "INSERT INTO chunked_uploads (id, user_id, target_type, target_id, target_path, total_chunks, received_chunks, total_bytes, expires_at)
         VALUES (?, ?, 'library', ?, 'test.bin', 2, 0, 1024, ?)",
    )
    .bind(&upload_id)
    .bind("alice-user-id") // doesn't matter for cleanup
    .bind(&library_id)
    .bind(&expired_at)
    .execute(pool)
    .await
    .unwrap();

    // Create a staging directory for it
    let staging = tmp
        .path()
        .join("data")
        .join(".chunks")
        .join(&upload_id);
    tokio::fs::create_dir_all(&staging).await.unwrap();
    tokio::fs::write(staging.join("00000000.chunk"), b"fake chunk")
        .await
        .unwrap();
    assert!(tokio::fs::try_exists(&staging).await.unwrap());

    // Run cleanup
    let cleaned = services::chunk_service::cleanup_expired_uploads(pool, config)
        .await
        .unwrap();
    assert_eq!(cleaned, 1);

    // Staging dir should be gone
    assert!(!tokio::fs::try_exists(&staging).await.unwrap());

    // DB row should be gone
    let row: Option<(String,)> =
        sqlx::query_as("SELECT id FROM chunked_uploads WHERE id = ?")
            .bind(&upload_id)
            .fetch_optional(pool)
            .await
            .unwrap();
    assert!(row.is_none(), "Expired upload row should be deleted");
}

// ---------------------------------------------------------------------------
// Tests — Multiple files, subdirectories
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scan_detects_corruption_in_subdirectory() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let (token, library_id) = create_ready_admin(&client, "alice", "alice@example.com", &pw).await;

    // Upload files in root and in a subdir
    client
        .post("/api/v1/library/upload?path=root.txt")
        .header(auth_header(&token))
        .body("root file")
        .dispatch()
        .await;

    client
        .post("/api/v1/library/upload?path=docs/nested.txt")
        .header(auth_header(&token))
        .body("nested file")
        .dispatch()
        .await;

    // Corrupt only the nested file
    let nested_path = library_file_path(&tmp, &library_id, "docs/nested.txt");
    let mut data = tokio::fs::read(&nested_path).await.unwrap();
    let mid = data.len() / 2;
    data[mid] ^= 0xFF;
    tokio::fs::write(&nested_path, &data).await.unwrap();

    // Scan
    let resp = client
        .post(format!(
            "/api/v1/admin/integrity/scan?target_type=library&target_id={}",
            library_id
        ))
        .header(auth_header(&token))
        .header(Header::new("X-Requested-With", "XMLHttpRequest"))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let json: Value = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    assert_eq!(json["files_scanned"], 2);
    assert_eq!(json["failures_found"], 1);

    // Verify the event path mentions the nested file
    let resp = client
        .get("/api/v1/library/integrity/events")
        .header(auth_header(&token))
        .dispatch()
        .await;
    let json: Value = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    let events = json["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert!(
        events[0]["file_path"]
            .as_str()
            .unwrap()
            .contains("nested.txt")
    );
}

#[tokio::test]
async fn scan_empty_library_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let (token, library_id) = create_ready_admin(&client, "alice", "alice@example.com", &pw).await;

    let resp = client
        .post(format!(
            "/api/v1/admin/integrity/scan?target_type=library&target_id={}",
            library_id
        ))
        .header(auth_header(&token))
        .header(Header::new("X-Requested-With", "XMLHttpRequest"))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let json: Value = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    assert_eq!(json["files_scanned"], 0);
    assert_eq!(json["failures_found"], 0);
}

#[tokio::test]
async fn no_events_initially() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let (token, _) = create_ready_admin(&client, "alice", "alice@example.com", &pw).await;

    // Events list should be empty
    let resp = client
        .get("/api/v1/library/integrity/events")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let json: Value = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    assert!(json["events"].as_array().unwrap().is_empty());

    // Notifications should have count 0
    let resp = client
        .get("/api/v1/users/me/notifications")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let json: Value = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    assert_eq!(json["count"], 0);
}

#[tokio::test]
async fn acknowledge_nonexistent_event_returns_404() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let pw = alice_password();
    let (token, _) = create_ready_admin(&client, "alice", "alice@example.com", &pw).await;

    let resp = client
        .post("/api/v1/library/integrity/events/nonexistent-id/acknowledge")
        .header(auth_header(&token))
        .header(Header::new("X-Requested-With", "XMLHttpRequest"))
        .dispatch()
        .await;

    assert_eq!(resp.status(), Status::NotFound);
}
