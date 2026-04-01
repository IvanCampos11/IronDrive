use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::Client;
use rocket::serde::json::serde_json;
use rocket_dyn_templates::Template;
use serde_json::Value;

use crate::config::AppConfig;
use crate::db;
use crate::routes;
use crate::services;

fn auth_header(token: &str) -> Header<'static> {
    Header::new("Authorization", format!("Bearer {}", token))
}

fn chunks_for(total_bytes: usize, chunk_size: usize) -> u32 {
    if total_bytes == 0 {
        1
    } else {
        ((total_bytes + chunk_size - 1) / chunk_size) as u32
    }
}

fn checksum_hex(data: &[u8]) -> String {
    hex::encode(crate::services::crypto_service::sha256_bytes(data))
}

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
        max_upload_bytes: 10 * 1024 * 1024,
        session_expiry_hours: 168,
        chunk_size_bytes: 64 * 1024,
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

async fn register_user(client: &Client, username: &str, email: &str, password: &str) {
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

async fn setup_library(client: &Client, token: &str) {
    let response = client
        .post("/api/v1/auth/setup-library")
        .header(auth_header(token))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok, "setup-library failed");
}

async fn create_ready_user(client: &Client, username: &str, email: &str, password: &str) -> String {
    register_user(client, username, email, password).await;
    let token = login_user(client, username, password).await;
    setup_library(client, &token).await;
    token
}

#[tokio::test]
async fn chunked_upload_download_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "alice", "alice@example.com", "test-password-1").await;

    let chunk_size = 64 * 1024usize;
    let total_bytes = chunk_size * 2 + 123;
    let payload = vec![0x5Au8; total_bytes];
    let checksum = checksum_hex(&payload);
    let total_chunks = chunks_for(payload.len(), chunk_size);

    let init_body = serde_json::json!({
        "path": "videos/roundtrip.bin",
        "total_chunks": total_chunks,
        "total_bytes": payload.len(),
        "checksum_sha256": checksum,
    });

    let init_resp = client
        .post("/api/v1/library/chunked/init")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(init_body.to_string())
        .dispatch()
        .await;
    assert_eq!(init_resp.status(), Status::Ok);
    let init_json: Value = serde_json::from_str(&init_resp.into_string().await.unwrap()).unwrap();
    let upload_id = init_json["upload_id"].as_str().unwrap();

    for index in 0..total_chunks {
        let start = index as usize * chunk_size;
        let end = std::cmp::min(start + chunk_size, payload.len());
        let chunk = &payload[start..end];

        let put_resp = client
            .put(format!(
                "/api/v1/library/chunked/upload/{}/{}",
                upload_id, index
            ))
            .header(auth_header(&token))
            .body(chunk.to_vec())
            .dispatch()
            .await;
        assert_eq!(put_resp.status(), Status::Ok);
    }

    let complete_body = serde_json::json!({
        "upload_id": upload_id,
        "verify": true,
    });
    let complete_resp = client
        .post("/api/v1/library/chunked/complete")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(complete_body.to_string())
        .dispatch()
        .await;
    assert_eq!(complete_resp.status(), Status::Ok);

    let dl_init_resp = client
        .get("/api/v1/library/chunked/download/init?path=videos/roundtrip.bin")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(dl_init_resp.status(), Status::Ok);

    let dl_json: Value = serde_json::from_str(&dl_init_resp.into_string().await.unwrap()).unwrap();
    let dl_token = dl_json["token"].as_str().unwrap().to_string();
    let dl_chunks = dl_json["total_chunks"].as_u64().unwrap() as u32;

    let mut downloaded = Vec::new();
    for index in 0..dl_chunks {
        let resp = client
            .get(format!(
                "/api/v1/library/chunked/download/chunk?token={}&index={}",
                dl_token, index
            ))
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        downloaded.extend_from_slice(&resp.into_bytes().await.unwrap());
    }

    assert_eq!(downloaded, payload);
}

#[tokio::test]
async fn chunked_upload_accepts_out_of_order_chunks() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "bob", "bob@example.com", "test-password-2").await;

    let chunk_size = 64 * 1024usize;
    let payload: Vec<u8> = (0..(chunk_size * 3 + 17))
        .map(|i| (i % 251) as u8)
        .collect();
    let total_chunks = chunks_for(payload.len(), chunk_size);

    let init_body = serde_json::json!({
        "path": "docs/out_of_order.bin",
        "total_chunks": total_chunks,
        "total_bytes": payload.len(),
        "checksum_sha256": checksum_hex(&payload),
    });

    let init_resp = client
        .post("/api/v1/library/chunked/init")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(init_body.to_string())
        .dispatch()
        .await;
    assert_eq!(init_resp.status(), Status::Ok);

    let init_json: Value = serde_json::from_str(&init_resp.into_string().await.unwrap()).unwrap();
    let upload_id = init_json["upload_id"].as_str().unwrap().to_string();

    let order = [2u32, 0u32, 1u32, 3u32];
    for index in order.into_iter().take(total_chunks as usize) {
        let start = index as usize * chunk_size;
        let end = std::cmp::min(start + chunk_size, payload.len());

        let resp = client
            .put(format!(
                "/api/v1/library/chunked/upload/{}/{}",
                upload_id, index
            ))
            .header(auth_header(&token))
            .body(payload[start..end].to_vec())
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    let complete_resp = client
        .post("/api/v1/library/chunked/complete")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(serde_json::json!({"upload_id": upload_id}).to_string())
        .dispatch()
        .await;
    assert_eq!(complete_resp.status(), Status::Ok);

    let download_resp = client
        .get("/api/v1/library/download?path=docs/out_of_order.bin")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(download_resp.status(), Status::Ok);
    assert_eq!(download_resp.into_bytes().await.unwrap(), payload);
}

#[tokio::test]
async fn incomplete_upload_cancel_cleans_staging() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "carol", "carol@example.com", "test-password-3").await;

    let chunk_size = 64 * 1024usize;
    let payload = vec![0x11u8; chunk_size * 2 + 9];
    let total_chunks = chunks_for(payload.len(), chunk_size);

    let init_resp = client
        .post("/api/v1/library/chunked/init")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(
            serde_json::json!({
                "path": "tmp/incomplete.bin",
                "total_chunks": total_chunks,
                "total_bytes": payload.len(),
            })
            .to_string(),
        )
        .dispatch()
        .await;
    assert_eq!(init_resp.status(), Status::Ok);

    let init_json: Value = serde_json::from_str(&init_resp.into_string().await.unwrap()).unwrap();
    let upload_id = init_json["upload_id"].as_str().unwrap().to_string();

    let first_chunk = &payload[..chunk_size];
    let put_resp = client
        .put(format!("/api/v1/library/chunked/upload/{}/0", upload_id))
        .header(auth_header(&token))
        .body(first_chunk.to_vec())
        .dispatch()
        .await;
    assert_eq!(put_resp.status(), Status::Ok);

    let cancel_resp = client
        .delete(format!(
            "/api/v1/library/chunked/cancel?upload_id={}",
            upload_id
        ))
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(cancel_resp.status(), Status::Ok);

    let staging_dir = tmp.path().join("data").join(".chunks").join(&upload_id);
    let exists = tokio::fs::try_exists(staging_dir).await.unwrap();
    assert!(!exists);

    let complete_resp = client
        .post("/api/v1/library/chunked/complete")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(serde_json::json!({"upload_id": upload_id}).to_string())
        .dispatch()
        .await;
    assert_eq!(complete_resp.status(), Status::NotFound);
}

#[tokio::test]
async fn checksum_mismatch_on_complete_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "dave", "dave@example.com", "test-password-4").await;

    let chunk_size = 64 * 1024usize;
    let payload = vec![0x42u8; chunk_size + 333];
    let total_chunks = chunks_for(payload.len(), chunk_size);

    let init_resp = client
        .post("/api/v1/library/chunked/init")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(
            serde_json::json!({
                "path": "docs/bad_checksum.bin",
                "total_chunks": total_chunks,
                "total_bytes": payload.len(),
                "checksum_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            })
            .to_string(),
        )
        .dispatch()
        .await;
    assert_eq!(init_resp.status(), Status::Ok);

    let init_json: Value = serde_json::from_str(&init_resp.into_string().await.unwrap()).unwrap();
    let upload_id = init_json["upload_id"].as_str().unwrap().to_string();

    for index in 0..total_chunks {
        let start = index as usize * chunk_size;
        let end = std::cmp::min(start + chunk_size, payload.len());
        let resp = client
            .put(format!(
                "/api/v1/library/chunked/upload/{}/{}",
                upload_id, index
            ))
            .header(auth_header(&token))
            .body(payload[start..end].to_vec())
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    let complete_resp = client
        .post("/api/v1/library/chunked/complete")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(serde_json::json!({"upload_id": upload_id}).to_string())
        .dispatch()
        .await;
    assert_eq!(complete_resp.status(), Status::BadRequest);
}

#[tokio::test]
async fn small_file_falls_back_to_single_request_upload() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "erin", "erin@example.com", "test-password-5").await;

    let chunk_size = 64 * 1024usize;
    let total_bytes = chunk_size - 10;

    let init_resp = client
        .post("/api/v1/library/chunked/init")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(
            serde_json::json!({
                "path": "docs/small.bin",
                "total_chunks": 1,
                "total_bytes": total_bytes,
            })
            .to_string(),
        )
        .dispatch()
        .await;

    assert_eq!(init_resp.status(), Status::BadRequest);
}

#[tokio::test]
async fn duplicate_chunk_upload_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "frank", "frank@example.com", "test-password-6").await;

    let chunk_size = 64 * 1024usize;
    let payload = vec![0x33u8; chunk_size * 2 + 77];
    let total_chunks = chunks_for(payload.len(), chunk_size);

    let init_resp = client
        .post("/api/v1/library/chunked/init")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(
            serde_json::json!({
                "path": "docs/duplicate.bin",
                "total_chunks": total_chunks,
                "total_bytes": payload.len(),
                "checksum_sha256": checksum_hex(&payload),
            })
            .to_string(),
        )
        .dispatch()
        .await;
    assert_eq!(init_resp.status(), Status::Ok);

    let init_json: Value = serde_json::from_str(&init_resp.into_string().await.unwrap()).unwrap();
    let upload_id = init_json["upload_id"].as_str().unwrap().to_string();

    let first = client
        .put(format!("/api/v1/library/chunked/upload/{}/0", upload_id))
        .header(auth_header(&token))
        .body(payload[..chunk_size].to_vec())
        .dispatch()
        .await;
    assert_eq!(first.status(), Status::Ok);

    let duplicate = client
        .put(format!("/api/v1/library/chunked/upload/{}/0", upload_id))
        .header(auth_header(&token))
        .body(payload[..chunk_size].to_vec())
        .dispatch()
        .await;
    assert_eq!(duplicate.status(), Status::Conflict);
}

#[tokio::test]
async fn chunked_init_rejects_oversized_file() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "gina", "gina@example.com", "test-password-7").await;

    let chunk_size = 64 * 1024usize;
    let total_bytes = 10 * 1024 * 1024usize + 1;
    let total_chunks = chunks_for(total_bytes, chunk_size);

    let init_resp = client
        .post("/api/v1/library/chunked/init")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(
            serde_json::json!({
                "path": "docs/too_large.bin",
                "total_chunks": total_chunks,
                "total_bytes": total_bytes,
            })
            .to_string(),
        )
        .dispatch()
        .await;

    assert_eq!(init_resp.status(), Status::BadRequest);
}

#[tokio::test]
async fn chunked_init_rejects_invalid_checksum_format() {
    let tmp = tempfile::tempdir().unwrap();
    let client = test_client(&tmp).await;
    let token = create_ready_user(&client, "hank", "hank@example.com", "test-password-8").await;

    let chunk_size = 64 * 1024usize;
    let total_bytes = chunk_size + 17;
    let total_chunks = chunks_for(total_bytes, chunk_size);

    let init_resp = client
        .post("/api/v1/library/chunked/init")
        .header(auth_header(&token))
        .header(ContentType::JSON)
        .body(
            serde_json::json!({
                "path": "docs/invalid-checksum.bin",
                "total_chunks": total_chunks,
                "total_bytes": total_bytes,
                "checksum_sha256": "deadbeef",
            })
            .to_string(),
        )
        .dispatch()
        .await;

    assert_eq!(init_resp.status(), Status::BadRequest);
}
