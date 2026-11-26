//! Storage quotas, trash and downloads, exercised through the browser routes.

use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::Client;
use rocket::serde::json::serde_json::{self, json, Value};

use super::page_routes::{page_test_client, signed_in_with_library, xhr_json};
use crate::db;

/// Change every user's quota directly in the database.
async fn set_quota(tmp: &tempfile::TempDir, bytes: i64) {
    let url = format!("sqlite:{}/irondrive.db", tmp.path().join("db").display());
    let pool = db::init_pool(&url).await.unwrap();
    sqlx::query("UPDATE users SET quota_bytes = ?")
        .bind(bytes)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

async fn upload(
    client: &Client,
    csrf: &str,
    base: &str,
    name: &str,
    len: usize,
) -> (Status, Value) {
    let r = client
        .post(format!("{base}/upload?path={name}"))
        .header(Header::new("X-CSRF-Token", csrf.to_string()))
        .body(vec![b'x'; len])
        .dispatch()
        .await;
    let status = r.status();
    let body = r.into_string().await.unwrap_or_default();
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

fn error_of(v: &Value) -> &str {
    v["error"].as_str().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Quotas
// ---------------------------------------------------------------------------

#[tokio::test]
async fn direct_upload_is_refused_when_it_would_exceed_the_quota() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let csrf = signed_in_with_library(&client).await;
    set_quota(&tmp, 3000).await;

    let (status, _) = upload(&client, &csrf, "/files", "a.txt", 1000).await;
    assert_eq!(status, Status::Ok);

    let (status, body) = upload(&client, &csrf, "/files", "b.txt", 2500).await;
    assert_eq!(status, Status::InsufficientStorage);
    assert!(
        error_of(&body).starts_with("Not enough storage: this needs"),
        "{body}"
    );

    // Overwriting a file only needs the difference.
    let (status, body) = upload(&client, &csrf, "/files", "a.txt", 1800).await;
    assert_eq!(status, Status::Ok, "{body}");

    // A full drive says so plainly.
    set_quota(&tmp, 100).await;
    let (status, body) = upload(&client, &csrf, "/files", "c.txt", 10).await;
    assert_eq!(status, Status::InsufficientStorage);
    assert!(error_of(&body).contains("storage is full"), "{body}");
}

#[tokio::test]
async fn in_progress_chunked_uploads_reserve_space() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let csrf = signed_in_with_library(&client).await;
    set_quota(&tmp, 20 << 20).await;

    let init = |path: &'static str| {
        let client = &client;
        let csrf = csrf.clone();
        async move {
            xhr_json(
                client,
                &csrf,
                "/files/chunked/init",
                json!({ "path": path, "total_chunks": 2, "total_bytes": 12u64 << 20 }),
            )
            .await
        }
    };

    let (status, first) = init("one.bin").await;
    assert_eq!(status, Status::Ok, "{first}");

    // Two 12 MiB uploads can't both fit in 20 MiB, even before any bytes land.
    let (status, body) = init("two.bin").await;
    assert_eq!(status, Status::InsufficientStorage, "{body}");

    // Cancelling the first frees its reservation.
    let id = first["upload_id"].as_str().unwrap();
    let r = client
        .delete(format!("/files/chunked/cancel?upload_id={id}"))
        .header(Header::new("X-CSRF-Token", csrf.clone()))
        .dispatch()
        .await;
    assert_eq!(r.status(), Status::Ok);
    let (status, body) = init("two.bin").await;
    assert_eq!(status, Status::Ok, "{body}");
}

#[tokio::test]
async fn spaces_you_own_count_toward_your_quota() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let csrf = signed_in_with_library(&client).await;

    let r = client
        .post("/spaces/create")
        .header(ContentType::Form)
        .body(format!("name=Team&csrf_token={csrf}"))
        .dispatch()
        .await;
    assert_eq!(r.status(), Status::SeeOther);
    let space = r.headers().get_one("Location").unwrap().to_string();

    set_quota(&tmp, 3000).await;
    let (status, body) = upload(&client, &csrf, &space, "big.txt", 2000).await;
    assert_eq!(status, Status::Ok, "{body}");

    // The space's 2 KB now leaves too little room in My files.
    let (status, _) = upload(&client, &csrf, "/files", "more.txt", 1500).await;
    assert_eq!(status, Status::InsufficientStorage);

    let page = client
        .get("/usage")
        .dispatch()
        .await
        .into_string()
        .await
        .unwrap();
    assert!(page.contains("Spaces you own"));
}
