//! Storage quotas, trash and downloads, exercised through the browser routes.

use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::Client;
use rocket::serde::json::serde_json::{self, json, Value};

use super::page_routes::{alice_password, page_test_client, signed_in_with_library, xhr_json};
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

// ---------------------------------------------------------------------------
// Trash
// ---------------------------------------------------------------------------

async fn upload_bytes(client: &Client, csrf: &str, base: &str, path: &str, bytes: &[u8]) {
    let r = client
        .post(format!("{base}/upload?path={path}"))
        .header(Header::new("X-CSRF-Token", csrf.to_string()))
        .body(bytes)
        .dispatch()
        .await;
    assert_eq!(r.status(), Status::Ok, "upload of {path} failed");
}

async fn download(client: &Client, base: &str, path: &str) -> (Status, Vec<u8>) {
    let r = client
        .get(format!("{base}/download?path={path}"))
        .dispatch()
        .await;
    let status = r.status();
    (status, r.into_bytes().await.unwrap_or_default())
}

async fn listing_has(client: &Client, base: &str, dir: &str, name: &str) -> bool {
    let html = client
        .get(format!("{base}/partial?path={dir}"))
        .dispatch()
        .await
        .into_string()
        .await
        .unwrap_or_default();
    html.contains(&format!("data-name=\"{name}\""))
}

async fn trash(client: &Client, csrf: &str, base: &str, paths: &[&str]) -> Vec<String> {
    let (status, body) = xhr_json(
        client,
        csrf,
        &format!("{base}/bulk-delete"),
        json!({ "paths": paths }),
    )
    .await;
    assert_eq!(status, Status::Ok);
    assert_eq!(body["errors"], json!([]), "{body}");
    body["trash_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn delete_moves_to_trash_and_undo_restores_it() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let csrf = signed_in_with_library(&client).await;
    upload_bytes(&client, &csrf, "/files", "notes.txt", b"hello trash").await;

    let ids = trash(&client, &csrf, "/files", &["notes.txt"]).await;
    assert_eq!(ids.len(), 1);
    assert!(!listing_has(&client, "/files", "", "notes.txt").await);
    let page = client
        .get("/trash")
        .dispatch()
        .await
        .into_string()
        .await
        .unwrap();
    assert!(page.contains("notes.txt"));
    assert!(page.contains("30 days"));

    // The hidden trash folder can't be reached through file paths.
    let (status, _) = download(&client, "/files", &format!(".trash/{}/notes.txt", ids[0])).await;
    assert_ne!(status, Status::Ok);

    let (status, body) = xhr_json(&client, &csrf, "/trash/restore", json!({ "ids": ids })).await;
    assert_eq!(status, Status::Ok);
    assert_eq!(body["restored"][0]["path"], "notes.txt");
    let (status, bytes) = download(&client, "/files", "notes.txt").await;
    assert_eq!(status, Status::Ok);
    assert_eq!(bytes, b"hello trash");
    let page = client
        .get("/trash")
        .dispatch()
        .await
        .into_string()
        .await
        .unwrap();
    assert!(page.contains("Trash is empty"));
}

#[tokio::test]
async fn restore_handles_name_clashes_and_missing_folders() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let csrf = signed_in_with_library(&client).await;

    // Name clash: a new file took the old name.
    upload_bytes(&client, &csrf, "/files", "report.pdf", b"old").await;
    let ids = trash(&client, &csrf, "/files", &["report.pdf"]).await;
    upload_bytes(&client, &csrf, "/files", "report.pdf", b"new").await;
    let (_, body) = xhr_json(&client, &csrf, "/trash/restore", json!({ "ids": ids })).await;
    assert_eq!(body["restored"][0]["path"], "report (restored).pdf");
    assert_eq!(download(&client, "/files", "report.pdf").await.1, b"new");
    assert_eq!(
        download(&client, "/files", "report%20(restored).pdf")
            .await
            .1,
        b"old"
    );

    // Missing parent: the folder was deleted after the file.
    let (status, _) = xhr_json(
        &client,
        &csrf,
        "/files/api/mkdir",
        json!({ "path": "", "name": "Docs" }),
    )
    .await;
    assert_eq!(status, Status::Ok);
    upload_bytes(&client, &csrf, "/files", "Docs/a.txt", b"inside").await;
    let file_ids = trash(&client, &csrf, "/files", &["Docs/a.txt"]).await;
    trash(&client, &csrf, "/files", &["Docs"]).await;
    let (_, body) = xhr_json(&client, &csrf, "/trash/restore", json!({ "ids": file_ids })).await;
    assert_eq!(body["restored"][0]["path"], "Docs/a.txt");
    assert_eq!(download(&client, "/files", "Docs/a.txt").await.1, b"inside");
}

#[tokio::test]
async fn trash_counts_toward_quota_until_emptied() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let csrf = signed_in_with_library(&client).await;
    set_quota(&tmp, 3000).await;

    upload_bytes(&client, &csrf, "/files", "a.bin", &[1; 2000]).await;
    let ids = trash(&client, &csrf, "/files", &["a.bin"]).await;
    let (status, _) = upload(&client, &csrf, "/files", "b.bin", 2000).await;
    assert_eq!(
        status,
        Status::InsufficientStorage,
        "trash should still count"
    );

    let (status, body) = xhr_json(&client, &csrf, "/trash/delete", json!({ "ids": ids })).await;
    assert_eq!((status, body["deleted"].as_u64()), (Status::Ok, Some(1)));
    let (status, _) = upload(&client, &csrf, "/files", "b.bin", 2000).await;
    assert_eq!(status, Status::Ok);

    trash(&client, &csrf, "/files", &["b.bin"]).await;
    let (status, body) = xhr_json(&client, &csrf, "/trash/empty", json!({})).await;
    assert_eq!((status, body["deleted"].as_u64()), (Status::Ok, Some(1)));
    assert!(client
        .get("/trash")
        .dispatch()
        .await
        .into_string()
        .await
        .unwrap()
        .contains("Trash is empty"));
}

#[tokio::test]
async fn expired_trash_is_purged() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let csrf = signed_in_with_library(&client).await;
    upload_bytes(&client, &csrf, "/files", "old.txt", b"x").await;
    upload_bytes(&client, &csrf, "/files", "recent.txt", b"y").await;
    let old = trash(&client, &csrf, "/files", &["old.txt"]).await;
    trash(&client, &csrf, "/files", &["recent.txt"]).await;

    let url = format!("sqlite:{}/irondrive.db", tmp.path().join("db").display());
    let pool = db::init_pool(&url).await.unwrap();
    sqlx::query("UPDATE trash_items SET deleted_at = datetime('now', '-31 days') WHERE id = ?")
        .bind(&old[0])
        .execute(&pool)
        .await
        .unwrap();
    let config = client.rocket().state::<crate::config::AppConfig>().unwrap();
    let removed = crate::services::trash_service::purge_expired(&pool, config, 30)
        .await
        .unwrap();
    assert_eq!(removed, 1);

    let page = client
        .get("/trash")
        .dispatch()
        .await
        .into_string()
        .await
        .unwrap();
    assert!(!page.contains("old.txt"));
    assert!(page.contains("recent.txt"));
    let lib_dir = std::fs::read_dir(tmp.path().join("data/libraries"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(!lib_dir.join(".trash").join(&old[0]).exists());
}

/// Bearer token for the API (the page tests sign in with a session cookie).
async fn api_token(client: &Client) -> Header<'static> {
    let r = client
        .post("/api/v1/auth/login")
        .header(ContentType::JSON)
        .body(json!({ "username": "alice", "password": alice_password() }).to_string())
        .dispatch()
        .await;
    assert_eq!(r.status(), Status::Ok);
    let body: Value = serde_json::from_str(&r.into_string().await.unwrap()).unwrap();
    Header::new(
        "Authorization",
        format!("Bearer {}", body["token"].as_str().unwrap()),
    )
}

#[tokio::test]
async fn api_delete_uses_trash_unless_permanent() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let csrf = signed_in_with_library(&client).await;
    upload_bytes(&client, &csrf, "/files", "keep.txt", b"1").await;
    upload_bytes(&client, &csrf, "/files", "gone.txt", b"2").await;
    let auth = api_token(&client).await;

    let r = client
        .delete("/api/v1/library/delete?path=keep.txt")
        .header(auth.clone())
        .dispatch()
        .await;
    assert_eq!(r.status(), Status::Ok);
    let body: Value = serde_json::from_str(&r.into_string().await.unwrap()).unwrap();
    let id = body["trash_id"].as_str().unwrap().to_string();

    let r = client
        .delete("/api/v1/library/delete?path=gone.txt&permanent=true")
        .header(auth.clone())
        .dispatch()
        .await;
    assert_eq!(r.status(), Status::Ok);

    let r = client
        .get("/api/v1/library/trash")
        .header(auth.clone())
        .dispatch()
        .await;
    let items: Value = serde_json::from_str(&r.into_string().await.unwrap()).unwrap();
    assert_eq!(items.as_array().unwrap().len(), 1);
    assert_eq!(items[0]["original_path"], "keep.txt");

    let r = client
        .post(format!("/api/v1/library/trash/{id}/restore"))
        .header(auth.clone())
        .dispatch()
        .await;
    assert_eq!(r.status(), Status::Ok);
    assert_eq!(download(&client, "/files", "keep.txt").await.1, b"1");
}
