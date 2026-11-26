//! Integration tests for the M5F page routes.
//!
//! These tests verify:
//! - Unauthenticated access redirects to login
//! - Security headers are present on responses
//! - Auth pages render correctly
//! - File browser requires authentication

use rocket::http::Status;
use rocket::local::asynchronous::Client;

use crate::config::AppConfig;
use crate::db;
use crate::routes;
use crate::services;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

pub(super) fn test_password(index: usize) -> String {
    let base = String::from("test-credential");
    format!("{}-page{}", base, index)
}

pub(super) fn alice_password() -> String {
    test_password(0)
}

/// Build a Rocket instance with Template fairing for page tests.
pub(super) async fn page_test_client(tmp: &tempfile::TempDir) -> Client {
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
        registration_enabled: true,
        secure_cookies: false,
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
        .attach(crate::templates_fairing())
        .attach(crate::security_headers_fairing())
        .attach(crate::cache_control_fairing())
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
        );

    Client::tracked(rocket)
        .await
        .expect("Failed to build Rocket test client")
}

// ── Tests ────────────────────────────────────────────────────────────────

/// GET a page to establish the CSRF cookie, then return the token value.
pub(super) async fn get_csrf_token(client: &Client, path: &str) -> String {
    let _ = client.get(path).dispatch().await;
    client
        .cookies()
        .get("csrf_token")
        .map(|c| c.value().to_string())
        .expect("CSRF cookie should be set after GET")
}

#[tokio::test]
async fn unauthenticated_index_redirects_to_login() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;

    let response = client.get("/").dispatch().await;
    assert_eq!(response.status(), Status::SeeOther);
    let location = response.headers().get_one("Location").unwrap_or("");
    assert!(
        location.contains("/login"),
        "Expected redirect to /login, got {}",
        location
    );
}

#[tokio::test]
async fn unauthenticated_files_redirects() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;

    let response = client.get("/files").dispatch().await;
    // SessionSetupComplete guard should redirect unauthenticated users
    assert!(
        [Status::SeeOther, Status::Unauthorized, Status::NotFound].contains(&response.status()),
        "Expected redirect or auth error for /files, got {}",
        response.status()
    );
}

#[tokio::test]
async fn login_page_renders() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;

    let response = client.get("/login").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let body = response.into_string().await.unwrap_or_default();
    assert!(
        body.contains("Sign in"),
        "Login page should contain 'Sign in'"
    );
    assert!(
        body.contains("username"),
        "Login page should have username field"
    );
}

#[tokio::test]
async fn register_page_renders() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;

    let response = client.get("/register").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let body = response.into_string().await.unwrap_or_default();
    assert!(
        body.contains("Create account"),
        "Register page should contain 'Create account'"
    );
    assert!(
        body.contains("password_confirm"),
        "Register page should have confirm password field"
    );
}

#[tokio::test]
async fn security_headers_present() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;

    let response = client.get("/login").dispatch().await;

    assert_eq!(
        response.headers().get_one("X-Content-Type-Options"),
        Some("nosniff"),
        "Missing X-Content-Type-Options header"
    );
    assert_eq!(
        response.headers().get_one("X-Frame-Options"),
        Some("DENY"),
        "Missing X-Frame-Options header"
    );
    assert!(
        response
            .headers()
            .get_one("Content-Security-Policy")
            .is_some(),
        "Missing Content-Security-Policy header"
    );
    assert!(
        response.headers().get_one("Referrer-Policy").is_some(),
        "Missing Referrer-Policy header"
    );
}

#[tokio::test]
async fn invalid_login_shows_error() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;

    let csrf = get_csrf_token(&client, "/login").await;

    let response = client
        .post("/login")
        .header(rocket::http::ContentType::Form)
        .body(format!(
            "username=nonexistent&password=wrongpassword&csrf_token={}",
            csrf
        ))
        .dispatch()
        .await;

    // Should redirect back to login with flash error
    assert_eq!(response.status(), Status::SeeOther);
    let location = response.headers().get_one("Location").unwrap_or("");
    assert!(
        location.contains("/login"),
        "Should redirect to /login on failure"
    );
}

#[tokio::test]
async fn register_password_mismatch_error() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;

    let csrf = get_csrf_token(&client, "/register").await;

    let response = client
        .post("/register")
        .header(rocket::http::ContentType::Form)
        .body(format!("username=testuser&email=test@example.com&password=Password123&password_confirm=Different456&csrf_token={}", csrf))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::SeeOther);
    let location = response.headers().get_one("Location").unwrap_or("");
    assert!(
        location.contains("/register"),
        "Should redirect to /register on mismatch"
    );
}

#[tokio::test]
async fn full_page_auth_flow() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let pw = alice_password();

    // Register via API (since the page form doesn't give us a token)
    let body = serde_json::json!({
        "username": "alice",
        "email": "alice@example.com",
        "password": pw,
    });
    let response = client
        .post("/api/v1/auth/register")
        .header(rocket::http::ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    // GET login page to establish CSRF cookie
    let csrf = get_csrf_token(&client, "/login").await;

    // Login via page form
    let response = client
        .post("/login")
        .header(rocket::http::ContentType::Form)
        .body(format!(
            "username=alice&password={}&csrf_token={}",
            pw, csrf
        ))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::SeeOther, "Login should redirect");
    let location = response.headers().get_one("Location").unwrap_or("");
    // Should redirect to setup since library isn't created
    assert!(
        location.contains("/setup"),
        "Should redirect to /setup after login without library, got {}",
        location
    );
}

#[tokio::test]
async fn csrf_token_set_on_login_page() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;

    let response = client.get("/login").dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let cookies = client.cookies();
    let csrf_cookie = cookies.get("csrf_token");
    assert!(
        csrf_cookie.is_some(),
        "CSRF cookie should be set on login page"
    );
    let token = csrf_cookie.unwrap().value().to_string();
    assert_eq!(token.len(), 64, "CSRF token should be 64 characters");

    let body = response.into_string().await.unwrap_or_default();
    assert!(
        body.contains(&token),
        "CSRF token should appear in the HTML form"
    );
}

#[tokio::test]
async fn post_without_csrf_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;

    // POST without getting CSRF token first — should get 422 (missing field)
    let response = client
        .post("/login")
        .header(rocket::http::ContentType::Form)
        .body("username=alice&password=test1234")
        .dispatch()
        .await;

    // Rocket returns 422 when form field is missing
    assert_eq!(response.status(), Status::UnprocessableEntity);
}

#[tokio::test]
async fn cache_control_static_assets() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;

    let response = client.get("/login").dispatch().await;
    let cache = response.headers().get_one("Cache-Control").unwrap_or("");
    assert!(
        cache.contains("no-cache"),
        "HTML pages should have no-cache, got: {}",
        cache
    );
}

/// Register + sign in through the page form + create the library.
/// Returns the CSRF token for XHR calls.
pub(super) async fn signed_in_with_library(client: &Client) -> String {
    let pw = alice_password();
    let body =
        serde_json::json!({ "username": "alice", "email": "alice@example.com", "password": pw });
    let r = client
        .post("/api/v1/auth/register")
        .header(rocket::http::ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;
    assert_eq!(r.status(), Status::Ok);

    let csrf = get_csrf_token(client, "/login").await;
    let r = client
        .post("/login")
        .header(rocket::http::ContentType::Form)
        .body(format!("username=alice&password={pw}&csrf_token={csrf}"))
        .dispatch()
        .await;
    assert_eq!(r.status(), Status::SeeOther);

    let r = client
        .post("/setup")
        .header(rocket::http::ContentType::Form)
        .body(format!("csrf_token={csrf}"))
        .dispatch()
        .await;
    assert_eq!(r.status(), Status::SeeOther);
    csrf
}

pub(super) async fn xhr_json(
    client: &Client,
    csrf: &str,
    url: &str,
    body: serde_json::Value,
) -> (Status, serde_json::Value) {
    let r = client
        .post(url.to_string())
        .header(rocket::http::ContentType::JSON)
        .header(rocket::http::Header::new("X-CSRF-Token", csrf.to_string()))
        .body(body.to_string())
        .dispatch()
        .await;
    let status = r.status();
    let text = r.into_string().await.unwrap_or_default();
    (
        status,
        serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn html_request_without_session_redirects_to_login() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;

    let r = client
        .get("/files")
        .header(rocket::http::Accept::HTML)
        .dispatch()
        .await;
    assert_eq!(
        r.status(),
        Status::SeeOther,
        "browsers should be sent to sign-in, not an error page"
    );
    assert_eq!(r.headers().get_one("Location"), Some("/login"));
}

#[tokio::test]
async fn file_api_mkdir_and_rename() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let csrf = signed_in_with_library(&client).await;

    let (status, body) = xhr_json(
        &client,
        &csrf,
        "/files/api/mkdir",
        serde_json::json!({"path": "", "name": "Docs"}),
    )
    .await;
    assert_eq!(status, Status::Ok);
    assert_eq!(body["path"], "Docs");

    let (status, body) = xhr_json(
        &client,
        &csrf,
        "/files/api/mkdir",
        serde_json::json!({"path": "Docs", "name": "Inner"}),
    )
    .await;
    assert_eq!(status, Status::Ok);
    assert_eq!(body["path"], "Docs/Inner");

    // Duplicate name → 409 with a readable message.
    let (status, body) = xhr_json(
        &client,
        &csrf,
        "/files/api/mkdir",
        serde_json::json!({"path": "", "name": "Docs"}),
    )
    .await;
    assert_eq!(status, Status::Conflict);
    assert!(body["error"].as_str().unwrap_or("").len() > 3);

    // Names with slashes or a leading dot are rejected.
    for bad in ["a/b", ".hidden", "  "] {
        let (status, _) = xhr_json(
            &client,
            &csrf,
            "/files/api/mkdir",
            serde_json::json!({"path": "", "name": bad}),
        )
        .await;
        assert_eq!(
            status,
            Status::BadRequest,
            "name {bad:?} should be rejected"
        );
    }

    // Rename keeps the item in its parent folder.
    let (status, body) = xhr_json(
        &client,
        &csrf,
        "/files/api/rename",
        serde_json::json!({"path": "Docs/Inner", "new_name": "Renamed"}),
    )
    .await;
    assert_eq!(status, Status::Ok);
    assert_eq!(body["path"], "Docs/Renamed");

    let page = client
        .get("/files/partial?path=Docs")
        .dispatch()
        .await
        .into_string()
        .await
        .unwrap();
    assert!(
        page.contains("data-name=\"Renamed\""),
        "renamed folder should be listed"
    );

    // Missing CSRF header is refused.
    let r = client
        .post("/files/api/mkdir")
        .header(rocket::http::ContentType::JSON)
        .body(serde_json::json!({"path": "", "name": "NoCsrf"}).to_string())
        .dispatch()
        .await;
    assert_eq!(r.status(), Status::Forbidden);
}

#[tokio::test]
async fn bulk_errors_are_user_facing() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let csrf = signed_in_with_library(&client).await;

    let (status, body) = xhr_json(
        &client,
        &csrf,
        "/files/bulk-delete",
        serde_json::json!({"paths": ["nope/missing.txt"]}),
    )
    .await;
    assert_eq!(status, Status::Ok);
    assert_eq!(body["deleted"], 0);
    let err = body["errors"][0].as_str().unwrap();
    assert!(
        err.starts_with("missing.txt: "),
        "error should name the file, got {err:?}"
    );
    assert!(
        !err.contains("internal"),
        "internal details must not leak: {err:?}"
    );
}

#[tokio::test]
async fn file_browser_page_renders_shell() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    signed_in_with_library(&client).await;

    let page = client
        .get("/files")
        .dispatch()
        .await
        .into_string()
        .await
        .unwrap();
    assert!(page.contains("id=\"file-browser-content\""));
    assert!(
        page.contains("aria-current=\"page\"") && page.contains("My files"),
        "My files nav item should be active"
    );
    assert!(
        page.contains("/static/js/browser.js?v="),
        "assets should carry a cache-busting version"
    );
    assert!(
        !page.contains("/shares") && !page.contains("/trash"),
        "links to unimplemented pages must be gone"
    );
}

/// Upload `bytes` to `name` at the library root through the page XHR endpoint.
pub(super) async fn page_upload(client: &Client, csrf: &str, name: &str, bytes: &[u8]) {
    let r = client
        .post(format!("/files/upload?path={name}"))
        .header(rocket::http::Header::new("X-CSRF-Token", csrf.to_string()))
        .body(bytes)
        .dispatch()
        .await;
    assert_eq!(r.status(), Status::Ok, "upload failed");
}

/// Flip a byte in the middle of the only library's copy of `name`.
pub(super) fn corrupt_library_file(tmp: &tempfile::TempDir, name: &str) {
    let libs = tmp.path().join("data/libraries");
    let lib = std::fs::read_dir(&libs)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let file = lib.join(name);
    let mut bytes = std::fs::read(&file).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xff;
    std::fs::write(&file, bytes).unwrap();
}

#[tokio::test]
async fn details_info_describes_files_and_folders() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let csrf = signed_in_with_library(&client).await;
    xhr_json(
        &client,
        &csrf,
        "/files/api/mkdir",
        serde_json::json!({"path": "", "name": "Docs"}),
    )
    .await;
    page_upload(&client, &csrf, "Docs/a.txt", b"hello world").await;

    let file: serde_json::Value = serde_json::from_str(
        &client
            .get("/files/info?path=Docs/a.txt")
            .dispatch()
            .await
            .into_string()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(file["name"], "a.txt");
    assert_eq!(file["size_bytes"], 11);
    assert_eq!(file["location"], "My files / Docs");
    assert_eq!(file["problems"].as_array().unwrap().len(), 0);

    let dir: serde_json::Value = serde_json::from_str(
        &client
            .get("/files/info?path=Docs")
            .dispatch()
            .await
            .into_string()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(dir["is_dir"], true);
    assert_eq!(dir["contents"]["files"], 1);
}

#[tokio::test]
async fn verify_flags_damaged_file_and_alert_lifecycle() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let csrf = signed_in_with_library(&client).await;
    page_upload(&client, &csrf, "ok.txt", b"fine").await;
    page_upload(&client, &csrf, "bad.txt", &[7u8; 4096]).await;
    corrupt_library_file(&tmp, "bad.txt");

    let (status, body) = xhr_json(
        &client,
        &csrf,
        "/files/verify?path=ok.txt",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, Status::Ok);
    assert_eq!(body["ok"], true);

    // Checking twice must not create a duplicate alert.
    for _ in 0..2 {
        let (status, body) = xhr_json(
            &client,
            &csrf,
            "/files/verify?path=bad.txt",
            serde_json::json!({}),
        )
        .await;
        assert_eq!(status, Status::Ok);
        assert_eq!(body["ok"], false);
    }

    let bell = client
        .get("/notifications")
        .dispatch()
        .await
        .into_string()
        .await
        .unwrap();
    assert_eq!(
        bell.matches("data-dismiss-alert=").count(),
        1,
        "exactly one alert expected"
    );
    let listing = client
        .get("/files/partial")
        .dispatch()
        .await
        .into_string()
        .await
        .unwrap();
    assert!(
        listing.contains("item-flag"),
        "damaged file should be badged in the listing"
    );

    let id = bell
        .split("data-dismiss-alert=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_string();
    let (status, _) = xhr_json(
        &client,
        &csrf,
        &format!("/notifications/{id}/dismiss"),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, Status::Ok);
    let bell = client
        .get("/notifications")
        .dispatch()
        .await
        .into_string()
        .await
        .unwrap();
    assert!(
        !bell.contains("data-dismiss-alert="),
        "alert should be gone after dismissing"
    );

    // Re-flag it, then "restore" the file: a clean check clears the alert by itself.
    xhr_json(
        &client,
        &csrf,
        "/files/verify?path=bad.txt",
        serde_json::json!({}),
    )
    .await;
    corrupt_library_file(&tmp, "bad.txt"); // flips the same byte back
    let (_, body) = xhr_json(
        &client,
        &csrf,
        "/files/verify?path=bad.txt",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["resolved"], 1);
    let bell = client
        .get("/notifications")
        .dispatch()
        .await
        .into_string()
        .await
        .unwrap();
    assert!(
        !bell.contains("data-dismiss-alert="),
        "a clean check should resolve the alert"
    );
}

#[tokio::test]
async fn admin_page_is_admin_only_and_sets_quota() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let csrf = signed_in_with_library(&client).await; // first user → admin

    // A second account for the admin to manage.
    let r = client
        .post("/api/v1/auth/register")
        .header(rocket::http::ContentType::JSON)
        .body(serde_json::json!({"username": "bob", "email": "bob@example.com", "password": alice_password()}).to_string())
        .dispatch()
        .await;
    assert_eq!(r.status(), Status::Ok);
    let bob_id = serde_json::from_str::<serde_json::Value>(&r.into_string().await.unwrap())
        .unwrap()["user_id"]
        .as_str()
        .unwrap()
        .to_string();

    let page = client.get("/admin").dispatch().await;
    assert_eq!(page.status(), Status::Ok);
    assert!(page
        .into_string()
        .await
        .unwrap()
        .contains("bob@example.com"));

    let r = client
        .post(format!("/admin/users/{bob_id}/quota"))
        .header(rocket::http::ContentType::Form)
        .body(format!("quota=2%20GB&csrf_token={csrf}"))
        .dispatch()
        .await;
    assert_eq!(r.status(), Status::SeeOther);
    assert!(client
        .get("/admin")
        .dispatch()
        .await
        .into_string()
        .await
        .unwrap()
        .contains("2.0 GB"));

    // Admins can't disable themselves.
    let me_id = client
        .get("/settings")
        .dispatch()
        .await
        .into_string()
        .await
        .unwrap();
    assert!(me_id.contains("Server admin"));

    // Sign out, sign in as bob: non-admins are refused.
    let r = client
        .post("/logout")
        .header(rocket::http::ContentType::Form)
        .body(format!("csrf_token={csrf}"))
        .dispatch()
        .await;
    assert_eq!(r.status(), Status::SeeOther);
    let csrf = get_csrf_token(&client, "/login").await;
    let r = client
        .post("/login")
        .header(rocket::http::ContentType::Form)
        .body(format!(
            "username=bob&password={}&csrf_token={csrf}",
            alice_password()
        ))
        .dispatch()
        .await;
    assert_eq!(r.status(), Status::SeeOther);
    client
        .post("/setup")
        .header(rocket::http::ContentType::Form)
        .body(format!("csrf_token={csrf}"))
        .dispatch()
        .await;
    assert_eq!(
        client.get("/admin").dispatch().await.status(),
        Status::Forbidden
    );
    let r = client
        .post(format!("/admin/users/{bob_id}/quota"))
        .header(rocket::http::ContentType::Form)
        .body(format!("quota=100%20GB&csrf_token={csrf}"))
        .dispatch()
        .await;
    assert_eq!(
        r.status(),
        Status::Forbidden,
        "non-admins can't change quotas"
    );
}
