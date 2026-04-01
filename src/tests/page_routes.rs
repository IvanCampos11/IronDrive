//! Integration tests for the M5F page routes.
//!
//! These tests verify:
//! - Unauthenticated access redirects to login
//! - Security headers are present on responses
//! - Auth pages render correctly
//! - File browser requires authentication

use rocket::http::Status;
use rocket::local::asynchronous::Client;
use rocket_dyn_templates::Template;

use crate::config::AppConfig;
use crate::db;
use crate::routes;
use crate::services;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn test_password(index: usize) -> String {
    let base = String::from("test-credential");
    format!("{}-page{}", base, index)
}

fn alice_password() -> String {
    test_password(0)
}

/// Build a Rocket instance with Template fairing for page tests.
async fn page_test_client(tmp: &tempfile::TempDir) -> Client {
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
        .attach(Template::fairing())
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
async fn get_csrf_token(client: &Client, path: &str) -> String {
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
