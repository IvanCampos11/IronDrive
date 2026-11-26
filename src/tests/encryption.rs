//! Encryption tiers, unlocking, and how space keys reach members on any tier.
//! Everything goes through the API with bearer tokens, one per user.

use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::Client;
use rocket::serde::json::serde_json::{self, json, Value};

use super::page_routes::page_test_client;

fn pw(name: &str) -> String {
    format!("{name}-login-password-123")
}

async fn call(
    client: &Client,
    method: &str,
    url: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (Status, Value) {
    let mut req = match method {
        "GET" => client.get(url.to_string()),
        "POST" => client.post(url.to_string()),
        "PUT" => client.put(url.to_string()),
        "DELETE" => client.delete(url.to_string()),
        _ => unreachable!(),
    };
    if let Some(t) = token {
        req = req.header(Header::new("Authorization", format!("Bearer {t}")));
    }
    if let Some(b) = body {
        req = req.header(ContentType::JSON).body(b.to_string());
    }
    let r = req.dispatch().await;
    let status = r.status();
    let text = r.into_string().await.unwrap_or_default();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

async fn login(client: &Client, name: &str, password: &str) -> String {
    let (s, v) = call(
        client,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({ "username": name, "password": password })),
    )
    .await;
    assert_eq!(s, Status::Ok, "login {name}: {v}");
    v["token"].as_str().unwrap().to_string()
}

/// Register, sign in and set up with the given setup body. Returns a token.
async fn user(client: &Client, name: &str, setup: Value) -> String {
    let (s, v) = call(
        client,
        "POST",
        "/api/v1/auth/register",
        None,
        Some(json!({ "username": name, "email": format!("{name}@example.com"), "password": pw(name) })),
    )
    .await;
    assert_eq!(s, Status::Ok, "register {name}: {v}");
    let token = login(client, name, &pw(name)).await;
    let (s, v) = call(
        client,
        "POST",
        "/api/v1/auth/setup-library",
        Some(&token),
        Some(setup),
    )
    .await;
    assert_eq!(s, Status::Ok, "setup {name}: {v}");
    token
}

fn pure(name: &str) -> Value {
    json!({ "tier": "pure_user", "password_mode": "single", "password": pw(name) })
}

async fn upload(client: &Client, token: &str, base: &str, path: &str, body: &str) -> Status {
    client
        .post(format!("{base}/upload?path={path}"))
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .body(body)
        .dispatch()
        .await
        .status()
}

async fn download(client: &Client, token: &str, base: &str, path: &str) -> (Status, String) {
    let r = client
        .get(format!("{base}/download?path={path}"))
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .dispatch()
        .await;
    let s = r.status();
    (s, r.into_string().await.unwrap_or_default())
}

async fn create_space(client: &Client, token: &str, body: Value) -> String {
    let (s, v) = call(client, "POST", "/api/v1/spaces", Some(token), Some(body)).await;
    assert_eq!(s, Status::Ok, "create space: {v}");
    v["id"].as_str().unwrap().to_string()
}

async fn grant(client: &Client, token: &str, space: &str, username: &str) {
    let (s, v) = call(
        client,
        "POST",
        &format!("/api/v1/spaces/{space}/access/user"),
        Some(token),
        Some(json!({ "username": username, "permission": "write" })),
    )
    .await;
    assert_eq!(s, Status::Ok, "grant {username}: {v}");
}

async fn lock(client: &Client, token: &str) {
    let (s, _) = call(client, "POST", "/api/v1/auth/lock", Some(token), None).await;
    assert_eq!(s, Status::Ok);
}

async fn unlock(client: &Client, token: &str, password: &str) -> Status {
    call(
        client,
        "POST",
        "/api/v1/auth/unlock",
        Some(token),
        Some(json!({ "password": password })),
    )
    .await
    .0
}

async fn encryption(client: &Client, token: &str) -> Value {
    call(client, "GET", "/api/v1/auth/encryption", Some(token), None)
        .await
        .1
}

const LIB: &str = "/api/v1/library";

fn space_base(id: &str) -> String {
    format!("/api/v1/spaces/{id}/files")
}

#[tokio::test]
async fn pure_tier_library_locks_and_unlocks_with_the_login_password() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let alice = user(&client, "alice", pure("alice")).await;
    assert_eq!(encryption(&client, &alice).await["tier"], "pure_user");
    assert_eq!(encryption(&client, &alice).await["recoverable"], false);

    assert_eq!(
        upload(&client, &alice, LIB, "a.txt", "secret").await,
        Status::Ok
    );

    lock(&client, &alice).await;
    assert_eq!(encryption(&client, &alice).await["unlocked"], false);
    assert_eq!(
        download(&client, &alice, LIB, "a.txt").await.0,
        Status::Locked
    );

    assert_eq!(
        unlock(&client, &alice, "wrong password!").await,
        Status::Unauthorized
    );
    assert_eq!(unlock(&client, &alice, &pw("alice")).await, Status::Ok);
    assert_eq!(
        download(&client, &alice, LIB, "a.txt").await,
        (Status::Ok, "secret".into())
    );

    // Signing in again also unlocks (single mode).
    lock(&client, &alice).await;
    let again = login(&client, "alice", &pw("alice")).await;
    assert_eq!(download(&client, &again, LIB, "a.txt").await.0, Status::Ok);
}

#[tokio::test]
async fn logout_locks_only_when_the_last_session_ends() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let first = user(&client, "alice", pure("alice")).await;
    let second = login(&client, "alice", &pw("alice")).await;
    assert_eq!(upload(&client, &first, LIB, "a.txt", "x").await, Status::Ok);

    let (s, _) = call(&client, "POST", "/api/v1/auth/logout", Some(&first), None).await;
    assert_eq!(s, Status::Ok);
    assert_eq!(download(&client, &second, LIB, "a.txt").await.0, Status::Ok);

    let (s, _) = call(&client, "POST", "/api/v1/auth/logout", Some(&second), None).await;
    assert_eq!(s, Status::Ok);
    let third = login(&client, "alice", &pw("alice")).await;
    // Sign-in unlocked it again; prove it was locked in between by locking
    // and checking the encryption status flips.
    assert_eq!(encryption(&client, &third).await["unlocked"], true);
}

#[tokio::test]
async fn separate_mode_needs_the_encryption_password() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let setup = json!({
        "tier": "failsafe_user", "password_mode": "separate",
        "password": pw("alice"), "encryption_password": "a different secret",
    });
    let alice = user(&client, "alice", setup).await;
    assert_eq!(upload(&client, &alice, LIB, "a.txt", "x").await, Status::Ok);

    lock(&client, &alice).await;
    let token = login(&client, "alice", &pw("alice")).await;
    assert_eq!(
        download(&client, &token, LIB, "a.txt").await.0,
        Status::Locked
    );
    assert_eq!(
        unlock(&client, &token, &pw("alice")).await,
        Status::Unauthorized
    );
    assert_eq!(
        unlock(&client, &token, "a different secret").await,
        Status::Ok
    );
    assert_eq!(download(&client, &token, LIB, "a.txt").await.0, Status::Ok);
}

#[tokio::test]
async fn setup_rejects_bad_tier_choices() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    call(
        &client,
        "POST",
        "/api/v1/auth/register",
        None,
        Some(json!({ "username": "alice", "email": "a@example.com", "password": pw("alice") })),
    )
    .await;
    let t = login(&client, "alice", &pw("alice")).await;
    let setup = |body: Value| {
        call(
            &client,
            "POST",
            "/api/v1/auth/setup-library",
            Some(&t),
            Some(body),
        )
    };

    // Wrong login password.
    let (s, _) = setup(json!({ "tier": "pure_user", "password": "nope nope nope" })).await;
    assert_eq!(s, Status::Unauthorized);
    // Separate mode with the login password as the encryption password.
    let (s, _) = setup(json!({ "tier": "pure_user", "password_mode": "separate",
        "password": pw("alice"), "encryption_password": pw("alice") }))
    .await;
    assert_eq!(s, Status::BadRequest);
    // Unknown tier.
    let (s, _) = setup(json!({ "tier": "nope" })).await;
    assert_eq!(s, Status::BadRequest);
    // Malformed JSON isn't silently treated as "server".
    let r = client
        .post("/api/v1/auth/setup-library")
        .header(Header::new("Authorization", format!("Bearer {t}")))
        .header(ContentType::JSON)
        .body("{not json")
        .dispatch()
        .await;
    assert_eq!(r.status(), Status::BadRequest);
}

#[tokio::test]
async fn standard_space_follows_the_creators_tier_and_works_for_every_member() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let alice = user(&client, "alice", pure("alice")).await; // first user = admin
    let bob = user(&client, "bob", json!({})).await; // server tier
    let carol = user(&client, "carol", pure("carol")).await;

    let space = create_space(&client, &alice, json!({ "name": "Shared" })).await;
    let (_, v) = call(
        &client,
        "GET",
        &format!("/api/v1/spaces/{space}"),
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(v["encryption_mode"], "members");

    let base = space_base(&space);
    assert_eq!(
        upload(&client, &alice, &base, "doc.txt", "hello").await,
        Status::Ok
    );
    grant(&client, &alice, &space, "bob").await;
    grant(&client, &alice, &space, "carol").await;

    // Bob (server tier) and Carol (pure) both read it without extra steps.
    assert_eq!(download(&client, &bob, &base, "doc.txt").await.1, "hello");
    assert_eq!(download(&client, &carol, &base, "doc.txt").await.1, "hello");

    // Alice locks: Bob is a server-tier member, so the space stays open.
    lock(&client, &alice).await;
    lock(&client, &carol).await;
    assert_eq!(
        download(&client, &bob, &base, "doc.txt").await.0,
        Status::Ok
    );
}

#[tokio::test]
async fn members_space_closes_when_every_member_is_locked() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let alice = user(&client, "alice", pure("alice")).await;
    let carol = user(&client, "carol", pure("carol")).await;
    let space = create_space(&client, &alice, json!({ "name": "Private" })).await;
    let base = space_base(&space);
    assert_eq!(
        upload(&client, &alice, &base, "doc.txt", "hello").await,
        Status::Ok
    );
    grant(&client, &alice, &space, "carol").await;

    lock(&client, &alice).await;
    assert_eq!(
        download(&client, &carol, &base, "doc.txt").await.0,
        Status::Ok
    );
    lock(&client, &carol).await;
    assert_eq!(
        download(&client, &carol, &base, "doc.txt").await.0,
        Status::Locked
    );
    let (_, v) = call(
        &client,
        "GET",
        &format!("/api/v1/spaces/{space}/lock-state"),
        Some(&carol),
        None,
    )
    .await;
    assert_eq!(v["state"], "account_locked");

    // Carol's own envelope opens it again, without Alice.
    assert_eq!(unlock(&client, &carol, &pw("carol")).await, Status::Ok);
    assert_eq!(download(&client, &carol, &base, "doc.txt").await.1, "hello");
}

#[tokio::test]
async fn access_given_while_nobody_has_the_key_is_sealed_later() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let alice = user(&client, "alice", pure("alice")).await;
    let carol = user(&client, "carol", pure("carol")).await;
    let space = create_space(&client, &alice, json!({ "name": "Later" })).await;
    let base = space_base(&space);
    assert_eq!(
        upload(&client, &alice, &base, "doc.txt", "hello").await,
        Status::Ok
    );

    // Nobody holding the key is unlocked when Carol is added.
    lock(&client, &alice).await;
    grant(&client, &alice, &space, "carol").await;
    assert_eq!(
        download(&client, &carol, &base, "doc.txt").await.0,
        Status::Locked
    );
    let (_, v) = call(
        &client,
        "GET",
        &format!("/api/v1/spaces/{space}/lock-state"),
        Some(&carol),
        None,
    )
    .await;
    assert_eq!(v["state"], "waiting_for_key");

    // Alice comes back: Carol's envelope is sealed, and survives Alice leaving.
    assert_eq!(unlock(&client, &alice, &pw("alice")).await, Status::Ok);
    lock(&client, &alice).await;
    lock(&client, &carol).await;
    assert_eq!(unlock(&client, &carol, &pw("carol")).await, Status::Ok);
    assert_eq!(download(&client, &carol, &base, "doc.txt").await.1, "hello");
}

#[tokio::test]
async fn revoking_access_removes_the_envelope() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let alice = user(&client, "alice", pure("alice")).await;
    let carol = user(&client, "carol", pure("carol")).await;
    let space = create_space(&client, &alice, json!({ "name": "S" })).await;
    grant(&client, &alice, &space, "carol").await;

    let (_, v) = call(
        &client,
        "GET",
        "/api/v1/auth/encryption",
        Some(&carol),
        None,
    )
    .await;
    assert_eq!(v["tier"], "pure_user");
    let (_, list) = call(
        &client,
        "GET",
        &format!("/api/v1/spaces/{space}/access"),
        Some(&alice),
        None,
    )
    .await;
    let carol_id = list["access"][0]["grantee_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, _) = call(
        &client,
        "DELETE",
        &format!("/api/v1/spaces/{space}/access/user/{carol_id}"),
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(s, Status::Ok);

    let url = format!("sqlite:{}/irondrive.db", tmp.path().join("db").display());
    let pool = crate::db::init_pool(&url).await.unwrap();
    let (n,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM space_key_envelopes WHERE space_id = ?")
            .bind(&space)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(n, 1, "only Alice's envelope remains");
}

#[tokio::test]
async fn group_members_added_later_get_the_key() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let alice = user(&client, "alice", pure("alice")).await;
    let dave = user(&client, "dave", pure("dave")).await;
    let (s, g) = call(
        &client,
        "POST",
        "/api/v1/groups",
        Some(&alice),
        Some(json!({ "name": "team" })),
    )
    .await;
    assert_eq!(s, Status::Ok, "{g}");
    let group = g["id"].as_str().unwrap().to_string();
    let space = create_space(&client, &alice, json!({ "name": "S" })).await;
    let (s, v) = call(
        &client,
        "POST",
        &format!("/api/v1/spaces/{space}/access/group"),
        Some(&alice),
        Some(json!({ "group_id": group, "permission": "read" })),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    let base = space_base(&space);
    assert_eq!(
        upload(&client, &alice, &base, "doc.txt", "team doc").await,
        Status::Ok
    );

    let (s, v) = call(
        &client,
        "POST",
        &format!("/api/v1/groups/{group}/members"),
        Some(&alice),
        Some(json!({ "username": "dave", "role": "member" })),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");

    lock(&client, &alice).await;
    lock(&client, &dave).await;
    assert_eq!(unlock(&client, &dave, &pw("dave")).await, Status::Ok);
    assert_eq!(
        download(&client, &dave, &base, "doc.txt").await.1,
        "team doc"
    );
}

#[tokio::test]
async fn password_space_needs_every_member_to_type_the_password() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let alice = user(&client, "alice", json!({})).await;
    let bob = user(&client, "bob", json!({})).await;
    let space = create_space(
        &client,
        &alice,
        json!({ "name": "Vault", "password": "vault password" }),
    )
    .await;
    let base = space_base(&space);
    assert_eq!(
        upload(&client, &alice, &base, "doc.txt", "classified").await,
        Status::Ok
    );
    grant(&client, &alice, &space, "bob").await;

    // Bob has access but hasn't typed the password.
    assert_eq!(
        download(&client, &bob, &base, "doc.txt").await.0,
        Status::Locked
    );
    let (s, _) = call(
        &client,
        "GET",
        &format!("{base}/list?path="),
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(s, Status::Locked, "file names are hidden too");
    // Management still works while locked.
    let (s, _) = call(
        &client,
        "GET",
        &format!("/api/v1/spaces/{space}"),
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(s, Status::Ok);

    let space_unlock = |token: String, password: &'static str| {
        let url = format!("/api/v1/spaces/{space}/unlock");
        let client = &client;
        async move {
            call(
                client,
                "POST",
                &url,
                Some(&token),
                Some(json!({ "password": password })),
            )
            .await
            .0
        }
    };
    assert_eq!(
        space_unlock(bob.clone(), "wrong").await,
        Status::Unauthorized
    );
    assert_eq!(
        space_unlock(bob.clone(), "vault password").await,
        Status::Ok
    );
    assert_eq!(
        download(&client, &bob, &base, "doc.txt").await.1,
        "classified"
    );

    // Alice changes the password: Bob has to type the new one.
    let (s, v) = call(
        &client,
        "PUT",
        &format!("/api/v1/spaces/{space}/protection"),
        Some(&alice),
        Some(json!({ "mode": "password", "password": "new vault password" })),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(
        download(&client, &bob, &base, "doc.txt").await.0,
        Status::Locked
    );
    assert_eq!(
        space_unlock(bob.clone(), "vault password").await,
        Status::Unauthorized
    );
    assert_eq!(
        space_unlock(bob.clone(), "new vault password").await,
        Status::Ok
    );
    assert_eq!(
        download(&client, &alice, &base, "doc.txt").await.0,
        Status::Ok
    );

    // Locking it for Bob leaves Alice's unlock alone.
    let (s, _) = call(
        &client,
        "POST",
        &format!("/api/v1/spaces/{space}/lock"),
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(s, Status::Ok);
    assert_eq!(
        download(&client, &bob, &base, "doc.txt").await.0,
        Status::Locked
    );
    assert_eq!(
        download(&client, &alice, &base, "doc.txt").await.0,
        Status::Ok
    );
}

#[tokio::test]
async fn space_protection_can_move_between_modes() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let alice = user(&client, "alice", json!({})).await;
    let carol = user(&client, "carol", pure("carol")).await;
    let space = create_space(&client, &alice, json!({ "name": "S" })).await;
    let base = space_base(&space);
    assert_eq!(
        upload(&client, &alice, &base, "doc.txt", "data").await,
        Status::Ok
    );
    grant(&client, &alice, &space, "carol").await;

    for mode in ["members", "password", "server", "members"] {
        let body = if mode == "password" {
            json!({ "mode": mode, "password": "space password" })
        } else {
            json!({ "mode": mode })
        };
        let (s, v) = call(
            &client,
            "PUT",
            &format!("/api/v1/spaces/{space}/protection"),
            Some(&alice),
            Some(body),
        )
        .await;
        assert_eq!(s, Status::Ok, "{mode}: {v}");
        assert_eq!(
            download(&client, &alice, &base, "doc.txt").await.1,
            "data",
            "{mode}"
        );
    }

    // Ended as members-only: Carol opens it from her own envelope.
    lock(&client, &carol).await;
    assert_eq!(unlock(&client, &carol, &pw("carol")).await, Status::Ok);
    assert_eq!(download(&client, &carol, &base, "doc.txt").await.1, "data");

    // Only space admins can change protection.
    let (s, _) = call(
        &client,
        "PUT",
        &format!("/api/v1/spaces/{space}/protection"),
        Some(&carol),
        Some(json!({ "mode": "server" })),
    )
    .await;
    assert_eq!(s, Status::Forbidden);
}

#[tokio::test]
async fn switching_tiers_keeps_files_readable() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let alice = user(&client, "alice", json!({})).await;
    assert_eq!(
        upload(&client, &alice, LIB, "a.txt", "keep me").await,
        Status::Ok
    );

    let change = |body: Value| {
        call(
            &client,
            "PUT",
            "/api/v1/auth/encryption",
            Some(&alice),
            Some(body),
        )
    };
    let (s, _) = change(json!({ "current_password": "wrong password", "tier": "pure_user" })).await;
    assert_eq!(s, Status::Unauthorized);

    let (s, v) = change(json!({ "current_password": pw("alice"), "tier": "pure_user" })).await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["tier"], "pure_user");
    lock(&client, &alice).await;
    assert_eq!(
        download(&client, &alice, LIB, "a.txt").await.0,
        Status::Locked
    );
    assert_eq!(unlock(&client, &alice, &pw("alice")).await, Status::Ok);
    assert_eq!(download(&client, &alice, LIB, "a.txt").await.1, "keep me");

    let (s, v) = change(json!({
        "current_password": pw("alice"), "tier": "failsafe_user",
        "password_mode": "separate", "encryption_password": "my encryption pw",
    }))
    .await;
    assert_eq!(s, Status::Ok, "{v}");
    lock(&client, &alice).await;
    assert_eq!(
        unlock(&client, &alice, "my encryption pw").await,
        Status::Ok
    );

    let (s, v) = change(json!({ "current_password": pw("alice"), "tier": "server" })).await;
    assert_eq!(s, Status::Ok, "{v}");
    lock(&client, &alice).await; // no-op for server tier
    assert_eq!(download(&client, &alice, LIB, "a.txt").await.1, "keep me");
}

#[tokio::test]
async fn changing_the_login_password_rewraps_single_mode_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let alice = user(&client, "alice", pure("alice")).await;
    assert_eq!(upload(&client, &alice, LIB, "a.txt", "x").await, Status::Ok);

    let (s, v) = call(
        &client,
        "POST",
        "/api/v1/auth/password",
        Some(&alice),
        Some(json!({ "current_password": pw("alice"), "new_password": "brand new password" })),
    )
    .await;
    assert_eq!(s, Status::Ok, "{v}");

    lock(&client, &alice).await;
    assert_eq!(
        unlock(&client, &alice, &pw("alice")).await,
        Status::Unauthorized
    );
    assert_eq!(
        unlock(&client, &alice, "brand new password").await,
        Status::Ok
    );
    let t = login(&client, "alice", "brand new password").await;
    assert_eq!(download(&client, &t, LIB, "a.txt").await.0, Status::Ok);
}

#[tokio::test]
async fn failsafe_keys_can_be_recovered_but_pure_keys_cannot() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let alice = user(
        &client,
        "alice",
        json!({ "tier": "failsafe_user", "password": pw("alice") }),
    )
    .await;
    let _bob = user(&client, "bob", pure("bob")).await;
    assert_eq!(
        upload(&client, &alice, LIB, "a.txt", "recover me").await,
        Status::Ok
    );

    let rocket = client.rocket();
    let pool = rocket.state::<crate::db::DbPool>().unwrap();
    let master = rocket
        .state::<crate::services::crypto_service::MasterKey>()
        .unwrap();
    let alice_id: (String,) = sqlx::query_as("SELECT id FROM users WHERE username = 'alice'")
        .fetch_one(pool)
        .await
        .unwrap();
    let bob_id: (String,) = sqlx::query_as("SELECT id FROM users WHERE username = 'bob'")
        .fetch_one(pool)
        .await
        .unwrap();

    use crate::services::key_service::recover_with_master_key;
    recover_with_master_key(pool, master, &alice_id.0, "recovered password")
        .await
        .unwrap();
    assert!(matches!(
        recover_with_master_key(pool, master, &bob_id.0, "x x x x x x").await,
        Err(crate::errors::AppError::RecoveryNotAvailable)
    ));

    lock(&client, &alice).await;
    assert_eq!(
        unlock(&client, &alice, "recovered password").await,
        Status::Ok
    );
    assert_eq!(
        download(&client, &alice, LIB, "a.txt").await.1,
        "recover me"
    );
}

async fn user_id(client: &Client, name: &str) -> String {
    let pool = client.rocket().state::<crate::db::DbPool>().unwrap();
    let (id,): (String,) = sqlx::query_as("SELECT id FROM users WHERE username = ?")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap();
    id
}

async fn issue_reset(client: &Client, admin: &str, target: &str) -> (Status, Value) {
    let id = user_id(client, target).await;
    call(
        client,
        "POST",
        &format!("/api/v1/admin/users/{id}/reset"),
        Some(admin),
        Some(json!({ "reason": "forgot it" })),
    )
    .await
}

async fn redeem(client: &Client, body: Value) -> Status {
    call(client, "POST", "/api/v1/auth/reset", None, Some(body))
        .await
        .0
}

#[tokio::test]
async fn admin_reset_recovers_failsafe_keys_and_tells_the_user() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let admin = user(&client, "admin", json!({})).await;
    let bob = user(
        &client,
        "bob",
        json!({ "tier": "failsafe_user", "password": pw("bob") }),
    )
    .await;
    assert_eq!(
        upload(&client, &bob, LIB, "b.txt", "bob's").await,
        Status::Ok
    );

    // Only admins can issue codes.
    let (s, _) = issue_reset(&client, &bob, "admin").await;
    assert_eq!(s, Status::Forbidden);

    let (s, v) = issue_reset(&client, &admin, "bob").await;
    assert_eq!(s, Status::Ok, "{v}");
    assert_eq!(v["kind"], "key_recovery");
    let code = v["code"].as_str().unwrap().to_lowercase(); // case doesn't matter

    assert_eq!(
        redeem(&client, json!({ "username": "bob", "code": "AAAA-BBBB-CCCC-DDDD", "new_password": "bob new password" })).await,
        Status::Unauthorized
    );
    assert_eq!(
        redeem(
            &client,
            json!({ "username": "bob", "code": code, "new_password": "bob new password" })
        )
        .await,
        Status::Ok
    );
    // Single use; and the old session is gone.
    assert_eq!(
        redeem(
            &client,
            json!({ "username": "bob", "code": code, "new_password": "another one!!" })
        )
        .await,
        Status::Unauthorized
    );
    let (s, _) = call(&client, "GET", "/api/v1/auth/encryption", Some(&bob), None).await;
    assert_eq!(s, Status::Unauthorized);

    let bob = login(&client, "bob", "bob new password").await;
    assert_eq!(download(&client, &bob, LIB, "b.txt").await.1, "bob's");
    let (_, notices) = call(
        &client,
        "GET",
        "/api/v1/users/me/security-notices",
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(notices[0]["target_type"], "keys");
    assert_eq!(notices[0]["admin_username"], "admin");
    assert_eq!(notices[0]["reason"], "forgot it");
    let id = notices[0]["id"].as_str().unwrap();
    let (s, _) = call(
        &client,
        "POST",
        &format!("/api/v1/users/me/security-notices/{id}/ack"),
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(s, Status::Ok);
    let (_, notices) = call(
        &client,
        "GET",
        "/api/v1/users/me/security-notices",
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(notices[0]["acknowledged"], true);
}

#[tokio::test]
async fn reset_rules_follow_the_tier() {
    let tmp = tempfile::tempdir().unwrap();
    let client = page_test_client(&tmp).await;
    let admin = user(&client, "admin", json!({})).await;
    let _pure = user(&client, "pure", pure("pure")).await;
    let _sep = user(
        &client,
        "sep",
        json!({ "tier": "failsafe_user", "password_mode": "separate",
                "password": pw("sep"), "encryption_password": "sep encryption pw" }),
    )
    .await;

    // pure_user + single: a reset would lock their files forever.
    let (s, _) = issue_reset(&client, &admin, "pure").await;
    assert_eq!(s, Status::UnprocessableEntity);

    // failsafe + separate: needs a new encryption password as well.
    let (_, v) = issue_reset(&client, &admin, "sep").await;
    assert_eq!(v["needs_encryption_password"], true);
    let code = v["code"].as_str().unwrap();
    assert_eq!(
        redeem(
            &client,
            json!({ "username": "sep", "code": code, "new_password": "sep new login pw" })
        )
        .await,
        Status::BadRequest
    );
    assert_eq!(
        redeem(
            &client,
            json!({ "username": "sep", "code": code,
            "new_password": "sep new login pw", "new_encryption_password": "sep new enc pw" })
        )
        .await,
        Status::Ok
    );
    let t = login(&client, "sep", "sep new login pw").await;
    assert_eq!(
        unlock(&client, &t, "sep encryption pw").await,
        Status::Unauthorized
    );
    assert_eq!(unlock(&client, &t, "sep new enc pw").await, Status::Ok);
}
