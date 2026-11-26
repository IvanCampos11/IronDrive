//! Trash: the browser page plus JSON endpoints (session + CSRF) and the
//! token-authenticated API. Personal trash belongs to the library owner;
//! a space's trash is visible to anyone who can write to the space.

use rocket::http::{CookieJar, Status};
use rocket::serde::json::{serde_json, Json};
use rocket::Route;
use rocket::State;
use rocket_dyn_templates::{context, Template};
use serde::{Deserialize, Serialize};

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::guards::csrf_guard::{ensure_csrf_token, CsrfXhr};
use crate::guards::session_guard::SessionSetupComplete;
use crate::guards::space_guard::{SessionSpaceWriter, SpaceWriter};
use crate::guards::SetupComplete;
use crate::routes::pages::{
    file_icon, format_bytes, format_timestamp, icon_glyph, json_error, require_library,
};
use crate::services::fs_service::TargetKind;
use crate::services::trash_service::{self, TrashItem};

type JsonResult = Result<Json<serde_json::Value>, (Status, Json<serde_json::Value>)>;

#[derive(Deserialize)]
pub struct IdsRequest {
    pub ids: Vec<String>,
}

#[derive(Serialize)]
pub struct RestoredItem {
    pub id: String,
    pub path: String,
}

/// Days until an item deleted at `deleted_at` is purged (None if never).
fn days_left(deleted_at: &str, retention_days: u64) -> Option<i64> {
    if retention_days == 0 {
        return None;
    }
    let deleted = chrono::NaiveDateTime::parse_from_str(deleted_at, "%Y-%m-%d %H:%M:%S").ok()?;
    let age = chrono::Utc::now().naive_utc() - deleted;
    Some((retention_days as i64 - age.num_days()).max(0))
}

fn item_view(item: &TrashItem, root_name: &str, retention_days: u64) -> serde_json::Value {
    let icon = file_icon(item.name(), item.is_dir, None);
    let location = if item.parent().is_empty() {
        root_name.to_string()
    } else {
        format!("{root_name} › {}", item.parent().replace('/', " › "))
    };
    serde_json::json!({
        "id": item.id,
        "name": item.name(),
        "original_path": item.original_path,
        "location": location,
        "is_dir": item.is_dir,
        "icon": icon,
        "glyph": icon_glyph(icon),
        "size": format_bytes(item.size_bytes.max(0) as u64),
        "file_count": item.file_count,
        "deleted": format_timestamp(&item.deleted_at),
        "raw_deleted": format!("{}Z", item.deleted_at.replace(' ', "T")),
        "days_left": days_left(&item.deleted_at, retention_days),
    })
}

#[allow(clippy::too_many_arguments)]
fn render_page(
    cookies: &CookieJar<'_>,
    username: &str,
    current_path: &str,
    base_url: &str,
    root_name: &str,
    back_url: &str,
    space_id: Option<&str>,
    items: &[TrashItem],
    retention_days: u64,
) -> Template {
    let views: Vec<_> = items
        .iter()
        .map(|i| item_view(i, root_name, retention_days))
        .collect();
    let total: i64 = items.iter().map(|i| i.size_bytes.max(0)).sum();
    Template::render(
        "trash/page",
        context! {
            user: username,
            csrf_token: ensure_csrf_token(cookies),
            current_path: current_path,
            base_url: base_url,
            back_url: back_url,
            root_name: root_name,
            space_id: space_id,
            items: views,
            total_size: format_bytes(total as u64),
            retention_days: retention_days,
        },
    )
}

// ---------------------------------------------------------------------------
// Shared actions
// ---------------------------------------------------------------------------

async fn restore_many(
    pool: &DbPool,
    config: &AppConfig,
    kind: TargetKind,
    target_id: &str,
    ids: &[String],
) -> serde_json::Value {
    let mut restored = Vec::new();
    let mut errors = Vec::new();
    for id in ids.iter().take(500) {
        match trash_service::restore(pool, config, kind, target_id, id).await {
            Ok(path) => restored.push(RestoredItem {
                id: id.clone(),
                path,
            }),
            Err(AppError::NotFound) => {
                errors.push("An item is no longer in the trash.".to_string())
            }
            Err(e) => errors.push(e.client_message()),
        }
    }
    serde_json::json!({ "restored": restored, "errors": errors })
}

async fn delete_many(
    pool: &DbPool,
    config: &AppConfig,
    kind: TargetKind,
    target_id: &str,
    ids: &[String],
) -> serde_json::Value {
    let mut deleted = 0;
    let mut errors = Vec::new();
    for id in ids.iter().take(500) {
        match trash_service::delete_forever(pool, config, kind, target_id, id).await {
            Ok(()) => deleted += 1,
            Err(AppError::NotFound) => {}
            Err(e) => errors.push(e.client_message()),
        }
    }
    serde_json::json!({ "deleted": deleted, "errors": errors })
}

async fn library_id(
    pool: &DbPool,
    user_id: &str,
) -> Result<String, (Status, Json<serde_json::Value>)> {
    require_library(pool, user_id)
        .await
        .map(|l| l.id)
        .map_err(json_error)
}

// ---------------------------------------------------------------------------
// Browser: personal trash
// ---------------------------------------------------------------------------

#[get("/trash")]
pub async fn trash_page(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
) -> Result<Template, Status> {
    let lib = require_library(pool.inner(), &user.0.id)
        .await
        .map_err(|_| Status::NotFound)?;
    let items = trash_service::list(pool.inner(), TargetKind::Library, &lib.id)
        .await
        .map_err(|_| Status::InternalServerError)?;
    Ok(render_page(
        cookies,
        &user.0.username,
        "trash",
        "/trash",
        "My files",
        "/files",
        None,
        &items,
        config.trash_retention_days,
    ))
}

#[post("/trash/restore", data = "<body>")]
pub async fn trash_restore(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    _csrf: CsrfXhr,
    user: SessionSetupComplete,
    body: Json<IdsRequest>,
) -> JsonResult {
    let lib = library_id(pool.inner(), &user.0.id).await?;
    Ok(Json(
        restore_many(
            pool.inner(),
            config.inner(),
            TargetKind::Library,
            &lib,
            &body.ids,
        )
        .await,
    ))
}

#[post("/trash/delete", data = "<body>")]
pub async fn trash_delete(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    _csrf: CsrfXhr,
    user: SessionSetupComplete,
    body: Json<IdsRequest>,
) -> JsonResult {
    let lib = library_id(pool.inner(), &user.0.id).await?;
    Ok(Json(
        delete_many(
            pool.inner(),
            config.inner(),
            TargetKind::Library,
            &lib,
            &body.ids,
        )
        .await,
    ))
}

#[post("/trash/empty")]
pub async fn trash_empty(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    _csrf: CsrfXhr,
    user: SessionSetupComplete,
) -> JsonResult {
    let lib = library_id(pool.inner(), &user.0.id).await?;
    let n = trash_service::empty(pool.inner(), config.inner(), TargetKind::Library, &lib)
        .await
        .map_err(json_error)?;
    Ok(Json(serde_json::json!({ "deleted": n })))
}

// ---------------------------------------------------------------------------
// Browser: space trash
// ---------------------------------------------------------------------------

#[get("/spaces/<space_id>/trash")]
pub async fn space_trash_page(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    cookies: &CookieJar<'_>,
    writer: SessionSpaceWriter,
    space_id: &str,
) -> Result<Template, Status> {
    let items = trash_service::list(pool.inner(), TargetKind::Space, space_id)
        .await
        .map_err(|_| Status::InternalServerError)?;
    let base = format!("/spaces/{space_id}/trash");
    let back = format!("/spaces/{space_id}");
    Ok(render_page(
        cookies,
        &writer.user.username,
        "spaces",
        &base,
        &writer.space.space.name,
        &back,
        Some(space_id),
        &items,
        config.trash_retention_days,
    ))
}

#[post("/spaces/<space_id>/trash/restore", data = "<body>")]
pub async fn space_trash_restore(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    _csrf: CsrfXhr,
    _writer: SessionSpaceWriter,
    space_id: &str,
    body: Json<IdsRequest>,
) -> JsonResult {
    Ok(Json(
        restore_many(
            pool.inner(),
            config.inner(),
            TargetKind::Space,
            space_id,
            &body.ids,
        )
        .await,
    ))
}

#[post("/spaces/<space_id>/trash/delete", data = "<body>")]
pub async fn space_trash_delete(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    _csrf: CsrfXhr,
    _writer: SessionSpaceWriter,
    space_id: &str,
    body: Json<IdsRequest>,
) -> JsonResult {
    Ok(Json(
        delete_many(
            pool.inner(),
            config.inner(),
            TargetKind::Space,
            space_id,
            &body.ids,
        )
        .await,
    ))
}

#[post("/spaces/<space_id>/trash/empty")]
pub async fn space_trash_empty(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    _csrf: CsrfXhr,
    _writer: SessionSpaceWriter,
    space_id: &str,
) -> JsonResult {
    let n = trash_service::empty(pool.inner(), config.inner(), TargetKind::Space, space_id)
        .await
        .map_err(json_error)?;
    Ok(Json(serde_json::json!({ "deleted": n })))
}

// ---------------------------------------------------------------------------
// API (token auth)
// ---------------------------------------------------------------------------

#[get("/api/v1/library/trash")]
pub async fn api_library_trash(
    pool: &State<DbPool>,
    user: SetupComplete,
) -> Result<Json<Vec<TrashItem>>, AppError> {
    let lib = require_library(pool.inner(), &user.0.id).await?;
    Ok(Json(
        trash_service::list(pool.inner(), TargetKind::Library, &lib.id).await?,
    ))
}

#[post("/api/v1/library/trash/<id>/restore")]
pub async fn api_library_restore(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    user: SetupComplete,
    id: &str,
) -> Result<Json<RestoredItem>, AppError> {
    let lib = require_library(pool.inner(), &user.0.id).await?;
    let path = trash_service::restore(
        pool.inner(),
        config.inner(),
        TargetKind::Library,
        &lib.id,
        id,
    )
    .await?;
    Ok(Json(RestoredItem {
        id: id.to_string(),
        path,
    }))
}

#[delete("/api/v1/library/trash/<id>")]
pub async fn api_library_delete_forever(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    user: SetupComplete,
    id: &str,
) -> Result<Status, AppError> {
    let lib = require_library(pool.inner(), &user.0.id).await?;
    trash_service::delete_forever(
        pool.inner(),
        config.inner(),
        TargetKind::Library,
        &lib.id,
        id,
    )
    .await?;
    Ok(Status::NoContent)
}

#[delete("/api/v1/library/trash")]
pub async fn api_library_empty(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    user: SetupComplete,
) -> Result<Json<serde_json::Value>, AppError> {
    let lib = require_library(pool.inner(), &user.0.id).await?;
    let n =
        trash_service::empty(pool.inner(), config.inner(), TargetKind::Library, &lib.id).await?;
    Ok(Json(serde_json::json!({ "deleted": n })))
}

#[get("/api/v1/spaces/<_id>/trash")]
pub async fn api_space_trash(
    pool: &State<DbPool>,
    _id: &str,
    writer: SpaceWriter,
) -> Result<Json<Vec<TrashItem>>, AppError> {
    Ok(Json(
        trash_service::list(pool.inner(), TargetKind::Space, &writer.space.space.id).await?,
    ))
}

#[post("/api/v1/spaces/<_id>/trash/<id>/restore")]
pub async fn api_space_restore(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    _id: &str,
    writer: SpaceWriter,
    id: &str,
) -> Result<Json<RestoredItem>, AppError> {
    let path = trash_service::restore(
        pool.inner(),
        config.inner(),
        TargetKind::Space,
        &writer.space.space.id,
        id,
    )
    .await?;
    Ok(Json(RestoredItem {
        id: id.to_string(),
        path,
    }))
}

#[delete("/api/v1/spaces/<_id>/trash/<id>")]
pub async fn api_space_delete_forever(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    _id: &str,
    writer: SpaceWriter,
    id: &str,
) -> Result<Status, AppError> {
    trash_service::delete_forever(
        pool.inner(),
        config.inner(),
        TargetKind::Space,
        &writer.space.space.id,
        id,
    )
    .await?;
    Ok(Status::NoContent)
}

#[delete("/api/v1/spaces/<_id>/trash")]
pub async fn api_space_empty(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    _id: &str,
    writer: SpaceWriter,
) -> Result<Json<serde_json::Value>, AppError> {
    let n = trash_service::empty(
        pool.inner(),
        config.inner(),
        TargetKind::Space,
        &writer.space.space.id,
    )
    .await?;
    Ok(Json(serde_json::json!({ "deleted": n })))
}

pub fn routes() -> Vec<Route> {
    routes![
        trash_page,
        trash_restore,
        trash_delete,
        trash_empty,
        space_trash_page,
        space_trash_restore,
        space_trash_delete,
        space_trash_empty,
        api_library_trash,
        api_library_restore,
        api_library_delete_forever,
        api_library_empty,
        api_space_trash,
        api_space_restore,
        api_space_delete_forever,
        api_space_empty,
    ]
}
