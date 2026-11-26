//! Streaming downloads: single files (with HTTP Range support) and folders
//! as zip archives. Nothing is buffered whole — files are decrypted segment
//! by segment as the client reads, so memory use doesn't grow with file size.

use std::pin::Pin;

use rocket::futures::TryStreamExt;
use rocket::http::{ContentType, Header, Status};
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::{self, Responder, Response};
use tokio::io::AsyncRead;
use tokio_util::io::StreamReader;

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::routes::library::{content_disposition_attachment, DOWNLOAD_CSP};
use crate::services::crypto_service::{self, PlaintextStream};
use crate::services::fs_service::{self, TargetKind};
use crate::services::integrity_service;
use crate::services::unlock_state::UnlockState;

/// The raw `Range` request header, if any.
pub struct RangeHeader(pub Option<String>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RangeHeader {
    type Error = std::convert::Infallible;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(RangeHeader(
            req.headers().get_one("Range").map(str::to_string),
        ))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ByteRange {
    /// No (usable) range: send the whole file with 200.
    Full,
    /// Send bytes `[start, end)` with 206.
    Partial(u64, u64),
    /// Range can't be satisfied: 416.
    Unsatisfiable,
}

/// Parse a single-range `Range: bytes=...` header against a file of `size`
/// bytes. Multi-range and malformed headers fall back to the full file, as
/// RFC 9110 allows.
pub fn parse_range(header: Option<&str>, size: u64) -> ByteRange {
    let Some(spec) = header.and_then(|h| h.trim().strip_prefix("bytes=")) else {
        return ByteRange::Full;
    };
    if spec.contains(',') {
        return ByteRange::Full;
    }
    let Some((a, b)) = spec.trim().split_once('-') else {
        return ByteRange::Full;
    };
    let (a, b) = (a.trim(), b.trim());

    if a.is_empty() {
        // Suffix range: the last N bytes.
        return match b.parse::<u64>() {
            Ok(0) => ByteRange::Unsatisfiable,
            Ok(_) if size == 0 => ByteRange::Unsatisfiable,
            Ok(n) => ByteRange::Partial(size - n.min(size), size),
            Err(_) => ByteRange::Full,
        };
    }

    let Ok(start) = a.parse::<u64>() else {
        return ByteRange::Full;
    };
    let end = if b.is_empty() {
        size
    } else {
        match b.parse::<u64>() {
            Ok(last) if last >= start => last.saturating_add(1).min(size),
            _ => return ByteRange::Full,
        }
    };
    if start >= size {
        ByteRange::Unsatisfiable
    } else {
        ByteRange::Partial(start, end)
    }
}

type Body = Pin<Box<dyn AsyncRead + Send>>;

/// A streamed file or archive. `length` is sent as Content-Length when known,
/// so a stream that aborts early is seen by the client as a failed download
/// rather than a short, "successful" one.
pub struct StreamedDownload {
    status: Status,
    filename: String,
    content_type: ContentType,
    length: Option<u64>,
    content_range: Option<String>,
    /// Plaintext SHA-256, when known up front (small files).
    checksum: Option<String>,
    body: Option<Body>,
}

impl<'r> Responder<'r, 'static> for StreamedDownload {
    fn respond_to(self, _request: &'r Request<'_>) -> response::Result<'static> {
        let mut res = Response::build();
        res.status(self.status)
            .header(self.content_type)
            .header(Header::new(
                "Content-Disposition",
                content_disposition_attachment(&self.filename),
            ))
            .header(Header::new("Content-Security-Policy", DOWNLOAD_CSP))
            .header(Header::new("Cache-Control", "private, no-store"));
        if let Some(range) = self.content_range {
            res.header(Header::new("Content-Range", range));
        }
        if let Some(sum) = self.checksum {
            res.header(Header::new("X-IronDrive-Integrity", sum));
        }
        if let Some(len) = self.length {
            res.header(Header::new("Accept-Ranges", "bytes"))
                .raw_header("Content-Length", len.to_string());
        }
        if let Some(body) = self.body {
            res.streamed_body(body);
        }
        res.ok()
    }
}

fn content_type_of(mime: Option<&str>) -> ContentType {
    mime.and_then(|m| m.split_once('/'))
        .map(|(top, sub)| ContentType::new(top.to_string(), sub.to_string()))
        .unwrap_or(ContentType::Binary)
}

/// Record that a file couldn't be decrypted while someone downloaded it.
async fn record_damage(pool: &DbPool, kind: TargetKind, target_id: &str, path: &str, detail: &str) {
    let _ = integrity_service::record_event(
        pool,
        kind.as_str(),
        target_id,
        path,
        "decrypt_failed",
        Some(detail),
        "download",
    )
    .await;
}

/// Record an integrity alert when a stream hits a damaged segment.
fn report_damage(
    stream: PlaintextStream,
    pool: &DbPool,
    kind: TargetKind,
    target_id: &str,
    path: &str,
) -> PlaintextStream {
    let pool = pool.clone();
    let target_id = target_id.to_string();
    let path = path.to_string();
    Box::pin(stream.inspect_err(move |e| {
        if e.kind() != std::io::ErrorKind::InvalidData {
            return; // e.g. the client went away
        }
        let (pool, target_id, path) = (pool.clone(), target_id.clone(), path.clone());
        tokio::spawn(async move {
            record_damage(
                &pool,
                kind,
                &target_id,
                &path,
                "A download stopped at a damaged part of the file.",
            )
            .await;
        });
    }))
}

/// Stream one file from a library or space, honouring a `Range` header.
pub async fn stream_file(
    pool: &DbPool,
    config: &AppConfig,
    unlock_state: &UnlockState,
    kind: TargetKind,
    target_id: &str,
    user_path: &str,
    range: &RangeHeader,
) -> Result<StreamedDownload, AppError> {
    let file =
        fs_service::resolve_readable_file(config, unlock_state, kind, target_id, user_path).await?;
    let size = file.plaintext_size;
    let content_type = content_type_of(file.mime_type.as_deref());

    let (status, start, end, content_range) = match parse_range(range.0.as_deref(), size) {
        ByteRange::Full => (Status::Ok, 0, size, None),
        ByteRange::Partial(s, e) => (
            Status::PartialContent,
            s,
            e,
            Some(format!("bytes {s}-{}/{size}", e - 1)),
        ),
        ByteRange::Unsatisfiable => {
            return Ok(StreamedDownload {
                status: Status::RangeNotSatisfiable,
                filename: file.filename,
                content_type,
                length: Some(0),
                content_range: Some(format!("bytes */{size}")),
                checksum: None,
                body: None,
            })
        }
    };

    // Small files are stored in one piece and decrypted whole anyway, so a
    // full download of one can carry its SHA-256 (X-IronDrive-Integrity),
    // as the API always has. Chunked files stream without it.
    if status == Status::Ok && !crypto_service::is_stream_format(&file.path).await {
        let plaintext =
            match crypto_service::read_and_decrypt_file(&file.data_key, &file.path).await {
                Ok(p) => p,
                Err(e) => {
                    if matches!(e, AppError::Internal(_)) {
                        record_damage(
                            pool,
                            kind,
                            target_id,
                            user_path,
                            "The file could not be decrypted for download.",
                        )
                        .await;
                    }
                    return Err(e);
                }
            };
        let checksum = hex::encode(crypto_service::sha256_bytes(&plaintext));
        let len = plaintext.len() as u64;
        return Ok(StreamedDownload {
            status,
            filename: file.filename,
            content_type,
            length: Some(len),
            content_range: None,
            checksum: Some(checksum),
            body: Some(Box::pin(std::io::Cursor::new(plaintext))),
        });
    }

    let stream =
        match crypto_service::open_plaintext_stream(&file.data_key, &file.path, start, end).await {
            Ok(s) => s,
            Err(e) => {
                if matches!(e, AppError::Internal(_)) {
                    record_damage(
                        pool,
                        kind,
                        target_id,
                        user_path,
                        "The file could not be decrypted for download.",
                    )
                    .await;
                }
                return Err(e);
            }
        };
    let stream = report_damage(stream, pool, kind, target_id, user_path);

    Ok(StreamedDownload {
        status,
        filename: file.filename,
        content_type,
        length: Some(end - start),
        content_range,
        checksum: None,
        body: Some(Box::pin(StreamReader::new(stream))),
    })
}

// ---------------------------------------------------------------------------
// Folder downloads (zip)
// ---------------------------------------------------------------------------

/// One thing to put in the archive.
struct ZipItem {
    /// Path inside the zip ("Photos/2024/beach.jpg"; folders end in "/").
    name: String,
    /// Path relative to the library/space root, for alerts.
    rel: String,
    abs: std::path::PathBuf,
    is_dir: bool,
    modified: Option<std::time::SystemTime>,
}

/// Collect everything under `paths` (files and folders, recursively),
/// skipping hidden entries. Each top-level item keeps its own name, so
/// selecting "Photos" yields "Photos/...".
async fn collect_zip_items(
    root: &std::path::Path,
    paths: &[String],
) -> Result<Vec<ZipItem>, AppError> {
    let mut items = Vec::new();
    for user_path in paths {
        let abs = fs_service::safe_join_async(root.to_path_buf(), user_path.clone()).await?;
        let meta = tokio::fs::metadata(&abs).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::NotFound
            } else {
                AppError::Internal(format!("Cannot read entry metadata: {e}"))
            }
        })?;
        let top = user_path
            .rsplit('/')
            .next()
            .unwrap_or(user_path)
            .to_string();
        if !meta.is_dir() {
            items.push(ZipItem {
                name: top,
                rel: user_path.clone(),
                abs,
                is_dir: false,
                modified: meta.modified().ok(),
            });
            continue;
        }

        let mut stack = vec![(abs, top, user_path.clone())];
        while let Some((dir, name, rel)) = stack.pop() {
            let dir_meta = tokio::fs::metadata(&dir).await.ok();
            items.push(ZipItem {
                name: format!("{name}/"),
                rel: rel.clone(),
                abs: dir.clone(),
                is_dir: true,
                modified: dir_meta.and_then(|m| m.modified().ok()),
            });
            let mut rd = tokio::fs::read_dir(&dir).await?;
            let mut children = Vec::new();
            while let Some(entry) = rd.next_entry().await? {
                let child = entry.file_name().to_string_lossy().to_string();
                if child.starts_with('.') {
                    continue;
                }
                let Ok(m) = entry.metadata().await else {
                    continue;
                };
                children.push((child, entry.path(), m));
            }
            children.sort_by(|a, b| a.0.cmp(&b.0));
            for (child, path, m) in children.into_iter().rev() {
                let child_name = format!("{name}/{child}");
                let child_rel = format!("{rel}/{child}");
                if m.is_dir() {
                    stack.push((path, child_name, child_rel));
                } else if m.is_file() {
                    items.push(ZipItem {
                        name: child_name,
                        rel: child_rel,
                        abs: path,
                        is_dir: false,
                        modified: m.modified().ok(),
                    });
                }
            }
        }
    }
    // Directory entries were pushed before their contents; keep a stable,
    // readable order (by path) so the archive lists naturally.
    items.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(items)
}

fn zip_date(t: Option<std::time::SystemTime>) -> async_zip::ZipDateTime {
    use chrono::{Datelike, Timelike};
    let dt: chrono::DateTime<chrono::Utc> = t.unwrap_or_else(std::time::SystemTime::now).into();
    async_zip::ZipDateTimeBuilder::new()
        .year(dt.year().max(1980))
        .month(dt.month())
        .day(dt.day())
        .hour(dt.hour())
        .minute(dt.minute())
        .second(dt.second())
        .build()
}

/// `AsyncWrite` that forwards everything into a channel feeding the HTTP
/// response, so the zip writer can run in its own task.
struct ChannelWriter {
    tx: tokio_util::sync::PollSender<std::io::Result<bytes::Bytes>>,
}

impl tokio::io::AsyncWrite for ChannelWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        let closed = || std::io::Error::new(std::io::ErrorKind::BrokenPipe, "client went away");
        match self.tx.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(closed())),
            Poll::Ready(Ok(())) => {
                let chunk = bytes::Bytes::copy_from_slice(buf);
                match self.tx.send_item(Ok(chunk)) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(_) => Poll::Ready(Err(closed())),
                }
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Name of the note added to an archive when some files couldn't be read.
pub const ZIP_ERRORS_NOTE: &str = "IronDrive - files that could not be read.txt";

async fn write_zip(
    writer: ChannelWriter,
    items: Vec<ZipItem>,
    data_key: crypto_service::DataKey,
    pool: DbPool,
    kind: TargetKind,
    target_id: String,
) -> Result<(), String> {
    use async_zip::{Compression, ZipEntryBuilder};
    use rocket::futures::{AsyncWriteExt, StreamExt};

    let mut zip = async_zip::tokio::write::ZipFileWriter::with_tokio(writer);
    let mut unreadable: Vec<String> = Vec::new();

    for item in items {
        let entry = ZipEntryBuilder::new(item.name.clone().into(), Compression::Stored)
            .last_modification_date(zip_date(item.modified));
        if item.is_dir {
            zip.write_entry_whole(entry, &[])
                .await
                .map_err(|e| e.to_string())?;
            continue;
        }

        let mut out = zip
            .write_entry_stream(entry)
            .await
            .map_err(|e| e.to_string())?;
        match crypto_service::open_plaintext_stream(&data_key, &item.abs, 0, u64::MAX).await {
            Ok(mut stream) => {
                while let Some(chunk) = stream.next().await {
                    match chunk {
                        Ok(bytes) => out.write_all(&bytes).await.map_err(|e| e.to_string())?,
                        Err(e) => {
                            // The entry ends early; the note below says so.
                            unreadable.push(item.name.clone());
                            if e.kind() == std::io::ErrorKind::InvalidData {
                                record_damage(
                                    &pool,
                                    kind,
                                    &target_id,
                                    &item.rel,
                                    "A folder download stopped at a damaged part of the file.",
                                )
                                .await;
                            }
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                unreadable.push(item.name.clone());
                if matches!(e, AppError::Internal(_)) {
                    record_damage(
                        &pool,
                        kind,
                        &target_id,
                        &item.rel,
                        "The file could not be decrypted for a folder download.",
                    )
                    .await;
                }
            }
        }
        out.close().await.map_err(|e| e.to_string())?;
    }

    if !unreadable.is_empty() {
        let note = format!(
            "These files could not be read completely, so their copies in this archive are \
             incomplete or empty. They may be damaged on the server; check the alerts in \
             IronDrive.\n\n{}\n",
            unreadable.join("\n")
        );
        let entry = ZipEntryBuilder::new(ZIP_ERRORS_NOTE.to_string().into(), Compression::Stored)
            .last_modification_date(zip_date(None));
        zip.write_entry_whole(entry, note.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
    }

    zip.close().await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Stream a zip of `paths` (files and/or folders) from a library or space.
/// `archive_name` is used for the download's file name (".zip" is added).
#[allow(clippy::too_many_arguments)]
pub async fn stream_zip(
    pool: &DbPool,
    config: &AppConfig,
    unlock_state: &UnlockState,
    kind: TargetKind,
    target_id: &str,
    paths: Vec<String>,
    archive_name: &str,
) -> Result<StreamedDownload, AppError> {
    if paths.is_empty() || paths.len() > 1000 {
        return Err(AppError::Validation(
            "Choose between 1 and 1000 items.".into(),
        ));
    }
    let data_key = match kind {
        TargetKind::Library => unlock_state.get_library_key(target_id),
        TargetKind::Space => unlock_state.get_space_key(target_id),
    }
    .ok_or(AppError::Locked)?;
    let root = fs_service::root_of(config, kind, target_id);
    let items = collect_zip_items(&root, &paths).await?;

    let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<bytes::Bytes>>(8);
    let writer = ChannelWriter {
        tx: tokio_util::sync::PollSender::new(tx.clone()),
    };
    let pool = pool.clone();
    let target_id = target_id.to_string();
    tokio::spawn(async move {
        if let Err(e) = write_zip(writer, items, data_key, pool, kind, target_id).await {
            tracing::warn!(error = %e, "Folder download stopped");
            // Make the response fail instead of ending like a complete file.
            let _ = tx
                .send(Err(std::io::Error::other("archive could not be completed")))
                .await;
        }
    });

    let body = StreamReader::new(tokio_stream_from(rx));
    Ok(StreamedDownload {
        status: Status::Ok,
        filename: format!("{archive_name}.zip"),
        content_type: ContentType::ZIP,
        length: None,
        content_range: None,
        checksum: None,
        body: Some(Box::pin(body)),
    })
}

/// Adapt an mpsc receiver into a `Stream`.
fn tokio_stream_from(
    mut rx: tokio::sync::mpsc::Receiver<std::io::Result<bytes::Bytes>>,
) -> PlaintextStream {
    Box::pin(rocket::futures::stream::poll_fn(move |cx| rx.poll_recv(cx)))
}

// ---------------------------------------------------------------------------
// Zip routes
// ---------------------------------------------------------------------------

/// Archive name: the item's own name for a single selection, otherwise the
/// folder the items are in (or the root's name).
fn archive_name(paths: &[String], root_name: &str) -> String {
    let base = |p: &str| p.rsplit('/').next().unwrap_or(p).to_string();
    match paths {
        [one] => base(one),
        [first, ..] => match first.rsplit_once('/') {
            Some((parent, _)) => base(parent),
            None => root_name.to_string(),
        },
        [] => root_name.to_string(),
    }
}

#[get("/files/zip?<path>")]
pub async fn files_zip(
    pool: &rocket::State<DbPool>,
    config: &rocket::State<AppConfig>,
    unlock_state: &rocket::State<UnlockState>,
    user: crate::guards::session_guard::SessionSetupComplete,
    path: Vec<String>,
) -> Result<StreamedDownload, (Status, String)> {
    let fail = |e: AppError| (e.status(), e.client_message());
    let lib = crate::routes::pages::require_library(pool.inner(), &user.0.id)
        .await
        .map_err(fail)?;
    let name = archive_name(&path, "My files");
    stream_zip(
        pool.inner(),
        config.inner(),
        unlock_state.inner(),
        TargetKind::Library,
        &lib.id,
        path,
        &name,
    )
    .await
    .map_err(fail)
}

#[get("/spaces/<space_id>/zip?<path>")]
pub async fn space_zip(
    pool: &rocket::State<DbPool>,
    config: &rocket::State<AppConfig>,
    unlock_state: &rocket::State<UnlockState>,
    reader: crate::guards::space_guard::SessionSpaceReader,
    space_id: &str,
    path: Vec<String>,
) -> Result<StreamedDownload, (Status, String)> {
    let name = archive_name(&path, &reader.space.space.name);
    stream_zip(
        pool.inner(),
        config.inner(),
        unlock_state.inner(),
        TargetKind::Space,
        space_id,
        path,
        &name,
    )
    .await
    .map_err(|e| (e.status(), e.client_message()))
}

/// GET /api/v1/library/zip?path=a&path=b — stream a zip of files/folders.
#[get("/api/v1/library/zip?<path>")]
pub async fn api_library_zip(
    pool: &rocket::State<DbPool>,
    config: &rocket::State<AppConfig>,
    unlock_state: &rocket::State<UnlockState>,
    user: crate::guards::SetupComplete,
    path: Vec<String>,
) -> Result<StreamedDownload, AppError> {
    let lib = crate::routes::pages::require_library(pool.inner(), &user.0.id).await?;
    let name = archive_name(&path, "My files");
    stream_zip(
        pool.inner(),
        config.inner(),
        unlock_state.inner(),
        TargetKind::Library,
        &lib.id,
        path,
        &name,
    )
    .await
}

/// GET /api/v1/spaces/<id>/files/zip?path=a&path=b
#[get("/api/v1/spaces/<_id>/files/zip?<path>")]
pub async fn api_space_zip(
    pool: &rocket::State<DbPool>,
    config: &rocket::State<AppConfig>,
    unlock_state: &rocket::State<UnlockState>,
    _id: &str,
    reader: crate::guards::space_guard::SpaceReader,
    path: Vec<String>,
) -> Result<StreamedDownload, AppError> {
    let name = archive_name(&path, &reader.space.space.name);
    stream_zip(
        pool.inner(),
        config.inner(),
        unlock_state.inner(),
        TargetKind::Space,
        &reader.space.space.id,
        path,
        &name,
    )
    .await
}

pub fn routes() -> Vec<rocket::Route> {
    routes![files_zip, space_zip, api_library_zip, api_space_zip]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_parsing() {
        use ByteRange::*;
        assert_eq!(parse_range(None, 100), Full);
        assert_eq!(parse_range(Some("bytes=0-9"), 100), Partial(0, 10));
        assert_eq!(parse_range(Some("bytes=90-"), 100), Partial(90, 100));
        assert_eq!(parse_range(Some("bytes=90-500"), 100), Partial(90, 100));
        assert_eq!(parse_range(Some("bytes=-10"), 100), Partial(90, 100));
        assert_eq!(parse_range(Some("bytes=-500"), 100), Partial(0, 100));
        assert_eq!(parse_range(Some("bytes=100-"), 100), Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=-0"), 100), Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=0-"), 0), Unsatisfiable);
        // Ignored (full response): other units, multiple ranges, junk.
        assert_eq!(parse_range(Some("items=0-1"), 100), Full);
        assert_eq!(parse_range(Some("bytes=0-1,5-6"), 100), Full);
        assert_eq!(parse_range(Some("bytes=9-3"), 100), Full);
        assert_eq!(parse_range(Some("bytes=x-"), 100), Full);
    }

    #[test]
    fn archive_names() {
        let p = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(archive_name(&p(&["Photos"]), "My files"), "Photos");
        assert_eq!(archive_name(&p(&["a/b/Trip"]), "My files"), "Trip");
        assert_eq!(archive_name(&p(&["a", "b"]), "My files"), "My files");
        assert_eq!(archive_name(&p(&["x/a", "x/b"]), "My files"), "x");
    }
}
