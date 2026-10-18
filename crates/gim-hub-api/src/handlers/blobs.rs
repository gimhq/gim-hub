//! Encrypted attachments, and federated reads of blobs uploaded on other
//! hubs (docs/federation.md §5.6).

use std::{
    io,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
};

use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures_util::StreamExt;
use gim_hub_db::blobs::{self, Blob, RemoteBlob};
use gim_hub_identity::HubId;
use gim_hub_s2s::{
    ops::blob::{self as s2s_blob, CHUNK_BYTES},
    BlobOrigin, BlobService, FederationService, FetchBlobError,
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
};

use crate::{
    auth::AuthDevice,
    dto::{BlobCreated, Error, RawBytes},
    error::{ApiError, PEER_UNAVAILABLE_RETRY_AFTER},
    state::AppState,
};

const READ_CHUNK_BYTES: usize = 64 * 1024;

#[utoipa::path(
    post,
    path = "/v2/blobs",
    tag = "blobs",
    summary = "Upload an encrypted blob",
    description = "Stores the request body verbatim. The client encrypts before upload and shares \
the blob ID and key inside MLS messages. Bodies larger than the hub limit (default 104857600 \
bytes) fail with 413. The blob ID is `<hub_id>/b_<random>`, naming this hub as the origin; \
percent-encode the `/` as `%2F` in paths.",
    request_body(content = inline(RawBytes), content_type = "application/octet-stream", description = "Raw encrypted bytes"),
    security(("bearerAuth" = [])),
    responses(
        (status = 201, description = "Blob stored", body = BlobCreated),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 413, description = "Payload too large (`payload_too_large`)", body = Error),
    ),
)]
pub async fn upload_blob(
    State(state): State<AppState>,
    auth: AuthDevice,
    headers: HeaderMap,
    body: Body,
) -> Result<(StatusCode, Json<BlobCreated>), ApiError> {
    let max = state.config.load().max_blob_bytes;
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok()?.parse::<u64>().ok());
    if declared.is_some_and(|len| len > max) {
        return Err(ApiError::PayloadTooLarge);
    }

    let dir = state.config.load().blobs_dir();
    tokio::fs::create_dir_all(&dir).await.map_err(internal)?;
    let blob_id = new_blob_id(state.hub.hub_id())?;
    let name = s2s_blob::file_name(&blob_id);
    let path = dir.join(&name);
    // Write to a temp file and rename, so a blob file is always complete.
    let tmp = dir.join(format!(".{name}.tmp"));
    let size = match write_body(&tmp, body, max).await {
        Ok(size) => size,
        Err(err) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(err);
        }
    };
    if let Err(err) = tokio::fs::rename(&tmp, &path).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(internal(err));
    }

    let blob = Blob {
        blob_id: blob_id.clone(),
        size: i64::try_from(size).map_err(internal)?,
        uploader_user_id: auth.user_id,
        uploader_device_id: auth.device_id,
        created_at: state.clock.now_ms(),
    };
    if let Err(err) = state.db.write(move |tx| blobs::insert(tx, &blob)).await {
        let _ = tokio::fs::remove_file(&path).await;
        return Err(err.into());
    }
    Ok((StatusCode::CREATED, Json(BlobCreated { blob_id, size })))
}

/// Streams `body` into a new file at `path`; fails with 413 once more than
/// `max` bytes arrive. Returns the number of bytes written.
async fn write_body(path: &FsPath, body: Body, max: u64) -> Result<u64, ApiError> {
    let mut file = File::create(path).await.map_err(internal)?;
    let mut stream = body.into_data_stream();
    let mut size: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|err| ApiError::ValidationFailed(format!("reading request body: {err}")))?;
        size += chunk.len() as u64;
        if size > max {
            return Err(ApiError::PayloadTooLarge);
        }
        file.write_all(&chunk).await.map_err(internal)?;
    }
    file.sync_all().await.map_err(internal)?;
    Ok(size)
}

#[utoipa::path(
    get,
    path = "/v2/blobs/{blob_id}",
    tag = "blobs",
    summary = "Download an encrypted blob",
    description = "Supports a single byte range (`Range: bytes=a-b`, `bytes=a-`, or `bytes=-n`). \
A blob uploaded on another hub (its ID names that hub as the origin) is fetched from the origin \
on first access, cached, and then served like a local blob. Legacy IDs without `/` name this hub.",
    params(
        ("blob_id" = String, Path, description = "Blob ID `<origin hub_id>/b_<random>`, `/` percent-encoded as `%2F`; legacy IDs are `b_<random>`", example = "hciqgtrdldzdkwq3c7fkmzvld7djgm3waetwtedhujnndujzulpgk6vq%2Fb_Hk4dN7sL2pX9cV0mB5qT1g"),
        ("Range" = Option<String>, Header, description = "Single byte range", example = "bytes=0-1023"),
    ),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Whole blob", body = inline(RawBytes), content_type = "application/octet-stream"),
        (status = 206, description = "Requested range", body = inline(RawBytes), content_type = "application/octet-stream"),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
        (status = 416, description = "Range not satisfiable (`range_not_satisfiable`)", body = Error),
        (status = 502, description = "The origin hub refused to serve the blob (`peer_refused`)", body = Error),
        (status = 503, description = "The origin hub is unreachable (`peer_unavailable`, with `Retry-After`)", body = Error),
    ),
)]
pub async fn download_blob(
    State(state): State<AppState>,
    _auth: AuthDevice,
    Path(blob_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let path = match s2s_blob::parse_blob_id(&blob_id) {
        None => return Err(ApiError::NotFound),
        Some(BlobOrigin::Hub(origin)) if origin != *state.hub.hub_id() => {
            remote_copy(&state, origin, blob_id).await?
        }
        Some(_) => {
            // Only IDs recorded in the database are mapped to file names.
            let lookup_id = blob_id.clone();
            state
                .db
                .read(move |conn| blobs::get(conn, &lookup_id))
                .await?
                .ok_or(ApiError::NotFound)?;
            state
                .config
                .load()
                .blobs_dir()
                .join(s2s_blob::file_name(&blob_id))
        }
    };
    serve_file(&path, &headers).await
}

/// Serves the blob file at `path`, honouring a single `Range`.
async fn serve_file(path: &FsPath, headers: &HeaderMap) -> Result<Response, ApiError> {
    let mut file = match File::open(path).await {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Err(ApiError::NotFound),
        Err(err) => return Err(internal(err)),
    };
    let size = file.metadata().await.map_err(internal)?.len();

    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| parse_range(value, size));
    let (status, start, len) = match range {
        None => (StatusCode::OK, 0, size),
        Some(Range::Unsatisfiable) => {
            let mut response = ApiError::RangeNotSatisfiable.into_response();
            response.headers_mut().insert(
                header::CONTENT_RANGE,
                header_value(&format!("bytes */{size}"))?,
            );
            return Ok(response);
        }
        Some(Range::Bytes { start, end }) => (StatusCode::PARTIAL_CONTENT, start, end - start + 1),
    };
    if start > 0 {
        file.seek(io::SeekFrom::Start(start))
            .await
            .map_err(internal)?;
    }

    let mut response = Response::new(Body::from_stream(read_stream(file.take(len))));
    *response.status_mut() = status;
    let response_headers = response.headers_mut();
    response_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response_headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    response_headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    if status == StatusCode::PARTIAL_CONTENT {
        response_headers.insert(
            header::CONTENT_RANGE,
            header_value(&format!("bytes {start}-{}/{size}", start + len - 1))?,
        );
    }
    Ok(response)
}

/// Chunks of `reader` until EOF or the first read error.
fn read_stream<R>(reader: R) -> impl futures_util::Stream<Item = io::Result<Bytes>>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    futures_util::stream::unfold(Some(reader), |reader| async move {
        let mut reader = reader?;
        let mut buf = vec![0u8; READ_CHUNK_BYTES];
        match reader.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok(Bytes::from(buf)), Some(reader)))
            }
            Err(err) => Some((Err(err), None)),
        }
    })
}

/// A single byte range resolved against the blob size (inclusive `end`).
#[derive(Debug, PartialEq, Eq)]
enum Range {
    Bytes { start: u64, end: u64 },
    Unsatisfiable,
}

/// Parses a single `bytes=` range (RFC 9110 §14.1.2). Returns `None` when the
/// header must be ignored (malformed or multiple ranges).
fn parse_range(header: &str, size: u64) -> Option<Range> {
    let spec = header.trim().strip_prefix("bytes=")?;
    let (first, last) = spec.split_once('-')?;
    let number = |s: &str| -> Option<Option<u64>> {
        if s.is_empty() {
            Some(None)
        } else if s.bytes().all(|b| b.is_ascii_digit()) {
            s.parse().ok().map(Some)
        } else {
            None
        }
    };
    match (number(first)?, number(last)?) {
        (None, None) => None,
        (None, Some(suffix)) => {
            if suffix == 0 || size == 0 {
                Some(Range::Unsatisfiable)
            } else {
                Some(Range::Bytes {
                    start: size.saturating_sub(suffix),
                    end: size - 1,
                })
            }
        }
        (Some(start), last) => {
            if last.is_some_and(|last| last < start) {
                None
            } else if start >= size {
                Some(Range::Unsatisfiable)
            } else {
                let end = last.map_or(size - 1, |last| last.min(size - 1));
                Some(Range::Bytes { start, end })
            }
        }
    }
}

/// The cached copy of remote blob `blob_id` uploaded on `origin`, fetched
/// first if missing. Concurrent requests for one blob share a fetch; the
/// fetch runs in its own task, so a client disconnect does not abort it.
async fn remote_copy(
    state: &AppState,
    origin: HubId,
    blob_id: String,
) -> Result<PathBuf, ApiError> {
    let path = state
        .config
        .load()
        .blobs_dir()
        .join(s2s_blob::file_name(&blob_id));
    if cached(state, &blob_id).await? {
        return Ok(path);
    }
    if !state.federation.is_enabled() {
        return Err(ApiError::NotFound);
    }
    let task = {
        let (state, path) = (state.clone(), path.clone());
        tokio::spawn(async move {
            let lock = state
                .blob_fetches
                .lock()
                .expect("blob fetches lock")
                .entry(blob_id.clone())
                .or_default()
                .clone();
            let guard = lock.lock().await;
            let result = match cached(&state, &blob_id).await {
                Ok(true) => Ok(()),
                Ok(false) => fetch_remote(&state, &origin, &blob_id, &path).await,
                Err(err) => Err(err),
            };
            let mut fetches = state.blob_fetches.lock().expect("blob fetches lock");
            if fetches
                .get(&blob_id)
                .is_some_and(|current| Arc::ptr_eq(current, &lock))
            {
                fetches.remove(&blob_id);
            }
            drop(guard);
            result
        })
    };
    task.await.map_err(internal)??;
    Ok(path)
}

async fn cached(state: &AppState, blob_id: &str) -> Result<bool, ApiError> {
    let blob_id = blob_id.to_owned();
    Ok(state
        .db
        .read(move |conn| blobs::get_remote(conn, &blob_id))
        .await?
        .is_some())
}

/// Fetches remote blob `blob_id` from `origin` into a temp file, renames it
/// to `path` and records the cached copy, so a partial fetch never becomes
/// visible.
async fn fetch_remote(
    state: &AppState,
    origin: &HubId,
    blob_id: &str,
    path: &FsPath,
) -> Result<(), ApiError> {
    let dir = state.config.load().blobs_dir();
    tokio::fs::create_dir_all(&dir).await.map_err(internal)?;
    let mut raw = [0u8; 8];
    getrandom::fill(&mut raw).map_err(internal)?;
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        s2s_blob::file_name(blob_id),
        hex::encode(raw)
    ));
    let size = match download_to(state, origin, blob_id, &tmp).await {
        Ok(size) => size,
        Err(err) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(err);
        }
    };
    if let Err(err) = tokio::fs::rename(&tmp, path).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(internal(err));
    }
    let blob = RemoteBlob {
        blob_id: blob_id.to_owned(),
        size: i64::try_from(size).map_err(internal)?,
        fetched_at: state.clock.now_ms(),
    };
    state
        .db
        .write(move |tx| blobs::put_remote(tx, &blob))
        .await?;
    Ok(())
}

/// Reads remote blob `blob_id` chunk by chunk into a new file at `tmp`,
/// checking that the chunks are consistent and the size within
/// `GIM_HUB_MAX_BLOB_BYTES`. Returns the size.
async fn download_to(
    state: &AppState,
    origin: &HubId,
    blob_id: &str,
    tmp: &FsPath,
) -> Result<u64, ApiError> {
    let refused = |reason: &str| {
        tracing::info!(%origin, blob_id, reason, "origin hub sent an invalid blob");
        ApiError::PeerRefused(format!("origin hub: {reason}"))
    };
    let mut file = File::create(tmp).await.map_err(internal)?;
    let mut size = None;
    let mut offset: u64 = 0;
    loop {
        let chunk = s2s_blob::fetch_chunk(
            state.federation.as_ref(),
            origin,
            blob_id,
            offset,
            CHUNK_BYTES,
        )
        .await
        .map_err(|err| fetch_error(origin, blob_id, err))?;
        let total = *size.get_or_insert(chunk.size);
        if total > state.config.load().max_blob_bytes {
            return Err(refused("blob exceeds the size limit"));
        }
        if chunk.size != total || chunk.offset != offset {
            return Err(refused("inconsistent chunk"));
        }
        let len = chunk.data.len() as u64;
        if len > total - offset || (len == 0 && offset < total) {
            return Err(refused("chunk does not match the blob size"));
        }
        file.write_all(&chunk.data).await.map_err(internal)?;
        offset += len;
        if offset == total {
            break;
        }
    }
    file.sync_all().await.map_err(internal)?;
    Ok(offset)
}

/// Maps a failed `FetchBlob` to the client error (docs/federation.md §5.6).
fn fetch_error(origin: &HubId, blob_id: &str, err: FetchBlobError) -> ApiError {
    match err {
        FetchBlobError::NotFound | FetchBlobError::Disabled => ApiError::NotFound,
        FetchBlobError::Refused(reason) => ApiError::PeerRefused(reason),
        FetchBlobError::Unavailable(reason) => {
            tracing::info!(%origin, blob_id, reason, "origin hub unavailable");
            ApiError::PeerUnavailable {
                retry_after: PEER_UNAVAILABLE_RETRY_AFTER,
            }
        }
    }
}

/// Registers the `FetchBlob` op handler, serving this hub's uploads to
/// other hubs. Returns the service, which the caller keeps alive.
pub fn register_blob_op(state: &AppState, service: &FederationService) -> Arc<BlobService> {
    let blobs = BlobService::new(
        state.db.clone(),
        state.hub.hub_id().clone(),
        state.config.load().blobs_dir(),
    );
    blobs.register(service);
    blobs
}

/// A new blob ID `<hub_id>/b_<base64url of 16 random bytes>`.
fn new_blob_id(hub_id: &HubId) -> Result<String, ApiError> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(internal)?;
    Ok(format!("{hub_id}/b_{}", URL_SAFE_NO_PAD.encode(raw)))
}

fn header_value(value: &str) -> Result<HeaderValue, ApiError> {
    HeaderValue::from_str(value).map_err(internal)
}

fn internal(err: impl std::fmt::Display) -> ApiError {
    ApiError::Internal(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        let bytes = |start, end| Some(Range::Bytes { start, end });
        assert_eq!(parse_range("bytes=0-3", 10), bytes(0, 3));
        assert_eq!(parse_range("bytes=4-", 10), bytes(4, 9));
        assert_eq!(parse_range("bytes=5-100", 10), bytes(5, 9));
        assert_eq!(parse_range("bytes=-3", 10), bytes(7, 9));
        assert_eq!(parse_range("bytes=-30", 10), bytes(0, 9));
        assert_eq!(parse_range("bytes=10-", 10), Some(Range::Unsatisfiable));
        assert_eq!(parse_range("bytes=-0", 10), Some(Range::Unsatisfiable));
        assert_eq!(parse_range("bytes=0-0", 0), Some(Range::Unsatisfiable));
        assert_eq!(parse_range("bytes=5-4", 10), None);
        assert_eq!(parse_range("bytes=-", 10), None);
        assert_eq!(parse_range("bytes=0-1,3-4", 10), None);
        assert_eq!(parse_range("items=0-1", 10), None);
        assert_eq!(parse_range("bytes=+1-2", 10), None);
    }
}
