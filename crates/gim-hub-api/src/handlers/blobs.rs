//! Encrypted attachments.

use std::{io, path::Path as FsPath};

use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures_util::StreamExt;
use gim_hub_db::blobs::{self, Blob};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
};

use crate::{
    auth::AuthDevice,
    dto::{BlobCreated, Error, RawBytes},
    error::ApiError,
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
bytes) fail with 413.",
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
    let max = state.config.max_blob_bytes;
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok()?.parse::<u64>().ok());
    if declared.is_some_and(|len| len > max) {
        return Err(ApiError::PayloadTooLarge);
    }

    let dir = state.config.blobs_dir();
    tokio::fs::create_dir_all(&dir).await.map_err(internal)?;
    let blob_id = new_blob_id()?;
    let path = dir.join(&blob_id);
    // Write to a temp file and rename, so a blob file is always complete.
    let tmp = dir.join(format!(".{blob_id}.tmp"));
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
    description = "Supports a single byte range (`Range: bytes=a-b`, `bytes=a-`, or `bytes=-n`).",
    params(
        ("blob_id" = String, Path, description = "Opaque blob ID", example = "b_Hk4dN7sL2pX9cV0mB5qT1g"),
        ("Range" = Option<String>, Header, description = "Single byte range", example = "bytes=0-1023"),
    ),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Whole blob", body = inline(RawBytes), content_type = "application/octet-stream"),
        (status = 206, description = "Requested range", body = inline(RawBytes), content_type = "application/octet-stream"),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
        (status = 416, description = "Range not satisfiable (`range_not_satisfiable`)", body = Error),
    ),
)]
pub async fn download_blob(
    State(state): State<AppState>,
    _auth: AuthDevice,
    Path(blob_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    // Only IDs recorded in the database are mapped to file names.
    let lookup_id = blob_id.clone();
    state
        .db
        .read(move |conn| blobs::get(conn, &lookup_id))
        .await?
        .ok_or(ApiError::NotFound)?;
    let mut file = match File::open(state.config.blobs_dir().join(&blob_id)).await {
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

fn new_blob_id() -> Result<String, ApiError> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(internal)?;
    Ok(format!("b_{}", URL_SAFE_NO_PAD.encode(raw)))
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
