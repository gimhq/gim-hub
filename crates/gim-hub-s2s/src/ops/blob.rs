//! `FetchBlob` (docs/federation.md §5.6, docs/s2s.md): a hub reads a blob
//! uploaded on another hub, chunk by chunk, to serve it to its own clients.
//!
//! Blob ids carry their origin: `<origin hub_id>/b_<random>`. Ids without a
//! `/` are legacy single-hub ids and always mean "this hub"; they are never
//! fetched or served over S2S.

use std::{io::SeekFrom, path::PathBuf, sync::Arc};

use gim_hub_db::{blobs, Db, DbError};
use gim_hub_identity::HubId;
use gim_hub_proto::s2s::{
    s2s_request::Op, s2s_response::Result as OpOutput, Error as S2sError, ErrorCode,
    FetchBlobRequest, FetchBlobResponse, S2sRequest,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::{
    federation::{error, BoxFuture, Federation, FederationService, OpResult},
    policy::OpKind,
    transport::SendError,
};

/// Largest chunk of one `FetchBlob` response, well below the 8 MiB frame
/// limit.
pub const CHUNK_BYTES: u32 = 4 * 1024 * 1024;

/// Length of the base64url (no padding) encoding of the 16 random bytes.
const RANDOM_LEN: usize = 22;

/// Where a syntactically valid blob id lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobOrigin {
    /// A legacy id (`b_<random>`), uploaded on this hub.
    Legacy,
    /// `<hub_id>/b_<random>`, uploaded on `hub_id`.
    Hub(HubId),
}

/// Parses a blob id; `None` when it is neither a legacy nor an
/// origin-qualified id.
pub fn parse_blob_id(blob_id: &str) -> Option<BlobOrigin> {
    let (origin, random) = match blob_id.split_once('/') {
        None => (None, blob_id),
        Some((origin, random)) => (Some(HubId::parse(origin).ok()?), random),
    };
    let encoded = random.strip_prefix("b_")?;
    if encoded.len() != RANDOM_LEN
        || !encoded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    Some(origin.map_or(BlobOrigin::Legacy, BlobOrigin::Hub))
}

/// File name of a blob under `$DATA_DIR/blobs/`. Legacy ids keep their name;
/// the `/` of an origin-qualified id becomes `_` (hub ids are lowercase
/// base32, so names stay distinct). Only for ids [`parse_blob_id`] accepts.
pub fn file_name(blob_id: &str) -> String {
    blob_id.replace('/', "_")
}

/// Why a `FetchBlob` to the origin failed.
#[derive(Debug, Clone, PartialEq)]
pub enum FetchBlobError {
    /// The origin answered `NOT_FOUND`.
    NotFound,
    /// Local policy forbids the origin, or the origin refused the request
    /// (`UNAUTHORIZED`, `INVALID`, ...).
    Refused(String),
    /// The origin could not be reached, did not answer in time, or answered
    /// `INTERNAL`, `RATE_LIMITED` or `HELLO_REQUIRED`.
    Unavailable(String),
    /// Federation is disabled.
    Disabled,
}

impl From<SendError> for FetchBlobError {
    fn from(err: SendError) -> Self {
        match err {
            SendError::Disabled => Self::Disabled,
            SendError::PeerRefused(reason) => Self::Refused(reason),
            other => Self::Unavailable(other.to_string()),
        }
    }
}

/// Sends `FetchBlob{blob_id, offset, max_len}` to the origin hub `origin`.
pub async fn fetch_chunk(
    federation: &dyn Federation,
    origin: &HubId,
    blob_id: &str,
    offset: u64,
    max_len: u32,
) -> Result<FetchBlobResponse, FetchBlobError> {
    let request = S2sRequest {
        request_id: super::request_id(),
        op: Some(Op::FetchBlob(FetchBlobRequest {
            blob_id: blob_id.to_owned(),
            offset,
            max_len,
        })),
    };
    let response = federation.send(origin, request).await?;
    match (response.result, response.error) {
        (_, Some(err)) => {
            let reason = format!("{:?}: {}", err.code(), err.message);
            Err(match err.code() {
                ErrorCode::NotFound => FetchBlobError::NotFound,
                ErrorCode::Internal | ErrorCode::RateLimited | ErrorCode::HelloRequired => {
                    FetchBlobError::Unavailable(reason)
                }
                _ => FetchBlobError::Refused(reason),
            })
        }
        (Some(OpOutput::FetchBlob(response)), None) => Ok(response),
        _ => Err(FetchBlobError::Unavailable("unexpected response".into())),
    }
}

/// The `FetchBlob` op handler on the origin hub.
pub struct BlobService {
    db: Db,
    hub_id: HubId,
    blobs_dir: PathBuf,
}

impl BlobService {
    pub fn new(db: Db, hub_id: HubId, blobs_dir: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            db,
            hub_id,
            blobs_dir,
        })
    }

    /// Registers the `FetchBlob` op handler on `service`. The handler holds a
    /// weak reference: the caller keeps the returned service alive.
    pub fn register(self: &Arc<Self>, service: &FederationService) {
        let weak = Arc::downgrade(self);
        service.register(
            OpKind::FetchBlob,
            Arc::new(
                move |caller: HubId, op: Op| -> BoxFuture<'static, OpResult> {
                    let weak = weak.clone();
                    Box::pin(async move {
                        let Some(service) = weak.upgrade() else {
                            return Err(error(ErrorCode::Internal, "shutting down"));
                        };
                        service.handle(caller, op).await
                    })
                },
            ),
        );
    }

    /// Serves a chunk to `caller` (docs/federation.md §5.6): the id names
    /// this hub as origin, the blob was uploaded here (cached copies of
    /// other hubs' blobs are never served), and the caller is a reader hub
    /// of the uploader ([`blobs::reader_hubs`]).
    pub async fn handle(&self, caller: HubId, op: Op) -> OpResult {
        let Op::FetchBlob(request) = op else {
            return Err(error(ErrorCode::Invalid, "unexpected op"));
        };
        match parse_blob_id(&request.blob_id) {
            Some(BlobOrigin::Hub(origin)) if origin == self.hub_id => {}
            Some(BlobOrigin::Hub(_)) => {
                return Err(error(
                    ErrorCode::Unauthorized,
                    "this hub is not the blob's origin",
                ))
            }
            Some(BlobOrigin::Legacy) | None => {
                return Err(error(ErrorCode::Invalid, "not an origin-qualified blob id"))
            }
        }
        let blob_id = request.blob_id.clone();
        let own = self.hub_id.as_str().to_owned();
        let caller_id = caller.as_str().to_owned();
        let found = self
            .db
            .read(move |conn| {
                let Some(blob) = blobs::get(conn, &blob_id)? else {
                    return Ok::<_, DbError>(None);
                };
                let readers = blobs::reader_hubs(conn, &blob.uploader_user_id, &own)?;
                Ok(Some(readers.contains(&caller_id)))
            })
            .await
            .map_err(|err| internal(&err))?;
        match found {
            None => return Err(error(ErrorCode::NotFound, "unknown blob")),
            Some(false) => {
                return Err(error(
                    ErrorCode::Unauthorized,
                    "caller hosts no user sharing a group with the uploader",
                ))
            }
            Some(true) => {}
        }

        let path = self.blobs_dir.join(file_name(&request.blob_id));
        let mut file = match tokio::fs::File::open(&path).await {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(error(ErrorCode::NotFound, "unknown blob"))
            }
            Err(err) => return Err(io_internal(&err)),
        };
        let size = file
            .metadata()
            .await
            .map_err(|err| io_internal(&err))?
            .len();
        if request.offset > size {
            return Err(error(
                ErrorCode::Invalid,
                "offset beyond the end of the blob",
            ));
        }
        let max_len = match request.max_len {
            0 => CHUNK_BYTES,
            len => len.min(CHUNK_BYTES),
        };
        let len = (size - request.offset).min(u64::from(max_len));
        file.seek(SeekFrom::Start(request.offset))
            .await
            .map_err(|err| io_internal(&err))?;
        let mut data = Vec::with_capacity(usize::try_from(len).unwrap_or_default());
        file.take(len)
            .read_to_end(&mut data)
            .await
            .map_err(|err| io_internal(&err))?;
        Ok(OpOutput::FetchBlob(FetchBlobResponse {
            size,
            offset: request.offset,
            data,
        }))
    }
}

fn internal(err: &DbError) -> S2sError {
    tracing::error!(%err, "FetchBlob failed");
    error(ErrorCode::Internal, "internal error")
}

fn io_internal(err: &std::io::Error) -> S2sError {
    tracing::error!(%err, "FetchBlob failed");
    error(ErrorCode::Internal, "internal error")
}

#[cfg(test)]
mod tests {
    use gim_hub_identity::SigningKey;

    use super::*;

    fn hub(seed: u8) -> HubId {
        HubId::from_root_pubkey(&SigningKey::from_bytes(&[seed; 32]).verifying_key())
    }

    #[test]
    fn blob_ids() {
        let random = "b_Hk4dN7sL2pX9cV0mB5qT1g";
        assert_eq!(parse_blob_id(random), Some(BlobOrigin::Legacy));
        let qualified = format!("{}/{random}", hub(1));
        assert_eq!(parse_blob_id(&qualified), Some(BlobOrigin::Hub(hub(1))));
        assert_eq!(file_name(&qualified), format!("{}_{random}", hub(1)));
        assert_eq!(file_name(random), random);
        for bad in [
            "",
            "b_",
            "b_short",
            "x_Hk4dN7sL2pX9cV0mB5qT1g",
            "b_Hk4dN7sL2pX9cV0mB5qT1g/",
            "b_Hk4dN7sL2pX9cV0mB5q.1g",
            "hnotahub/b_Hk4dN7sL2pX9cV0mB5qT1g",
            "../b_Hk4dN7sL2pX9cV0mB5qT1g",
            &format!("{}/{}/{random}", hub(1), hub(2)),
        ] {
            assert_eq!(parse_blob_id(bad), None, "{bad:?}");
        }
    }

    #[tokio::test]
    async fn serves_only_own_uploads_to_reader_hubs() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let service = BlobService::new(db.clone(), hub(1), dir.path().to_owned());
        let blob_id = format!("{}/b_Hk4dN7sL2pX9cV0mB5qT1g", hub(1));
        std::fs::write(dir.path().join(file_name(&blob_id)), b"0123456789").unwrap();
        let row = blobs::Blob {
            blob_id: blob_id.clone(),
            size: 10,
            uploader_user_id: "alice".into(),
            uploader_device_id: "d".into(),
            created_at: 0,
        };
        let reader = hub(2).as_str().to_owned();
        db.write(move |tx| {
            blobs::insert(tx, &row)?;
            gim_hub_db::hosting::put(
                tx,
                &gim_hub_db::hosting::StoredHostingRecord {
                    user_id: "alice".into(),
                    record: vec![0],
                    seq: 1,
                    expires_at: 1,
                    hosted: true,
                    hub_ids: vec![reader],
                    fetched_at: 0,
                    published_at: None,
                    updated_at: 0,
                },
            )
        })
        .await
        .unwrap();
        let fetch = |caller: HubId, blob_id: String, offset: u64, max_len: u32| {
            service.handle(
                caller,
                Op::FetchBlob(FetchBlobRequest {
                    blob_id,
                    offset,
                    max_len,
                }),
            )
        };
        let code = |result: OpResult| result.unwrap_err().code();

        let Ok(OpOutput::FetchBlob(chunk)) = fetch(hub(2), blob_id.clone(), 3, 4).await else {
            panic!("expected a chunk");
        };
        assert_eq!((chunk.size, chunk.offset), (10, 3));
        assert_eq!(chunk.data, b"3456");
        let Ok(OpOutput::FetchBlob(end)) = fetch(hub(2), blob_id.clone(), 10, 0).await else {
            panic!("expected the end");
        };
        assert!(end.data.is_empty());
        assert_eq!(
            code(fetch(hub(2), blob_id.clone(), 11, 0).await),
            ErrorCode::Invalid
        );
        // An unrelated hub, an unknown id, another origin's id, a legacy id.
        assert_eq!(
            code(fetch(hub(3), blob_id.clone(), 0, 0).await),
            ErrorCode::Unauthorized
        );
        assert_eq!(
            code(fetch(hub(2), format!("{}/b_AAAAAAAAAAAAAAAAAAAAAA", hub(1)), 0, 0).await),
            ErrorCode::NotFound
        );
        assert_eq!(
            code(fetch(hub(2), format!("{}/b_Hk4dN7sL2pX9cV0mB5qT1g", hub(3)), 0, 0).await),
            ErrorCode::Unauthorized
        );
        assert_eq!(
            code(fetch(hub(2), "b_Hk4dN7sL2pX9cV0mB5qT1g".into(), 0, 0).await),
            ErrorCode::Invalid
        );
    }
}
