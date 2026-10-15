//! `/gim/s2s/1.0.0` codec: one protobuf message per direction, prefixed by
//! its length as an unsigned varint (prost length-delimited encoding).

use std::io;

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use gim_hub_proto::s2s::{S2sRequest, S2sResponse};
use libp2p::{request_response, StreamProtocol};
use prost::Message;

/// Largest request or response frame (docs/s2s.md "Limits").
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default)]
pub struct S2sCodec;

#[async_trait]
impl request_response::Codec for S2sCodec {
    type Protocol = StreamProtocol;
    type Request = S2sRequest;
    type Response = S2sResponse;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<S2sRequest>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io).await
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<S2sResponse>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io).await
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        req: S2sRequest,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &req).await
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        res: S2sResponse,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &res).await
    }
}

async fn read_frame<M, T>(io: &mut T) -> io::Result<M>
where
    M: Message + Default,
    T: AsyncRead + Unpin + Send,
{
    let len = read_varint(io).await?;
    if len > MAX_FRAME_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds {MAX_FRAME_BYTES}"),
        ));
    }
    let mut buf = vec![0u8; len as usize];
    io.read_exact(&mut buf).await?;
    M::decode(buf.as_slice()).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

async fn write_frame<M, T>(io: &mut T, msg: &M) -> io::Result<()>
where
    M: Message,
    T: AsyncWrite + Unpin + Send,
{
    let len = msg.encoded_len();
    if len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("frame of {len} bytes exceeds {MAX_FRAME_BYTES}"),
        ));
    }
    io.write_all(&msg.encode_length_delimited_to_vec()).await?;
    io.close().await
}

/// Reads an unsigned LEB128 varint of at most 10 bytes.
async fn read_varint<T: AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<u64> {
    let mut value = 0u64;
    for i in 0..10 {
        let mut byte = [0u8; 1];
        io.read_exact(&mut byte).await?;
        value |= u64::from(byte[0] & 0x7f) << (7 * i);
        if byte[0] & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "length prefix too long",
    ))
}

#[cfg(test)]
mod tests {
    use futures::io::Cursor;
    use gim_hub_proto::s2s::{s2s_request::Op, GetDeviceListRequest};
    use request_response::Codec;

    use super::*;

    fn protocol() -> StreamProtocol {
        StreamProtocol::new(gim_hub_proto::S2S_PROTOCOL)
    }

    #[tokio::test]
    async fn request_roundtrips_length_delimited() {
        let req = S2sRequest {
            request_id: "r-1".into(),
            op: Some(Op::GetDeviceList(GetDeviceListRequest {
                user_id: "u".repeat(300),
            })),
        };
        let mut buf = Cursor::new(Vec::new());
        S2sCodec
            .write_request(&protocol(), &mut buf, req.clone())
            .await
            .unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes, req.encode_length_delimited_to_vec());
        let read = S2sCodec
            .read_request(&protocol(), &mut Cursor::new(bytes))
            .await
            .unwrap();
        assert_eq!(read, req);
    }

    #[tokio::test]
    async fn rejects_oversized_and_malformed_frames() {
        // Length prefix of MAX_FRAME_BYTES + 1.
        let mut prefix = Vec::new();
        prost::encoding::encode_varint(MAX_FRAME_BYTES as u64 + 1, &mut prefix);
        let err = S2sCodec
            .read_response(&protocol(), &mut Cursor::new(prefix))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let too_long = vec![0xff; 11];
        let err = S2sCodec
            .read_request(&protocol(), &mut Cursor::new(too_long))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // Truncated body.
        let err = S2sCodec
            .read_request(&protocol(), &mut Cursor::new(vec![5, 1, 2]))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        let huge = S2sResponse {
            request_id: "x".repeat(MAX_FRAME_BYTES),
            ..Default::default()
        };
        let err = S2sCodec
            .write_response(&protocol(), &mut Cursor::new(Vec::new()), huge)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
