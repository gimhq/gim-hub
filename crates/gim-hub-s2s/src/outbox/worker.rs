//! The outbox worker (docs/federation.md §7.2-§7.6).
//!
//! A supervisor finds peers that are due (queued entries or a pending
//! resync, `next_attempt_at` reached) and runs one drain task per peer, so
//! each peer has at most one request in flight and is served in `id` order.

use std::{collections::HashMap, time::Duration};

use gim_hub_db::outbox::{self, Entry, Kind};
use gim_hub_identity::HubId;
use gim_hub_proto::s2s::{
    s2s_request::Op, s2s_response::Result as OpOutput, DeliverRequest, DeliverWelcomeRequest,
    ErrorCode, NotifyDeviceListRequest, NotifyHostingRecordRequest, S2sRequest, S2sResponse,
    SeedReplicaRequest, SequencedMessage,
};
use prost::Message;
use tokio::task::JoinSet;

use super::{DropReason, Outbox};
use crate::transport::SendError;

/// Most messages in one `Deliver`.
const MAX_BATCH: u32 = 256;
/// Most encoded bytes of the messages in one `Deliver`.
const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;
/// First retry delay; doubles per consecutive failure.
const BACKOFF_BASE: Duration = Duration::from_secs(1);

pub(super) async fn supervise(outbox: Outbox) {
    let inner = &outbox.inner;
    let sweep_every = i64::try_from(outbox.config().sweep_interval.as_millis()).unwrap_or(i64::MAX);
    let mut next_sweep = i64::MIN;
    let mut drains = JoinSet::new();
    loop {
        while drains.try_join_next().is_some() {}
        let now = outbox.now();
        if now >= next_sweep {
            sweep(&outbox, now).await;
            next_sweep = now.saturating_add(sweep_every);
        }
        let mut wake_at = next_sweep;
        match inner.db.read(outbox::pending_peers).await {
            Ok(peers) => {
                for (peer, next_attempt_at) in peers {
                    if next_attempt_at > now {
                        wake_at = wake_at.min(next_attempt_at);
                    } else if inner
                        .active
                        .lock()
                        .expect("active lock")
                        .insert(peer.clone())
                    {
                        drains.spawn(drain(outbox.clone(), peer));
                    }
                }
            }
            Err(err) => tracing::error!(%err, "outbox: listing pending peers failed"),
        }
        let delay = Duration::from_millis(u64::try_from(wake_at.saturating_sub(now)).unwrap_or(0));
        tokio::select! {
            () = inner.wake.notified() => {}
            () = tokio::time::sleep(delay) => {}
        }
    }
}

/// Deletes expired entries (§7.5).
async fn sweep(outbox: &Outbox, now: i64) {
    match outbox
        .inner
        .db
        .write(move |tx| outbox::expire(tx, now))
        .await
    {
        Ok(expired) => {
            for item in expired {
                outbox.count_dropped(&item.peer_hub_id, DropReason::Expired, item.count as u64);
            }
        }
        Err(err) => tracing::error!(%err, "outbox: expiring entries failed"),
    }
}

/// Removes the peer from the active set when its drain ends.
struct Active {
    outbox: Outbox,
    peer: String,
}

impl Drop for Active {
    fn drop(&mut self) {
        self.outbox
            .inner
            .active
            .lock()
            .expect("active lock")
            .remove(&self.peer);
        self.outbox.wake();
    }
}

/// Sends the peer's queue head until it is empty or a failure defers it.
async fn drain(outbox: Outbox, peer: String) {
    let active = Active {
        outbox: outbox.clone(),
        peer: peer.clone(),
    };
    let hub_id = match HubId::parse(&peer) {
        Ok(hub_id) => hub_id,
        Err(err) => {
            defer(&outbox, &peer, &err.to_string()).await;
            return;
        }
    };
    if let Err(err) = drain_peer(&outbox, &hub_id).await {
        tracing::error!(%err, peer, "outbox: drain failed");
        defer(&outbox, &peer, &err.to_string()).await;
    }
    drop(active);
}

async fn drain_peer(outbox: &Outbox, hub_id: &HubId) -> Result<(), gim_hub_db::DbError> {
    let inner = &outbox.inner;
    let peer = hub_id.as_str().to_owned();
    // UNAUTHORIZED is permanent only after one hosting refresh (§7.4).
    let mut refreshed = false;
    // After a permanent error on a batch, entries are sent one by one so
    // only the offending one is dropped.
    let mut single = false;
    loop {
        let now = outbox.now();
        let state = {
            let peer = peer.clone();
            inner.db.read(move |conn| outbox::peer(conn, &peer)).await?
        };
        if state.next_attempt_at > now {
            return Ok(());
        }
        let limit = if single { 1 } else { MAX_BATCH };
        let head = {
            let peer = peer.clone();
            inner
                .db
                .read(move |conn| outbox::head(conn, &peer, now, limit))
                .await?
        };
        if head.is_empty() {
            sweep(outbox, now).await;
            let needs_resync = {
                let peer = peer.clone();
                inner.db.read(move |conn| outbox::peer(conn, &peer)).await?
            }
            .needs_resync;
            if needs_resync {
                resync(outbox, hub_id).await?;
            }
            return Ok(());
        }

        let mut batch = build(outbox, hub_id, head).await?;
        if !batch.unbuildable.is_empty() {
            let ids = batch.unbuildable.clone();
            let deleted = inner.db.write(move |tx| outbox::delete(tx, &ids)).await?;
            outbox.count_dropped(&peer, DropReason::Unbuildable, deleted as u64);
        }
        let Some(op) = batch.op.take() else { continue };
        let ids: Vec<i64> = batch.entries.iter().map(|entry| entry.id).collect();
        {
            let ids = ids.clone();
            inner
                .db
                .write(move |tx| outbox::count_attempt(tx, &ids))
                .await?;
        }
        let request = S2sRequest {
            request_id: format!("outbox-{}", ids[0]),
            op: Some(op),
        };
        let response = inner.federation.send(hub_id, request).await;
        match classify(response) {
            Outcome::Ok(output) => {
                let Some(acked) = acked(&batch, &output) else {
                    defer(outbox, &peer, "unexpected response variant").await;
                    return Ok(());
                };
                let all = acked.len() == ids.len();
                inner
                    .db
                    .write(move |tx| outbox::delete(tx, &acked).map(drop))
                    .await?;
                if !all {
                    // The receiver stopped at a gap and is fetching the log;
                    // the rest is resent with the normal backoff (§7.3).
                    defer(outbox, &peer, "entries not acknowledged").await;
                    return Ok(());
                }
                let peer = peer.clone();
                inner
                    .db
                    .write(move |tx| outbox::record_success(tx, &peer, now))
                    .await?;
                single = false;
            }
            Outcome::Retry(reason) => {
                defer(outbox, &peer, &reason).await;
                return Ok(());
            }
            Outcome::Unauthorized(_) if !refreshed => {
                refreshed = true;
                inner.source.refresh_peer(hub_id).await;
            }
            Outcome::Unauthorized(reason) | Outcome::Permanent(reason) => {
                if ids.len() > 1 {
                    single = true;
                    continue;
                }
                tracing::warn!(
                    peer,
                    kind = batch.kind.as_str(),
                    id = ids[0],
                    %reason,
                    "outbox entry rejected by peer"
                );
                let deleted = inner.db.write(move |tx| outbox::delete(tx, &ids)).await?;
                outbox.count_dropped(&peer, DropReason::Rejected, deleted as u64);
            }
        }
    }
}

/// Sends the resync nudge (§7.6) and clears `needs_resync`.
async fn resync(outbox: &Outbox, hub_id: &HubId) -> Result<(), gim_hub_db::DbError> {
    let inner = &outbox.inner;
    let peer = hub_id.as_str().to_owned();
    let messages = {
        let source = inner.source.clone();
        let hub_id = hub_id.clone();
        inner
            .db
            .read(move |conn| source.resync_nudge(conn, &hub_id))
            .await?
    };
    let count = messages.len();
    for (index, messages) in split(messages).into_iter().enumerate() {
        let request = S2sRequest {
            request_id: format!("outbox-resync-{index}"),
            op: Some(Op::Deliver(DeliverRequest { messages })),
        };
        match classify(inner.federation.send(hub_id, request).await) {
            Outcome::Ok(output) if matches!(*output, OpOutput::Deliver(_)) => {}
            Outcome::Ok(_) => {
                defer(outbox, &peer, "unexpected response variant").await;
                return Ok(());
            }
            Outcome::Retry(reason) => {
                defer(outbox, &peer, &reason).await;
                return Ok(());
            }
            Outcome::Unauthorized(reason) | Outcome::Permanent(reason) => {
                tracing::warn!(peer, %reason, "outbox resync nudge rejected by peer");
            }
        }
    }
    let now = outbox.now();
    inner
        .db
        .write(move |tx| {
            outbox::set_needs_resync(tx, &peer, false, now)?;
            outbox::record_success(tx, &peer, now)
        })
        .await?;
    tracing::info!(
        peer = hub_id.as_str(),
        gids = count,
        "outbox resync nudge sent"
    );
    Ok(())
}

/// Counts a failure of `peer` and defers its next attempt (§7.4).
async fn defer(outbox: &Outbox, peer: &str, reason: &str) {
    let max = outbox.config().backoff_max;
    let jitter = random_jitter();
    let now = outbox.now();
    let result = {
        let peer = peer.to_owned();
        outbox
            .inner
            .db
            .write(move |tx| {
                let failures = outbox::peer(tx, &peer)?.failures;
                let delay = backoff(failures, max, jitter);
                let next = now.saturating_add(delay.as_millis() as i64);
                let failures = outbox::record_failure(tx, &peer, next, now)?;
                Ok::<_, gim_hub_db::DbError>((failures, delay, outbox::backlog(tx, &peer)?))
            })
            .await
    };
    match result {
        Ok((failures, delay, backlog)) => tracing::info!(
            peer,
            failures,
            retry_in_ms = delay.as_millis() as u64,
            s2s_outbox_entries = backlog.entries,
            s2s_outbox_bytes = backlog.bytes,
            reason,
            "outbox delivery deferred"
        ),
        Err(err) => tracing::error!(%err, peer, "outbox: recording failure failed"),
    }
}

/// `min(1 s · 2^failures, max)` scaled by `1 + 0.2 · jitter`, with `jitter`
/// in `[-1, 1]`; `failures` counts the consecutive failures before this one.
pub(super) fn backoff(failures: i64, max: Duration, jitter: f64) -> Duration {
    let exponent = u32::try_from(failures.clamp(0, 32)).unwrap_or(32);
    let base = BACKOFF_BASE.saturating_mul(1 << exponent.min(31)).min(max);
    base.mul_f64(1.0 + 0.2 * jitter.clamp(-1.0, 1.0))
}

fn random_jitter() -> f64 {
    let mut bytes = [0; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return 0.0;
    }
    (u64::from_le_bytes(bytes) as f64 / u64::MAX as f64) * 2.0 - 1.0
}

/// The request built from a peer's queue head.
struct Batch {
    kind: Kind,
    /// Entries carried by `op`.
    entries: Vec<Entry>,
    /// Entries that cannot be built; dropped.
    unbuildable: Vec<i64>,
    op: Option<Op>,
}

/// Builds the request for `peer`'s head: the leading run of `deliver`
/// entries (≤ 256 messages, ≤ 4 MiB) or the single first entry of another
/// kind.
async fn build(
    outbox: &Outbox,
    peer: &HubId,
    mut head: Vec<Entry>,
) -> Result<Batch, gim_hub_db::DbError> {
    let kind = head[0].kind;
    let source = outbox.inner.source.clone();
    match kind {
        Kind::Deliver => {
            let run = head
                .iter()
                .position(|entry| entry.kind != Kind::Deliver)
                .unwrap_or(head.len());
            head.truncate(run);
            let keys: Vec<(String, u64)> = head
                .iter()
                .map(|entry| {
                    (
                        entry.gid.clone().unwrap_or_default(),
                        entry.seq.unwrap_or_default() as u64,
                    )
                })
                .collect();
            let messages = outbox
                .inner
                .db
                .read(move |conn| source.deliver_messages(conn, &keys))
                .await?;
            let mut batch = Batch {
                kind,
                entries: Vec::new(),
                unbuildable: Vec::new(),
                op: None,
            };
            let mut carried = Vec::new();
            let mut bytes = 0;
            for (entry, message) in head.into_iter().zip(messages) {
                let Some(message) = message else {
                    batch.unbuildable.push(entry.id);
                    continue;
                };
                let len = message.encoded_len();
                if !carried.is_empty() && bytes + len > MAX_BATCH_BYTES {
                    break;
                }
                bytes += len;
                carried.push(message);
                batch.entries.push(entry);
            }
            if !carried.is_empty() {
                batch.op = Some(Op::Deliver(DeliverRequest { messages: carried }));
            }
            Ok(batch)
        }
        Kind::DeliverWelcome => {
            let entry = head.swap_remove(0);
            let request = entry
                .payload
                .as_deref()
                .and_then(|payload| DeliverWelcomeRequest::decode(payload).ok());
            Ok(single(kind, entry, request.map(Op::DeliverWelcome)))
        }
        Kind::DeviceList => {
            let entry = head.swap_remove(0);
            let user_id = entry.user_id.clone().unwrap_or_default();
            let list = {
                let user_id = user_id.clone();
                outbox
                    .inner
                    .db
                    .read(move |conn| source.device_list(conn, &user_id))
                    .await?
            };
            let op = list.map(|device_list_cbor| {
                Op::NotifyDeviceList(NotifyDeviceListRequest {
                    user_id,
                    device_list_cbor,
                })
            });
            Ok(single(kind, entry, op))
        }
        Kind::HostingRecord => {
            let entry = head.swap_remove(0);
            let user_id = entry.user_id.clone().unwrap_or_default();
            let record = {
                let user_id = user_id.clone();
                outbox
                    .inner
                    .db
                    .read(move |conn| source.hosting_record(conn, &user_id))
                    .await?
            };
            let op = record.map(|hosting_record_cbor| {
                Op::NotifyHostingRecord(NotifyHostingRecordRequest {
                    user_id,
                    hosting_record_cbor,
                })
            });
            Ok(single(kind, entry, op))
        }
        Kind::SeedReplica => {
            let entry = head.swap_remove(0);
            let request = entry
                .payload
                .as_deref()
                .and_then(|payload| SeedReplicaRequest::decode(payload).ok());
            Ok(single(kind, entry, request.map(Op::SeedReplica)))
        }
        Kind::PendingWelcomes => {
            let entry = head.swap_remove(0);
            let user_id = entry.user_id.clone().unwrap_or_default();
            let peer = peer.clone();
            let request = outbox
                .inner
                .db
                .read(move |conn| source.pending_welcomes(conn, &user_id, &peer))
                .await?;
            Ok(single(kind, entry, request.map(Op::CopyPendingWelcomes)))
        }
    }
}

fn single(kind: Kind, entry: Entry, op: Option<Op>) -> Batch {
    match op {
        Some(op) => Batch {
            kind,
            entries: vec![entry],
            unbuildable: Vec::new(),
            op: Some(op),
        },
        None => Batch {
            kind,
            entries: Vec::new(),
            unbuildable: vec![entry.id],
            op: None,
        },
    }
}

/// Splits messages into `Deliver` batches (≤ 256 messages, ≤ 4 MiB).
fn split(messages: Vec<SequencedMessage>) -> Vec<Vec<SequencedMessage>> {
    let mut batches: Vec<Vec<SequencedMessage>> = Vec::new();
    let mut bytes = 0;
    for message in messages {
        let len = message.encoded_len();
        match batches.last_mut() {
            Some(batch) if batch.len() < MAX_BATCH as usize && bytes + len <= MAX_BATCH_BYTES => {
                bytes += len;
                batch.push(message);
            }
            _ => {
                bytes = len;
                batches.push(vec![message]);
            }
        }
    }
    batches
}

/// Ids of the batch entries removed by a successful response (§7.3);
/// `None` when the response variant does not match the request.
fn acked(batch: &Batch, output: &OpOutput) -> Option<Vec<i64>> {
    let all = || batch.entries.iter().map(|entry| entry.id).collect();
    match (batch.kind, output) {
        (Kind::Deliver, OpOutput::Deliver(response)) => {
            let acks: HashMap<&str, u64> = response
                .acks
                .iter()
                .map(|ack| (ack.gid.as_str(), ack.highest_contiguous_seq))
                .collect();
            Some(
                batch
                    .entries
                    .iter()
                    .filter(|entry| {
                        let gid = entry.gid.as_deref().unwrap_or_default();
                        acks.get(gid)
                            .is_some_and(|&acked| acked >= entry.seq.unwrap_or_default() as u64)
                    })
                    .map(|entry| entry.id)
                    .collect(),
            )
        }
        (Kind::DeliverWelcome, OpOutput::DeliverWelcome(_))
        | (Kind::DeviceList, OpOutput::NotifyDeviceList(_))
        | (Kind::HostingRecord, OpOutput::NotifyHostingRecord(_))
        | (Kind::SeedReplica, OpOutput::SeedReplica(_))
        | (Kind::PendingWelcomes, OpOutput::CopyPendingWelcomes(_)) => Some(all()),
        _ => None,
    }
}

/// Failure class of a send (§7.4).
enum Outcome {
    Ok(Box<OpOutput>),
    /// Transport error, timeout, `INTERNAL`, `RATE_LIMITED`, `HELLO_REQUIRED`
    /// (the transport already re-sent `Hello` once), or a malformed response.
    Retry(String),
    Unauthorized(String),
    /// `INVALID`, `NOT_FOUND`, `UNAUTHORIZED` with `client_code`
    /// `user_not_admitted`.
    Permanent(String),
}

fn classify(response: Result<S2sResponse, SendError>) -> Outcome {
    match response {
        Err(err) => Outcome::Retry(err.to_string()),
        Ok(S2sResponse {
            error: Some(error), ..
        }) => {
            let reason = format!("{:?}: {}", error.code(), error.message);
            match error.code() {
                // The user policy refusal does not change with a hosting
                // refresh.
                _ if crate::ops::is_not_admitted(&error) => Outcome::Permanent(reason),
                ErrorCode::Invalid | ErrorCode::NotFound => Outcome::Permanent(reason),
                ErrorCode::Unauthorized => Outcome::Unauthorized(reason),
                _ => Outcome::Retry(reason),
            }
        }
        Ok(S2sResponse {
            result: Some(output),
            ..
        }) => Outcome::Ok(Box::new(output)),
        Ok(_) => Outcome::Retry("empty response".into()),
    }
}
