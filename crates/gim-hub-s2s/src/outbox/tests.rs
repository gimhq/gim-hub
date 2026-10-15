//! Outbox worker against an in-process fake peer (no network).

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use gim_hub_db::{outbox as store, Connection, Db, DbError};
use gim_hub_identity::{HubId, SigningKey};
use gim_hub_proto::s2s::{
    s2s_request::Op, s2s_response::Result as OpOutput, DeliverResponse, DeliverWelcomeRequest,
    DeliverWelcomeResponse, ErrorCode, GroupAck, NotifyDeviceListResponse, S2sRequest, S2sResponse,
    SequencedMessage,
};
use prost::Message;

use super::{worker::backoff, *};
use crate::{error, federation::BoxFuture, transport::SendError};

/// A member hub: applies `Deliver` like §6.6 (stops a gid at a gap) and
/// acks `highest_contiguous_seq`; refuses everything while down.
#[derive(Default)]
struct FakePeer {
    up: AtomicBool,
    last_seq: Mutex<HashMap<String, u64>>,
    requests: Mutex<Vec<Op>>,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    /// gids whose `Deliver` is answered `INVALID`.
    invalid_gids: Mutex<HashSet<String>>,
    /// Answer `DeliverWelcome` with `UNAUTHORIZED`.
    reject_welcomes: AtomicBool,
}

impl FakePeer {
    fn requests(&self) -> Vec<Op> {
        self.requests.lock().unwrap().clone()
    }

    fn answer(&self, op: Op) -> Result<OpOutput, gim_hub_proto::s2s::Error> {
        match op {
            Op::Deliver(request) => {
                if request
                    .messages
                    .iter()
                    .any(|m| self.invalid_gids.lock().unwrap().contains(&m.gid))
                {
                    return Err(error(ErrorCode::Invalid, "bad gid"));
                }
                let mut last_seq = self.last_seq.lock().unwrap();
                let mut gaps = HashSet::new();
                let mut gids = Vec::new();
                for message in request.messages {
                    if !gids.contains(&message.gid) {
                        gids.push(message.gid.clone());
                    }
                    let last = last_seq.entry(message.gid.clone()).or_default();
                    if gaps.contains(&message.gid) || message.seq <= *last {
                        continue;
                    }
                    if message.seq == *last + 1 {
                        *last = message.seq;
                    } else {
                        gaps.insert(message.gid);
                    }
                }
                Ok(OpOutput::Deliver(DeliverResponse {
                    acks: gids
                        .into_iter()
                        .map(|gid| GroupAck {
                            highest_contiguous_seq: last_seq[&gid],
                            gid,
                        })
                        .collect(),
                }))
            }
            Op::DeliverWelcome(_) if self.reject_welcomes.load(Ordering::SeqCst) => {
                Err(error(ErrorCode::Unauthorized, "not the owner"))
            }
            Op::DeliverWelcome(_) => Ok(OpOutput::DeliverWelcome(DeliverWelcomeResponse {})),
            Op::NotifyDeviceList(_) => Ok(OpOutput::NotifyDeviceList(NotifyDeviceListResponse {})),
            _ => Err(error(ErrorCode::Internal, "unexpected op")),
        }
    }
}

impl Federation for FakePeer {
    fn is_enabled(&self) -> bool {
        true
    }

    fn send(
        &self,
        _: &HubId,
        request: S2sRequest,
    ) -> BoxFuture<'_, Result<S2sResponse, SendError>> {
        Box::pin(async move {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(1)).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            if !self.up.load(Ordering::SeqCst) {
                return Err(SendError::Unreachable("down".into()));
            }
            let op = request.op.expect("op");
            self.requests.lock().unwrap().push(op.clone());
            let (result, error) = match self.answer(op) {
                Ok(output) => (Some(output), None),
                Err(err) => (None, Some(err)),
            };
            Ok(S2sResponse {
                request_id: request.request_id,
                result,
                error,
            })
        })
    }
}

/// Messages are `(gid, seq)` with a small payload; gid "gone" does not
/// exist. The nudge is the newest message of gid "g".
#[derive(Default)]
struct FakeSource {
    nudges: AtomicUsize,
    refreshes: AtomicUsize,
}

fn message(gid: &str, seq: u64) -> SequencedMessage {
    SequencedMessage {
        gid: gid.into(),
        seq,
        payload: vec![7; 16],
        message_id: format!("{gid}:{seq}"),
        ..SequencedMessage::default()
    }
}

impl OutboxSource for FakeSource {
    fn deliver_messages(
        &self,
        _: &Connection,
        keys: &[(String, u64)],
    ) -> Result<Vec<Option<SequencedMessage>>, DbError> {
        Ok(keys
            .iter()
            .map(|(gid, seq)| (gid != "gone").then(|| message(gid, *seq)))
            .collect())
    }

    fn device_list(&self, _: &Connection, user_id: &str) -> Result<Option<Vec<u8>>, DbError> {
        Ok(Some(format!("list:{user_id}").into_bytes()))
    }

    fn resync_nudge(&self, _: &Connection, _: &HubId) -> Result<Vec<SequencedMessage>, DbError> {
        self.nudges.fetch_add(1, Ordering::SeqCst);
        Ok(vec![message("g", 1000)])
    }

    fn refresh_peer(&self, _: &HubId) -> BoxFuture<'_, ()> {
        self.refreshes.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {})
    }
}

const T0: i64 = 1_700_000_000_000;

fn config() -> OutboxConfig {
    OutboxConfig {
        ttl: Duration::from_secs(3600),
        max_entries_per_peer: 100,
        max_bytes_per_peer: 1 << 20,
        backoff_max: Duration::from_secs(300),
        sweep_interval: Duration::from_secs(60),
    }
}

fn hub(seed: u8) -> HubId {
    HubId::from_root_pubkey(&SigningKey::from_bytes(&[seed; 32]).verifying_key())
}

struct Harness {
    db: Db,
    peer: Arc<FakePeer>,
    source: Arc<FakeSource>,
    clock: Arc<AtomicI64>,
    outbox: Outbox,
    hub: HubId,
}

impl Harness {
    fn new(db: Db, config: OutboxConfig, up: bool) -> Self {
        let peer = Arc::new(FakePeer::default());
        peer.up.store(up, Ordering::SeqCst);
        let source = Arc::new(FakeSource::default());
        let clock = Arc::new(AtomicI64::new(T0));
        let outbox = {
            let clock = clock.clone();
            Outbox::with_clock(
                db.clone(),
                peer.clone(),
                source.clone(),
                config,
                Arc::new(move || clock.load(Ordering::SeqCst)),
            )
        };
        Self {
            db,
            peer,
            source,
            clock,
            outbox,
            hub: hub(2),
        }
    }

    async fn enqueue(&self, entries: Vec<NewEntry<'static>>) {
        let outbox = self.outbox.clone();
        let hub = self.hub.clone();
        self.db
            .write(move |tx| {
                for entry in entries {
                    outbox.enqueue_in_tx(tx, &hub, entry)?;
                }
                Ok::<_, DbError>(())
            })
            .await
            .unwrap();
    }

    async fn queued(&self) -> Vec<(Option<String>, Option<i64>)> {
        let hub = self.hub.as_str().to_owned();
        self.db
            .read(move |conn| store::head(conn, &hub, 0, 1000))
            .await
            .unwrap()
            .into_iter()
            .map(|entry| (entry.gid, entry.seq))
            .collect()
    }

    async fn state(&self) -> store::Peer {
        let hub = self.hub.as_str().to_owned();
        self.db
            .read(move |conn| store::peer(conn, &hub))
            .await
            .unwrap()
    }

    fn advance_to(&self, at: i64) {
        self.clock.store(at, Ordering::SeqCst);
        self.outbox.wake();
    }

    fn delivered(&self) -> Vec<(String, u64)> {
        self.peer
            .requests()
            .into_iter()
            .filter_map(|op| match op {
                Op::Deliver(request) => Some(request.messages),
                _ => None,
            })
            .flatten()
            .map(|m| (m.gid, m.seq))
            .collect()
    }
}

fn deliver(gid: &'static str, seq: i64) -> NewEntry<'static> {
    NewEntry::Deliver { gid, seq, size: 16 }
}

async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    for _ in 0..500 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn backoff_doubles_up_to_the_maximum_with_jitter() {
    let max = Duration::from_secs(300);
    let secs = |failures| backoff(failures, max, 0.0).as_secs();
    assert_eq!(
        [0, 1, 2, 3, 8, 9, 40].map(secs),
        [1, 2, 4, 8, 256, 300, 300]
    );
    assert_eq!(backoff(0, max, 1.0), Duration::from_millis(1200));
    assert_eq!(backoff(0, max, -1.0), Duration::from_millis(800));
    assert_eq!(backoff(20, max, 1.0), Duration::from_secs(360));
}

#[tokio::test]
async fn delivers_fifo_batches_and_acks_remove_entries() {
    let h = Harness::new(Db::open_in_memory().unwrap(), config(), true);
    let welcome = DeliverWelcomeRequest {
        gid: "g2".into(),
        message_id: "w1".into(),
        ..DeliverWelcomeRequest::default()
    }
    .encode_to_vec()
    .leak();
    h.enqueue(vec![
        deliver("g1", 1),
        deliver("g1", 2),
        deliver("g2", 1),
        deliver("g1", 3),
        NewEntry::DeliverWelcome {
            gid: "g2",
            payload: welcome,
        },
        deliver("g2", 2),
        NewEntry::DeviceList { user_id: "u1" },
    ])
    .await;
    h.outbox.start(None);
    eventually("queue drained", || async { h.queued().await.is_empty() }).await;

    let requests = h.peer.requests();
    assert_eq!(requests.len(), 4, "{requests:?}");
    let Op::Deliver(first) = &requests[0] else {
        panic!("{requests:?}")
    };
    let keys: Vec<_> = first
        .messages
        .iter()
        .map(|m| (m.gid.as_str(), m.seq))
        .collect();
    assert_eq!(keys, [("g1", 1), ("g1", 2), ("g2", 1), ("g1", 3)]);
    assert!(matches!(&requests[1], Op::DeliverWelcome(w) if w.message_id == "w1"));
    assert!(matches!(&requests[2], Op::Deliver(d) if d.messages.len() == 1));
    assert!(matches!(
        &requests[3],
        Op::NotifyDeviceList(n) if n.device_list_cbor == b"list:u1"
    ));
    assert_eq!(h.peer.max_in_flight.load(Ordering::SeqCst), 1);
    assert_eq!(h.state().await.failures, 0);
    h.outbox.shutdown();
}

#[tokio::test]
async fn entries_above_the_ack_stay_until_the_gap_is_filled() {
    let h = Harness::new(Db::open_in_memory().unwrap(), config(), true);
    h.enqueue(vec![deliver("g", 2), deliver("g", 3)]).await;
    h.outbox.start(None);
    eventually("one failure", || async { h.state().await.failures == 1 }).await;
    assert_eq!(
        h.queued().await,
        [(Some("g".into()), Some(2)), (Some("g".into()), Some(3))]
    );

    // The member hub fetched seq 1..=2 from the log meanwhile.
    h.peer.last_seq.lock().unwrap().insert("g".into(), 2);
    let next = h.state().await.next_attempt_at;
    h.advance_to(next);
    eventually("queue drained", || async { h.queued().await.is_empty() }).await;
    assert_eq!(h.state().await.failures, 0);
    assert_eq!(
        h.delivered(),
        [
            ("g".into(), 2),
            ("g".into(), 3),
            ("g".into(), 2),
            ("g".into(), 3)
        ]
    );
    h.outbox.shutdown();
}

#[tokio::test]
async fn outage_backs_off_exponentially_then_drains_on_recovery() {
    let h = Harness::new(Db::open_in_memory().unwrap(), config(), false);
    h.enqueue(vec![deliver("g", 1)]).await;
    h.outbox.start(None);
    let mut now = T0;
    for failures in 1..=4 {
        eventually("next failure", || async {
            h.state().await.failures == failures
        })
        .await;
        let delay = h.state().await.next_attempt_at - now;
        let expected = 1000 << (failures - 1);
        assert!(
            (expected * 8 / 10..=expected * 12 / 10).contains(&delay),
            "failure {failures}: delay {delay}"
        );
        if failures < 4 {
            now += delay;
            h.advance_to(now);
        }
    }
    h.enqueue(vec![deliver("g", 2)]).await;
    assert_eq!(h.queued().await.len(), 2);

    // Not due for 8 s: the peer coming up resets the backoff.
    h.peer.up.store(true, Ordering::SeqCst);
    h.outbox.peer_up(&h.hub).await.unwrap();
    eventually("queue drained", || async { h.queued().await.is_empty() }).await;
    assert_eq!(h.delivered(), [("g".into(), 1), ("g".into(), 2)]);
    let state = h.state().await;
    assert_eq!((state.failures, state.next_attempt_at), (0, 0));
    assert_eq!(state.last_connected_at, Some(now));
    assert_eq!(h.source.nudges.load(Ordering::SeqCst), 0);
    h.outbox.shutdown();
}

#[tokio::test]
async fn expired_entries_are_dropped_and_trigger_a_resync_nudge() {
    let h = Harness::new(Db::open_in_memory().unwrap(), config(), false);
    h.enqueue(vec![deliver("g", 1), NewEntry::DeviceList { user_id: "u" }])
        .await;
    h.outbox.start(None);
    eventually("first failure", || async { h.state().await.failures == 1 }).await;

    h.advance_to(T0 + 3_600_000);
    eventually("entries expired", || async { h.queued().await.is_empty() }).await;
    assert_eq!(h.outbox.dropped_total(&h.hub, DropReason::Expired), 2);
    assert!(h.state().await.needs_resync);
    // The nudge is attempted, and fails, while the peer is still down.
    eventually("second failure", || async { h.state().await.failures == 2 }).await;

    h.peer.up.store(true, Ordering::SeqCst);
    h.outbox.peer_up(&h.hub).await.unwrap();
    eventually("resync cleared", || async { !h.state().await.needs_resync }).await;
    assert_eq!(h.source.nudges.load(Ordering::SeqCst), 2);
    assert_eq!(h.delivered(), [("g".into(), 1000)]);
    h.outbox.shutdown();
}

#[tokio::test]
async fn cap_eviction_marks_resync_and_nudges_after_draining() {
    let config = OutboxConfig {
        max_entries_per_peer: 2,
        ..config()
    };
    let h = Harness::new(Db::open_in_memory().unwrap(), config, false);
    h.enqueue(vec![deliver("g", 1), deliver("g", 2), deliver("g", 3)])
        .await;
    assert_eq!(h.outbox.dropped_total(&h.hub, DropReason::Evicted), 1);
    assert_eq!(
        h.queued().await,
        [(Some("g".into()), Some(2)), (Some("g".into()), Some(3))]
    );
    assert!(h.state().await.needs_resync);

    // The member hub had seq 1 before the outage.
    h.peer.last_seq.lock().unwrap().insert("g".into(), 1);
    h.peer.up.store(true, Ordering::SeqCst);
    h.outbox.start(None);
    eventually("resync cleared", || async { !h.state().await.needs_resync }).await;
    assert!(h.queued().await.is_empty());
    assert_eq!(h.source.nudges.load(Ordering::SeqCst), 1);
    assert_eq!(
        h.delivered(),
        [("g".into(), 2), ("g".into(), 3), ("g".into(), 1000)]
    );
    h.outbox.shutdown();
}

#[tokio::test]
async fn permanent_failures_drop_only_the_offending_entry() {
    let h = Harness::new(Db::open_in_memory().unwrap(), config(), true);
    h.peer.invalid_gids.lock().unwrap().insert("bad".into());
    h.peer.reject_welcomes.store(true, Ordering::SeqCst);
    let welcome = DeliverWelcomeRequest::default().encode_to_vec().leak();
    h.enqueue(vec![
        deliver("g", 1),
        deliver("bad", 1),
        deliver("gone", 1),
        deliver("g", 2),
        NewEntry::DeliverWelcome {
            gid: "g",
            payload: welcome,
        },
        NewEntry::DeliverWelcome {
            gid: "g",
            payload: b"not protobuf \xff\xff",
        },
        deliver("g", 3),
    ])
    .await;
    h.outbox.start(None);
    eventually("queue drained", || async { h.queued().await.is_empty() }).await;

    assert_eq!(h.outbox.dropped_total(&h.hub, DropReason::Rejected), 2);
    assert_eq!(h.outbox.dropped_total(&h.hub, DropReason::Unbuildable), 2);
    assert_eq!(h.source.refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(*h.peer.last_seq.lock().unwrap().get("g").unwrap(), 3);
    assert_eq!(h.state().await.failures, 0);
    h.outbox.shutdown();
}

#[tokio::test]
async fn queued_entries_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hub.db");
    {
        let h = Harness::new(Db::open(&path).unwrap(), config(), false);
        h.enqueue(vec![deliver("g", 1), deliver("g", 2)]).await;
        h.outbox.start(None);
        eventually("first failure", || async { h.state().await.failures == 1 }).await;
        h.outbox.shutdown();
    }

    let h = Harness::new(Db::open(&path).unwrap(), config(), true);
    let state = h.state().await;
    assert_eq!(state.failures, 1);
    assert_eq!(h.queued().await.len(), 2);
    h.outbox.start(None);
    h.advance_to(state.next_attempt_at);
    eventually("queue drained", || async { h.queued().await.is_empty() }).await;
    assert_eq!(h.delivered(), [("g".into(), 1), ("g".into(), 2)]);
    h.outbox.shutdown();
}

#[tokio::test]
async fn peer_up_events_reset_the_backoff() {
    let h = Harness::new(Db::open_in_memory().unwrap(), config(), false);
    h.enqueue(vec![deliver("g", 1)]).await;
    let (events, receiver) = tokio::sync::broadcast::channel(4);
    h.outbox.start(Some(receiver));
    eventually("first failure", || async { h.state().await.failures == 1 }).await;
    h.peer.up.store(true, Ordering::SeqCst);
    events.send(PeerEvent::Up(h.hub.clone())).unwrap();
    eventually("queue drained", || async { h.queued().await.is_empty() }).await;
    h.outbox.shutdown();
}

#[tokio::test]
async fn disabled_federation_queues_nothing() {
    let db = Db::open_in_memory().unwrap();
    db.write(|tx| Disabled.enqueue_in_tx(tx, &hub(3), NewEntry::DeviceList { user_id: "u" }))
        .await
        .unwrap();
    assert!(db.read(store::pending_peers).await.unwrap().is_empty());
}
