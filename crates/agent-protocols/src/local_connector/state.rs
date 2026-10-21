//! In-memory store the local connector projects records into. The public
//! [`LocalConnectorState`] holds the room, inbox, draft, and mail entries that
//! the handlers and projection read and mutate; [`ConnectorSnapshot`] is its
//! durable form, which `LocalConnector::snapshot` writes with the next nonce.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::discourse::{AgentStatus, ArchiveRecord, RoomJoinRequest, RoomResponse};
use crate::error::Result;
use crate::identity::AgentId;
use crate::mail::{MailCardCache, MailboxCard, MessagePayload, Packet};
use crate::profile::AgentProfile;

use super::inputs::{RoomSendMessageInput, RoomSubmitEventInput};
use super::views::{
    ActiveTurn, AgentProtocolsHost, HeldDraft, InboxItem, MailDelivery, MailDirection,
    RoomMemberView, TimelineItem,
};
use super::{INBOX_LIMIT, ROOM_HISTORY_LIMIT};

/// Local room state is keyed by `(host, room_id)`: ADP room IDs are only
/// RECOMMENDED to be globally unique, and a connector can be configured with
/// multiple hosts.
pub type RoomKey = (String, String);

#[derive(Clone, Debug, Default)]
pub struct LocalConnectorState {
    pub hosts: BTreeMap<String, AgentProtocolsHost>,
    pub(crate) rooms: BTreeMap<RoomKey, LocalRoomState>,
    pub(crate) profiles: BTreeMap<AgentId, AgentProfile>,
    /// Join requests visible to this agent as a reviewer.
    pub(crate) join_requests: BTreeMap<RoomKey, Vec<RoomJoinRequest>>,
    /// This agent's own join requests.
    pub(crate) own_join_requests: BTreeMap<RoomKey, RoomJoinRequest>,
    pub(crate) agent_statuses: BTreeMap<RoomKey, BTreeMap<AgentId, AgentStatus>>,
    pub(crate) inbox: BTreeMap<String, InboxEntry>,
    pub(crate) drafts: BTreeMap<String, HeldDraftEntry>,
    pub(crate) mail: MailState,
}

impl LocalConnectorState {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LocalRoomState {
    pub(crate) host: String,
    pub(crate) room: RoomResponse,
    pub(crate) head_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) head_hash: Option<String>,
    /// Presented head for this connector session (local connector Section 4.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) presented_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) presented_hash: Option<String>,
    pub(crate) synced_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) synced_hash: Option<String>,
    pub(crate) subscribed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) watch_types: Option<Vec<String>>,
    pub(crate) members: BTreeMap<AgentId, RoomMemberView>,
    pub(crate) timeline: Vec<TimelineItem>,
    pub(crate) records: Vec<ArchiveRecord>,
    pub(crate) read_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) active_turn: Option<ActiveTurn>,
}

impl LocalRoomState {
    pub(crate) fn new(host: String, room: RoomResponse) -> Self {
        Self {
            host,
            room,
            head_seq: 0,
            head_hash: None,
            presented_seq: None,
            presented_hash: None,
            synced_seq: 0,
            synced_hash: None,
            subscribed: false,
            watch_types: None,
            members: BTreeMap::new(),
            timeline: Vec::new(),
            records: Vec::new(),
            read_seq: 0,
            active_turn: None,
        }
    }

    pub(crate) fn unread_count(&self) -> usize {
        self.timeline
            .iter()
            .filter(|item| item.seq > self.read_seq)
            .count()
    }

    /// Forgets the oldest records and timeline items beyond
    /// [`ROOM_HISTORY_LIMIT`]. The synced and head positions stay.
    pub(crate) fn trim_history(&mut self) {
        let excess = self.records.len().saturating_sub(ROOM_HISTORY_LIMIT);
        self.records.drain(..excess);
        let excess = self.timeline.len().saturating_sub(ROOM_HISTORY_LIMIT);
        self.timeline.drain(..excess);
    }
}

/// Agent Mail state. Decryption keys are not part of it: the connector keeps
/// them apart, for the host's key store.
#[derive(Clone, Debug, Default)]
pub(crate) struct MailState {
    /// The active Agent ID's mailboxes: every card retained until its
    /// `receive_until`, in signing order, the last one current.
    pub(crate) mailboxes: BTreeMap<String, Vec<MailboxCard>>,
    /// Sender-side card pins (Agent Mail Section 3.2).
    pub(crate) pins: MailCardCache,
    /// Operator sender policy, applied before decryption.
    pub(crate) blocked_senders: BTreeSet<AgentId>,
    /// Received and sent messages in local order, kept until they expire.
    pub(crate) messages: Vec<StoredMailMessage>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct StoredMailMessage {
    pub(crate) direction: MailDirection,
    pub(crate) message: MessagePayload,
    /// The receiving mailbox, or the recipient's mailbox for a sent message.
    pub(crate) mailbox_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) received_at: Option<i64>,
    #[serde(default)]
    pub(crate) read: bool,
    /// A sent message's latest packet, retried byte-for-byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) packet: Option<Packet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) delivery: Option<MailDelivery>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum InboxEntryState {
    Pending,
    /// A lease until the given time, so a crashed session cannot hold the item forever.
    Claimed {
        until: i64,
    },
    Deferred {
        until: i64,
    },
    Acknowledged,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct InboxEntry {
    pub(crate) item: InboxItem,
    pub(crate) state: InboxEntryState,
}

/// Forgets inbox entries beyond [`INBOX_LIMIT`]: acknowledged ones first,
/// then the oldest.
pub(crate) fn trim_inbox(inbox: &mut BTreeMap<String, InboxEntry>) {
    let excess = inbox.len().saturating_sub(INBOX_LIMIT);
    if excess == 0 {
        return;
    }
    let mut order: Vec<_> = inbox
        .iter()
        .map(|(id, entry)| {
            let open = entry.state != InboxEntryState::Acknowledged;
            (open, entry.item.created_at, id.clone())
        })
        .collect();
    order.sort_unstable();
    for (_, _, id) in order.into_iter().take(excess) {
        inbox.remove(&id);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct HeldDraftEntry {
    pub(crate) draft: HeldDraft,
    pub(crate) request: HeldDraftRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "input", rename_all = "snake_case")]
pub(crate) enum HeldDraftRequest {
    Message(RoomSendMessageInput),
    Event(RoomSubmitEventInput),
}

/// Version of the document [`super::LocalConnector::snapshot`] produces.
pub const LOCAL_CONNECTOR_SNAPSHOT_VERSION: u64 = 2;

/// The persisted form of a connector: its Agent ID, next nonce, and every
/// map of [`LocalConnectorState`]. Maps keyed by `(host, room_id)` become
/// lists whose entries carry both; the other maps keep their string keys.
#[derive(Serialize, Deserialize)]
pub(crate) struct ConnectorSnapshot {
    pub(crate) version: u64,
    pub(crate) agent_id: AgentId,
    pub(crate) next_nonce: u64,
    hosts: BTreeMap<String, AgentProtocolsHost>,
    rooms: Vec<LocalRoomState>,
    profiles: BTreeMap<AgentId, AgentProfile>,
    join_requests: Vec<RoomJoinRequests>,
    own_join_requests: Vec<OwnJoinRequest>,
    agent_statuses: Vec<RoomAgentStatuses>,
    inbox: BTreeMap<String, InboxEntry>,
    drafts: BTreeMap<String, HeldDraftEntry>,
    mail: MailSnapshot,
}

#[derive(Serialize, Deserialize)]
struct MailSnapshot {
    mailboxes: Vec<OwnMailbox>,
    pins: Vec<MailboxCard>,
    blocked_senders: BTreeSet<AgentId>,
    messages: Vec<StoredMailMessage>,
}

#[derive(Serialize, Deserialize)]
struct OwnMailbox {
    mailbox_id: String,
    cards: Vec<MailboxCard>,
}

#[derive(Serialize, Deserialize)]
struct RoomJoinRequests {
    host: String,
    room_id: String,
    requests: Vec<RoomJoinRequest>,
}

#[derive(Serialize, Deserialize)]
struct OwnJoinRequest {
    host: String,
    room_id: String,
    request: RoomJoinRequest,
}

#[derive(Serialize, Deserialize)]
struct RoomAgentStatuses {
    host: String,
    room_id: String,
    statuses: BTreeMap<AgentId, AgentStatus>,
}

impl ConnectorSnapshot {
    pub(crate) fn new(
        agent_id: AgentId,
        next_nonce: u64,
        state: &LocalConnectorState,
    ) -> Result<Self> {
        let pins = serde_json::from_value(state.mail.pins.snapshot()?["pins"].take())?;
        Ok(Self {
            version: LOCAL_CONNECTOR_SNAPSHOT_VERSION,
            agent_id,
            next_nonce,
            hosts: state.hosts.clone(),
            rooms: state.rooms.values().cloned().collect(),
            profiles: state.profiles.clone(),
            join_requests: state
                .join_requests
                .iter()
                .map(|((host, room_id), requests)| RoomJoinRequests {
                    host: host.clone(),
                    room_id: room_id.clone(),
                    requests: requests.clone(),
                })
                .collect(),
            own_join_requests: state
                .own_join_requests
                .iter()
                .map(|((host, room_id), request)| OwnJoinRequest {
                    host: host.clone(),
                    room_id: room_id.clone(),
                    request: request.clone(),
                })
                .collect(),
            agent_statuses: state
                .agent_statuses
                .iter()
                .map(|((host, room_id), statuses)| RoomAgentStatuses {
                    host: host.clone(),
                    room_id: room_id.clone(),
                    statuses: statuses.clone(),
                })
                .collect(),
            inbox: state.inbox.clone(),
            drafts: state.drafts.clone(),
            mail: MailSnapshot {
                mailboxes: state
                    .mail
                    .mailboxes
                    .iter()
                    .map(|(mailbox_id, cards)| OwnMailbox {
                        mailbox_id: mailbox_id.clone(),
                        cards: cards.clone(),
                    })
                    .collect(),
                pins,
                blocked_senders: state.mail.blocked_senders.clone(),
                messages: state.mail.messages.clone(),
            },
        })
    }

    pub(crate) fn into_state(self) -> Result<LocalConnectorState> {
        let pins = MailCardCache::from_snapshot(&json!({"version": 1, "pins": self.mail.pins}))?;
        let mut inbox = self.inbox;
        trim_inbox(&mut inbox);
        Ok(LocalConnectorState {
            hosts: self.hosts,
            rooms: self
                .rooms
                .into_iter()
                .map(|mut room| {
                    room.trim_history();
                    ((room.host.clone(), room.room.id.clone()), room)
                })
                .collect(),
            profiles: self.profiles,
            join_requests: self
                .join_requests
                .into_iter()
                .map(|entry| ((entry.host, entry.room_id), entry.requests))
                .collect(),
            own_join_requests: self
                .own_join_requests
                .into_iter()
                .map(|entry| ((entry.host, entry.room_id), entry.request))
                .collect(),
            agent_statuses: self
                .agent_statuses
                .into_iter()
                .map(|entry| ((entry.host, entry.room_id), entry.statuses))
                .collect(),
            inbox,
            drafts: self.drafts,
            mail: MailState {
                mailboxes: self
                    .mail
                    .mailboxes
                    .into_iter()
                    .map(|mailbox| (mailbox.mailbox_id, mailbox.cards))
                    .collect(),
                pins,
                blocked_senders: self.mail.blocked_senders,
                messages: self.mail.messages,
            },
        })
    }
}
