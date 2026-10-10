//! In-memory store the local connector projects records into. The public
//! [`LocalConnectorState`] holds the room, inbox, and draft entries that the
//! handlers and projection read and mutate; [`ConnectorSnapshot`] is its
//! durable form, which `LocalConnector::snapshot` writes with the next nonce.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::discourse::{AgentStatus, ArchiveRecord, RoomJoinRequest, RoomResponse};
use crate::identity::AgentId;
use crate::profile::AgentProfile;

use super::inputs::{RoomSendMessageInput, RoomSubmitEventInput};
use super::views::{
    ActiveTurn, AgentProtocolsHost, HeldDraft, InboxItem, RoomMemberView, TimelineItem,
};

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
pub const LOCAL_CONNECTOR_SNAPSHOT_VERSION: u64 = 1;

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
    pub(crate) fn new(agent_id: AgentId, next_nonce: u64, state: &LocalConnectorState) -> Self {
        Self {
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
        }
    }

    pub(crate) fn into_state(self) -> LocalConnectorState {
        LocalConnectorState {
            hosts: self.hosts,
            rooms: self
                .rooms
                .into_iter()
                .map(|room| ((room.host.clone(), room.room.id.clone()), room))
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
            inbox: self.inbox,
            drafts: self.drafts,
        }
    }
}
