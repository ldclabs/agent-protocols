//! In-memory store the local connector projects records into. The public
//! [`LocalConnectorState`] is the durable snapshot a host persists and restores;
//! the room, inbox, and draft entries are the crate-internal working set that
//! the handlers and projection read and mutate.

use std::collections::BTreeMap;

use crate::discourse::{AgentStatus, RoomJoinRequestStatus, RoomResponse, ServerRecord};
use crate::identity::AgentId;
use crate::profile::AgentProfile;

use super::inputs::{RoomSendMessageInput, RoomSubmitEventInput};
use super::views::{ActiveTurn, AgentProtocolsHost, HeldDraft, InboxItem, RoomMemberView, TimelineItem};

/// Local room state is keyed by `(host, room_id)`: ADP room IDs are only
/// RECOMMENDED to be globally unique, and a connector can be configured with
/// multiple hosts.
pub type RoomKey = (String, String);

#[derive(Clone, Debug, Default)]
pub struct LocalConnectorState {
    pub hosts: BTreeMap<String, AgentProtocolsHost>,
    pub(crate) rooms: BTreeMap<RoomKey, LocalRoomState>,
    pub(crate) profiles: BTreeMap<AgentId, AgentProfile>,
    pub(crate) join_requests: BTreeMap<RoomKey, Vec<RoomJoinRequestStatus>>,
    pub(crate) agent_statuses: BTreeMap<RoomKey, BTreeMap<AgentId, AgentStatus>>,
    pub(crate) inbox: BTreeMap<String, InboxEntry>,
    pub(crate) drafts: BTreeMap<String, HeldDraftEntry>,
}

impl LocalConnectorState {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LocalRoomState {
    pub(crate) host: String,
    pub(crate) room: RoomResponse,
    pub(crate) head_seq: u64,
    pub(crate) head_hash: Option<String>,
    pub(crate) synced_seq: u64,
    pub(crate) synced_hash: Option<String>,
    pub(crate) subscribed: bool,
    pub(crate) members: BTreeMap<AgentId, RoomMemberView>,
    pub(crate) timeline: Vec<TimelineItem>,
    pub(crate) records: Vec<ServerRecord>,
    pub(crate) read_seq: u64,
    pub(crate) active_turn: Option<ActiveTurn>,
}

impl LocalRoomState {
    pub(crate) fn new(host: String, room: RoomResponse) -> Self {
        Self {
            host,
            room,
            head_seq: 0,
            head_hash: None,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InboxEntryState {
    Pending,
    Claimed,
    Deferred(i64),
    Acknowledged,
}

#[derive(Clone, Debug)]
pub(crate) struct InboxEntry {
    pub(crate) item: InboxItem,
    pub(crate) state: InboxEntryState,
}

#[derive(Clone, Debug)]
pub(crate) struct HeldDraftEntry {
    pub(crate) draft: HeldDraft,
    pub(crate) request: HeldDraftRequest,
}

#[derive(Clone, Debug)]
pub(crate) enum HeldDraftRequest {
    Message(RoomSendMessageInput),
    Event(RoomSubmitEventInput),
}
