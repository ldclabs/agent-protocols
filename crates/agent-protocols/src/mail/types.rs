use crate::identity::{AgentId, Envelope};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub type MailboxCard = Envelope<MailboxCardPayload>;
/// The signed `mail.submit` envelope: the wire object relays store and recipients open.
pub type Packet = Envelope<PacketPayload>;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MailboxCardPayload {
    pub mailbox_id: String,
    pub expires_at: i64,
    pub receive_until: i64,
    pub public_key: String,
    /// Zero to eight relay origins; an empty list closes the mailbox.
    pub routes: Vec<String>,
    pub max_packet_bytes: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MessagePayload {
    pub message_id: String,
    #[serde(rename = "from")]
    pub sender: AgentId,
    pub created_at: i64,
    pub to: AgentId,
    pub expires_at: i64,
    pub thread_id: String,
    pub parts: Vec<MailPart>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_card: Option<Value>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MailPart {
    pub media_type: String,
    pub data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}
impl MailPart {
    pub fn text(text: &str) -> Self {
        Self {
            media_type: "text/plain".into(),
            data: super::encode_bytes(text.as_bytes()),
            name: None,
        }
    }
    pub fn bytes(media_type: impl Into<String>, bytes: &[u8], name: Option<String>) -> Self {
        Self {
            media_type: media_type.into(),
            data: super::encode_bytes(bytes),
            name,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PacketHeader {
    pub mailbox_id: String,
    pub card_hash: String,
    pub expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PacketPayload {
    pub header: PacketHeader,
    pub enc: String,
    pub ciphertext: String,
}
/// Sender-authenticated delivery result. It never carries the mailbox `seq`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DeliveryResult {
    pub packet_id: String,
    pub accepted_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PacketRecord {
    pub packet_id: String,
    pub packet: Packet,
    pub accepted_at: i64,
    pub seq: u64,
}
/// A parsed mailbox address (Mail Section 3.3). `routes` is empty for the stable form.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MailAddress {
    pub owner: AgentId,
    pub mailbox_id: String,
    pub routes: Vec<String>,
}
#[derive(Clone, Debug, PartialEq)]
pub enum InboxAcceptance {
    Accepted(Box<MessagePayload>),
    Duplicate(Box<MessagePayload>),
}
