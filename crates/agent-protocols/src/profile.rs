use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::error::{Result, SdkError};
use crate::identity::{verify_envelope, AgentId, Envelope, Event};

pub const PROTOCOL: &str = "agent-profile/1.0";
pub const PROFILE_UPDATE: &str = "profile.update";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceEndpoint {
    #[serde(rename = "type")]
    pub kind: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocols: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ProfileUpdatePayload {
    pub agent_id: AgentId,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_endpoints: Vec<ServiceEndpoint>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub links: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
}

impl ProfileUpdatePayload {
    pub fn new(agent_id: AgentId, name: impl Into<String>) -> Self {
        Self {
            agent_id,
            name: name.into(),
            description: None,
            avatar_url: None,
            provider: None,
            capabilities: Vec::new(),
            service_endpoints: Vec::new(),
            links: BTreeMap::new(),
            metadata: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AgentProfile {
    pub agent_id: AgentId,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_endpoints: Vec<ServiceEndpoint>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub links: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
    pub updated_at: i64,
    pub profile_event_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ProfileReadResponse {
    pub profile: AgentProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_event: Option<Envelope<ProfileUpdatePayload>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileServiceDiscovery {
    pub protocol: String,
    pub service: String,
    pub endpoints: ProfileServiceEndpoints,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileServiceEndpoints {
    pub profiles: String,
}

pub fn profile_update_event(
    actor: AgentId,
    created_at: i64,
    nonce: impl Into<String>,
    payload: ProfileUpdatePayload,
) -> Event<ProfileUpdatePayload> {
    Event::new(PROTOCOL, PROFILE_UPDATE, actor, created_at, nonce, payload)
}

pub fn validate_profile_update(envelope: &Envelope<ProfileUpdatePayload>) -> Result<()> {
    verify_envelope(envelope)?;
    if envelope.event.protocol != PROTOCOL {
        return Err(SdkError::InvalidEventProtocol {
            expected: PROTOCOL.to_owned(),
            actual: envelope.event.protocol.clone(),
        });
    }
    if envelope.event.kind != PROFILE_UPDATE {
        return Err(SdkError::InvalidEventType {
            expected: PROFILE_UPDATE.to_owned(),
            actual: envelope.event.kind.clone(),
        });
    }
    if envelope.event.actor != envelope.event.payload.agent_id {
        return Err(SdkError::InvalidActor(
            "profile update actor must match payload.agent_id".to_owned(),
        ));
    }
    Ok(())
}

pub fn materialize_profile(envelope: &Envelope<ProfileUpdatePayload>) -> Result<AgentProfile> {
    validate_profile_update(envelope)?;
    let payload = &envelope.event.payload;
    Ok(AgentProfile {
        agent_id: payload.agent_id.clone(),
        name: payload.name.clone(),
        description: payload.description.clone(),
        avatar_url: payload.avatar_url.clone(),
        provider: payload.provider.clone(),
        capabilities: payload.capabilities.clone(),
        service_endpoints: payload.service_endpoints.clone(),
        links: payload.links.clone(),
        metadata: payload.metadata.clone(),
        updated_at: envelope.event.created_at,
        profile_event_id: envelope.event_id.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentSigner;

    #[test]
    fn materializes_valid_profile_update() {
        let signer = AgentSigner::from_seed([11; 32]);
        let mut payload = ProfileUpdatePayload::new(signer.agent_id(), "ResearchAgent-v3");
        payload.capabilities.push("research".to_owned());
        let event =
            profile_update_event(signer.agent_id(), 1_779_753_600_000, "n_profile", payload);
        let envelope = signer.sign_event(event).unwrap();

        let profile = materialize_profile(&envelope).unwrap();

        assert_eq!(profile.name, "ResearchAgent-v3");
        assert_eq!(profile.updated_at, 1_779_753_600_000);
        assert_eq!(profile.profile_event_id, envelope.event_id);
    }

    #[test]
    fn rejects_actor_payload_mismatch() {
        let signer = AgentSigner::from_seed([12; 32]);
        let other = AgentSigner::from_seed([13; 32]);
        let payload = ProfileUpdatePayload::new(other.agent_id(), "Imposter");
        let event =
            profile_update_event(signer.agent_id(), 1_779_753_600_000, "n_profile", payload);
        let envelope = signer.sign_event(event).unwrap();

        assert!(matches!(
            validate_profile_update(&envelope),
            Err(SdkError::InvalidActor(_))
        ));
    }
}
