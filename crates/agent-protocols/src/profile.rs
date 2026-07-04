use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::delegation::PrincipalDescriptor;
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProfileLinkRel {
    Homepage,
    Documentation,
    SourceCode,
    Social,
    Browser,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileLink {
    pub name: String,
    pub url: String,
    pub rel: ProfileLinkRel,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ProfileDelegationHint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub principal: PrincipalDescriptor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    pub credential_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ProfileUpdatePayload {
    pub id: AgentId,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<ProfileLink>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegations: Vec<ProfileDelegationHint>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl ProfileUpdatePayload {
    pub fn new(id: AgentId, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            description: None,
            avatar_url: None,
            provider: None,
            capabilities: Vec::new(),
            service_endpoints: Vec::new(),
            links: Vec::new(),
            delegations: Vec::new(),
            extra: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AgentProfile {
    pub id: AgentId,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<ProfileLink>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegations: Vec<ProfileDelegationHint>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
    pub updated_at: i64,
    pub event_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ProfileBatchReadRequest {
    pub ids: Vec<AgentId>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ProfileBatchReadResponse {
    pub result: Vec<AgentProfile>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ProfileEventsResponse {
    pub result: Vec<Envelope<ProfileUpdatePayload>>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_batch: Option<String>,
}

pub fn profile_update_event(
    actor: AgentId,
    created_at: i64,
    nonce: u64,
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
    if envelope.event.actor != envelope.event.payload.id {
        return Err(SdkError::InvalidActor(
            "profile update actor must match payload.id".to_owned(),
        ));
    }
    Ok(())
}

pub fn materialize_profile(envelope: &Envelope<ProfileUpdatePayload>) -> Result<AgentProfile> {
    validate_profile_update(envelope)?;
    let payload = &envelope.event.payload;
    Ok(AgentProfile {
        id: payload.id.clone(),
        name: payload.name.clone(),
        description: payload.description.clone(),
        avatar_url: payload.avatar_url.clone(),
        provider: payload.provider.clone(),
        capabilities: payload.capabilities.clone(),
        service_endpoints: payload.service_endpoints.clone(),
        links: payload.links.clone(),
        delegations: payload.delegations.clone(),
        extra: payload.extra.clone(),
        updated_at: envelope.event.created_at,
        event_id: envelope.hash.clone(),
    })
}

/// Selects the latest profile state from accepted update envelopes. Nonces
/// are strictly monotonic per Agent ID, so the latest profile is defined as
/// the accepted `profile.update` with the greatest `nonce` — deterministic and
/// independently checkable from event history alone.
pub fn latest_profile_update(
    envelopes: &[Envelope<ProfileUpdatePayload>],
) -> Option<&Envelope<ProfileUpdatePayload>> {
    envelopes.iter().max_by_key(|envelope| envelope.event.nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::PrincipalDescriptor;
    use crate::identity::AgentSigner;

    #[test]
    fn materializes_valid_profile_update() {
        let signer = AgentSigner::from_seed([11; 32]);
        let mut payload = ProfileUpdatePayload::new(signer.agent_id(), "ResearchAgent-v3");
        payload.capabilities.push("research".to_owned());
        payload
            .extra
            .insert("domain".to_owned(), Value::String("research".to_owned()));
        payload.links.push(ProfileLink {
            name: "Homepage".to_owned(),
            url: "https://example.com".to_owned(),
            rel: ProfileLinkRel::Homepage,
        });
        payload.delegations.push(ProfileDelegationHint {
            id: None,
            principal: PrincipalDescriptor {
                id: "https://al.ink/yan".to_owned(),
                kind: Some("person".to_owned()),
                name: Some("Yan".to_owned()),
            },
            relationship: Some("primary_delegate".to_owned()),
            scopes: vec!["inbox.screen".to_owned()],
            credential_url: "https://al.ink/v1/delegations/del_1".to_owned(),
            status_url: None,
        });
        let expected_extra = payload.extra.clone();
        let event = profile_update_event(signer.agent_id(), 1_779_753_600_000, 1, payload);
        let envelope = signer.sign_event(event).unwrap();

        let profile = materialize_profile(&envelope).unwrap();

        assert_eq!(profile.id, signer.agent_id());
        assert_eq!(profile.name, "ResearchAgent-v3");
        assert_eq!(profile.links.len(), 1);
        assert_eq!(profile.links[0].rel, ProfileLinkRel::Homepage);
        assert_eq!(profile.delegations.len(), 1);
        assert_eq!(profile.extra, expected_extra);
        assert_eq!(profile.updated_at, 1_779_753_600_000);
        assert_eq!(profile.event_id, envelope.hash);
    }

    #[test]
    fn materialized_profile_has_no_username_field() {
        let signer = AgentSigner::from_seed([15; 32]);
        let payload = ProfileUpdatePayload::new(signer.agent_id(), "ResearchAgent-v3");
        let event = profile_update_event(signer.agent_id(), 1_779_753_600_002, 1, payload);
        let envelope = signer.sign_event(event).unwrap();

        let profile = materialize_profile(&envelope).unwrap();

        assert_eq!(profile.id, signer.agent_id());
        let value = serde_json::to_value(&profile).unwrap();
        assert!(value.get("username").is_none());
    }

    #[test]
    fn latest_profile_update_picks_greatest_nonce() {
        let signer = AgentSigner::from_seed([16; 32]);
        let envelopes: Vec<_> = [3_u64, 1, 2]
            .into_iter()
            .map(|nonce| {
                let payload =
                    ProfileUpdatePayload::new(signer.agent_id(), format!("Agent-v{nonce}"));
                signer
                    .sign_event(profile_update_event(
                        signer.agent_id(),
                        1_779_753_600_000 + nonce as i64,
                        nonce,
                        payload,
                    ))
                    .unwrap()
            })
            .collect();

        assert!(latest_profile_update(&[]).is_none());
        let latest = latest_profile_update(&envelopes).unwrap();
        assert_eq!(latest.event.nonce, 3);
        assert_eq!(materialize_profile(latest).unwrap().name, "Agent-v3");
    }

    #[test]
    fn rejects_actor_payload_mismatch() {
        let signer = AgentSigner::from_seed([12; 32]);
        let other = AgentSigner::from_seed([13; 32]);
        let payload = ProfileUpdatePayload::new(other.agent_id(), "Imposter");
        let event = profile_update_event(signer.agent_id(), 1_779_753_600_000, 1, payload);
        let envelope = signer.sign_event(event).unwrap();

        assert!(matches!(
            validate_profile_update(&envelope),
            Err(SdkError::InvalidActor(_))
        ));
    }

    #[test]
    fn rejects_legacy_agent_id_payload_without_id() {
        let signer = AgentSigner::from_seed([14; 32]);
        let legacy_event = crate::identity::Event::new(
            PROTOCOL,
            PROFILE_UPDATE,
            signer.agent_id(),
            1_779_753_600_001,
            1,
            serde_json::json!({
                "agent_id": signer.agent_id(),
                "name": "LegacyAgent"
            }),
        );
        let signed = signer.sign_event(legacy_event).unwrap();

        assert!(serde_json::from_value::<Envelope<ProfileUpdatePayload>>(
            serde_json::to_value(signed).unwrap()
        )
        .is_err());
    }

    #[test]
    fn rejects_wrong_protocol_and_type() {
        let signer = AgentSigner::from_seed([19; 32]);
        let payload = ProfileUpdatePayload::new(signer.agent_id(), "ResearchAgent");

        let wrong_protocol = signer
            .sign_event(crate::identity::Event::new(
                "agent-discourse/1.0",
                PROFILE_UPDATE,
                signer.agent_id(),
                1_779_753_600_000,
                1,
                payload.clone(),
            ))
            .unwrap();
        assert!(matches!(
            validate_profile_update(&wrong_protocol),
            Err(SdkError::InvalidEventProtocol { .. })
        ));

        let wrong_type = signer
            .sign_event(crate::identity::Event::new(
                PROTOCOL,
                "profile.delete",
                signer.agent_id(),
                1_779_753_600_000,
                1,
                payload,
            ))
            .unwrap();
        assert!(matches!(
            validate_profile_update(&wrong_type),
            Err(SdkError::InvalidEventType { .. })
        ));
    }
}
