use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

use crate::delegation::{validate_delegation_id, PrincipalDescriptor};
use crate::error::{Result, SdkError};
use crate::identity::{
    validate_event_fields, verify_envelope, AgentId, Envelope, Event, ListResponse,
};

pub const PROTOCOL: &str = "agent-profile/1.0";
pub const PROFILE_UPDATE: &str = "profile.update";

// Optional collections are `Option`s throughout this module: a signed
// payload may carry an explicit `[]` or `{}`, and re-serializing it must
// reproduce the signed bytes, so an empty value stays distinct from an
// absent one.

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceEndpoint {
    #[serde(rename = "type")]
    pub kind: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<String>>,
}

/// Defined link relationships. `rel` is an open vocabulary: clients accept
/// other non-empty values and may render them as generic links.
pub mod link_rel {
    pub const HOMEPAGE: &str = "homepage";
    pub const DOCUMENTATION: &str = "documentation";
    pub const SOURCE_CODE: &str = "source_code";
    pub const SOCIAL: &str = "social";
    pub const BROWSER: &str = "browser";
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileLink {
    pub name: String,
    pub url: String,
    pub rel: String,
}

/// Discovery hint only. It carries no service URLs: the publishing agent is the
/// party whose claim is checked, so clients resolve the principal document at
/// `principal.id` and query the service it names.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProfileDelegationHint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub principal: PrincipalDescriptor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
}

/// The closed `profile.update` payload (Section 4.1): undefined fields are
/// rejected at deserialization, and application data belongs in `extra`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProfileUpdatePayload {
    pub id: AgentId,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_endpoints: Option<Vec<ServiceEndpoint>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<ProfileLink>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegations: Option<Vec<ProfileDelegationHint>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<BTreeMap<String, Value>>,
}

impl ProfileUpdatePayload {
    pub fn new(id: AgentId, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            description: None,
            avatar_url: None,
            provider: None,
            capabilities: None,
            service_endpoints: None,
            links: None,
            delegations: None,
            extra: None,
        }
    }
}

/// The materialized profile document: the latest payload's fields exactly as
/// signed, plus the service-derived `updated_at` and `event_id`.
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_endpoints: Option<Vec<ServiceEndpoint>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<ProfileLink>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegations: Option<Vec<ProfileDelegationHint>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<BTreeMap<String, Value>>,
    pub updated_at: i64,
    pub event_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ProfileBatchReadRequest {
    pub ids: Vec<AgentId>,
}

/// Agent Identity list of profile documents; never carries `next_cursor`.
pub type ProfileBatchReadResponse = ListResponse<AgentProfile>;

/// Agent Identity list of accepted updates, newest first by `nonce`.
pub type ProfileEventsResponse = ListResponse<Envelope<ProfileUpdatePayload>>;

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
    // Profile events carry only the six Agent Identity event fields.
    validate_event_fields(&envelope.event, &[])?;
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
    validate_profile_payload(&envelope.event.payload)
}

/// Section 4.1 field rules for a `profile.update` payload. The field set
/// itself is closed by [`ProfileUpdatePayload`] deserialization.
pub fn validate_profile_payload(payload: &ProfileUpdatePayload) -> Result<()> {
    payload.id.public_key_bytes()?;
    if payload.name.is_empty() {
        return Err(invalid_payload("name must not be empty"));
    }
    if let Some(url) = &payload.avatar_url {
        require_url(url, &["https"], "avatar_url")?;
    }
    unique_strings(payload.capabilities.as_deref(), "capabilities")?;
    let mut endpoints = BTreeSet::new();
    for endpoint in payload.service_endpoints.iter().flatten() {
        if endpoint.kind.is_empty() {
            return Err(invalid_payload("service endpoint type must not be empty"));
        }
        require_url(&endpoint.url, &["https"], "service endpoint url")?;
        unique_strings(endpoint.protocols.as_deref(), "service endpoint protocols")?;
        if !endpoints.insert((endpoint.kind.as_str(), endpoint.url.as_str())) {
            return Err(invalid_payload(
                "service endpoints must be unique by type and url",
            ));
        }
    }
    let mut links = BTreeSet::new();
    for link in payload.links.iter().flatten() {
        if link.name.is_empty() || link.rel.is_empty() {
            return Err(invalid_payload("link name and rel must not be empty"));
        }
        require_url(&link.url, &["http", "https"], "link url")?;
        if !links.insert((link.url.as_str(), link.rel.as_str())) {
            return Err(invalid_payload("links must be unique by url and rel"));
        }
    }
    for hint in payload.delegations.iter().flatten() {
        if let Some(id) = &hint.id {
            validate_delegation_id(id)?;
        }
        require_url(&hint.principal.id, &["https"], "delegation principal id")?;
        unique_strings(hint.scopes.as_deref(), "delegation hint scopes")?;
    }
    Ok(())
}

fn invalid_payload(message: &str) -> SdkError {
    SdkError::protocol("invalid_event", message)
}

fn require_url(value: &str, schemes: &[&str], field: &str) -> Result<()> {
    match url::Url::parse(value) {
        Ok(url) if schemes.contains(&url.scheme()) && url.host_str().is_some() => Ok(()),
        _ => Err(SdkError::protocol(
            "invalid_event",
            format!("{field} must be an {} URL", schemes.join(" or ")),
        )),
    }
}

fn unique_strings(values: Option<&[String]>, field: &str) -> Result<()> {
    let values = values.unwrap_or_default();
    if values.iter().any(String::is_empty) {
        return Err(SdkError::protocol(
            "invalid_event",
            format!("{field} entries must not be empty"),
        ));
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(SdkError::protocol(
            "invalid_event",
            format!("{field} entries must be unique"),
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

/// Durable ordering check for a new update (Agent Profile Section 6): its
/// nonce must exceed the nonce of the latest accepted update for the same
/// Agent ID, independent of the replay cache.
pub fn validate_profile_succession(
    envelope: &Envelope<ProfileUpdatePayload>,
    latest_nonce: Option<u64>,
) -> Result<()> {
    match latest_nonce {
        Some(latest) if envelope.event.nonce <= latest => {
            Err(SdkError::NonceNotGreater { max_nonce: latest })
        }
        _ => Ok(()),
    }
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
        payload.capabilities = Some(vec!["research".to_owned()]);
        payload.extra = Some(BTreeMap::from([(
            "domain".to_owned(),
            Value::String("research".to_owned()),
        )]));
        payload.links = Some(vec![ProfileLink {
            name: "Homepage".to_owned(),
            url: "https://example.com".to_owned(),
            rel: link_rel::HOMEPAGE.to_owned(),
        }]);
        let mut principal = PrincipalDescriptor::new("https://api.al.ink/d9c6a99cne5g00a6scn0");
        principal.kind = Some("person".to_owned());
        principal.name = Some("Yan".to_owned());
        payload.delegations = Some(vec![ProfileDelegationHint {
            id: Some("del_1".to_owned()),
            principal,
            relationship: Some("primary_delegate".to_owned()),
            scopes: Some(vec!["inbox.screen".to_owned()]),
        }]);
        let expected_extra = payload.extra.clone();
        let event = profile_update_event(signer.agent_id(), 1_779_753_600_000, 1, payload);
        let envelope = signer.sign_event(event).unwrap();

        let profile = materialize_profile(&envelope).unwrap();

        assert_eq!(profile.id, signer.agent_id());
        assert_eq!(profile.name, "ResearchAgent-v3");
        let links = profile.links.as_deref().unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].rel, link_rel::HOMEPAGE);
        assert_eq!(profile.delegations.as_deref().map(<[_]>::len), Some(1));
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
    fn requires_nonce_succession_and_closed_event_fields() {
        let signer = AgentSigner::from_seed([17; 32]);
        let payload = ProfileUpdatePayload::new(signer.agent_id(), "A");
        let envelope = signer
            .sign_event(profile_update_event(
                signer.agent_id(),
                1_000,
                7,
                payload.clone(),
            ))
            .unwrap();
        validate_profile_succession(&envelope, None).unwrap();
        validate_profile_succession(&envelope, Some(6)).unwrap();
        for latest in [7, 8] {
            assert!(matches!(
                validate_profile_succession(&envelope, Some(latest)),
                Err(SdkError::NonceNotGreater { max_nonce }) if max_nonce == latest
            ));
        }
        let extra = signer
            .sign_event(
                profile_update_event(signer.agent_id(), 1_000, 8, payload).with_room_id("r"),
            )
            .unwrap();
        assert_eq!(
            validate_profile_update(&extra).unwrap_err().code(),
            Some("invalid_event")
        );
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
