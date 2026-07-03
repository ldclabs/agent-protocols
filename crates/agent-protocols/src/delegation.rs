//! Agent Delegation Protocol 1.0 types and validation helpers.
//!
//! Delegation events are ordinary Agent Identity envelopes whose actor is a
//! controller key for an HTTPS principal document.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::error::{Result, SdkError};
use crate::identity::{verify_envelope, AgentId, Envelope, Event};
use url::Url;

pub const PROTOCOL: &str = "agent-delegation/1.0";
pub const DELEGATION_GRANT: &str = "delegation.grant";
pub const DELEGATION_REVOKE: &str = "delegation.revoke";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DelegationStatus {
    Active,
    Suspended,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrincipalLink {
    pub name: String,
    pub url: String,
    pub rel: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrincipalDescriptor {
    pub id: String,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl PrincipalDescriptor {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kind: None,
            name: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PrincipalDocument {
    pub id: String,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<PrincipalLink>,
    pub controllers: Vec<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegations_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DelegationGrantPayload {
    pub id: String,
    pub principal: PrincipalDescriptor,
    pub subject: AgentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub constraints: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

impl DelegationGrantPayload {
    pub fn new(
        id: impl Into<String>,
        principal: PrincipalDescriptor,
        subject: AgentId,
        scopes: Vec<String>,
    ) -> Self {
        Self {
            id: id.into(),
            principal,
            subject,
            relationship: None,
            scopes,
            constraints: BTreeMap::new(),
            not_before: None,
            expires_at: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationRevokePayload {
    pub id: String,
    pub principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum DelegationPayload {
    Grant(DelegationGrantPayload),
    Revoke(DelegationRevokePayload),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DelegationCredential {
    pub id: String,
    pub protocol: String,
    pub principal: PrincipalDescriptor,
    pub controller: AgentId,
    pub subject: AgentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub constraints: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    pub status: DelegationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_url: Option<String>,
    pub updated_at: i64,
    pub event_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationStatusDocument {
    pub id: String,
    pub status: DelegationStatus,
    pub checked_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    pub event_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationServiceDiscovery {
    pub protocol: String,
    pub service: String,
    pub endpoints: DelegationServiceEndpoints,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationServiceEndpoints {
    pub delegations: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationQueryRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<DelegationStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DelegationSummary {
    pub id: String,
    pub subject: AgentId,
    pub principal: PrincipalDescriptor,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    pub status: DelegationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DelegationQueryResponse {
    pub result: Vec<DelegationSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DelegationEventsResponse {
    pub result: Vec<Envelope<DelegationPayload>>,
}

pub fn delegation_grant_event(
    actor: AgentId,
    created_at: i64,
    nonce: u64,
    payload: DelegationGrantPayload,
) -> Event<DelegationGrantPayload> {
    Event::new(
        PROTOCOL,
        DELEGATION_GRANT,
        actor,
        created_at,
        nonce,
        payload,
    )
}

pub fn delegation_revoke_event(
    actor: AgentId,
    created_at: i64,
    nonce: u64,
    payload: DelegationRevokePayload,
) -> Event<DelegationRevokePayload> {
    Event::new(
        PROTOCOL,
        DELEGATION_REVOKE,
        actor,
        created_at,
        nonce,
        payload,
    )
}

pub fn validate_principal_document(document: &PrincipalDocument) -> Result<()> {
    validate_https_url(&document.id, "principal.id")?;
    if document.controllers.is_empty() {
        return Err(SdkError::InvalidPayload(
            "principal document controllers must be non-empty".to_owned(),
        ));
    }
    for controller in &document.controllers {
        controller.public_key_bytes()?;
    }
    if let Some(url) = &document.delegations_url {
        validate_https_url(url, "delegations_url")?;
    }
    Ok(())
}

pub fn validate_delegation_grant_payload(
    payload: &DelegationGrantPayload,
    created_at: Option<i64>,
) -> Result<()> {
    validate_non_empty(&payload.id, "payload.id")?;
    validate_principal_descriptor(&payload.principal)?;
    payload.subject.public_key_bytes()?;
    if payload.scopes.is_empty() || payload.scopes.iter().any(|scope| scope.trim().is_empty()) {
        return Err(SdkError::InvalidPayload(
            "delegation scopes must be non-empty".to_owned(),
        ));
    }
    if let Some(expires_at) = payload.expires_at {
        let not_before = payload.not_before.or(created_at);
        if not_before
            .map(|not_before| expires_at <= not_before)
            .unwrap_or(false)
        {
            return Err(SdkError::InvalidPayload(
                "expires_at must be greater than not_before or created_at".to_owned(),
            ));
        }
    }
    Ok(())
}

pub fn validate_delegation_revoke_payload(payload: &DelegationRevokePayload) -> Result<()> {
    validate_non_empty(&payload.id, "payload.id")?;
    validate_https_url(&payload.principal_id, "principal_id")
}

pub fn validate_delegation_envelope(envelope: &Envelope<DelegationPayload>) -> Result<()> {
    verify_envelope(envelope)?;
    if envelope.event.protocol != PROTOCOL {
        return Err(SdkError::InvalidEventProtocol {
            expected: PROTOCOL.to_owned(),
            actual: envelope.event.protocol.clone(),
        });
    }
    match (&envelope.event.kind[..], &envelope.event.payload) {
        (DELEGATION_GRANT, DelegationPayload::Grant(payload)) => {
            validate_delegation_grant_payload(payload, Some(envelope.event.created_at))
        }
        (DELEGATION_REVOKE, DelegationPayload::Revoke(payload)) => {
            validate_delegation_revoke_payload(payload)
        }
        (DELEGATION_GRANT, _) | (DELEGATION_REVOKE, _) => Err(SdkError::InvalidPayload(
            "delegation event type does not match payload shape".to_owned(),
        )),
        _ => Err(SdkError::InvalidEventType {
            expected: format!("{DELEGATION_GRANT} or {DELEGATION_REVOKE}"),
            actual: envelope.event.kind.clone(),
        }),
    }
}

pub fn materialize_delegation_credential(
    envelope: &Envelope<DelegationGrantPayload>,
    status: DelegationStatus,
    status_url: Option<String>,
    updated_at: Option<i64>,
) -> Result<DelegationCredential> {
    verify_envelope(envelope)?;
    if envelope.event.protocol != PROTOCOL {
        return Err(SdkError::InvalidEventProtocol {
            expected: PROTOCOL.to_owned(),
            actual: envelope.event.protocol.clone(),
        });
    }
    if envelope.event.kind != DELEGATION_GRANT {
        return Err(SdkError::InvalidEventType {
            expected: DELEGATION_GRANT.to_owned(),
            actual: envelope.event.kind.clone(),
        });
    }
    validate_delegation_grant_payload(&envelope.event.payload, Some(envelope.event.created_at))?;
    let payload = &envelope.event.payload;
    Ok(DelegationCredential {
        id: payload.id.clone(),
        protocol: PROTOCOL.to_owned(),
        principal: payload.principal.clone(),
        controller: envelope.event.actor.clone(),
        subject: payload.subject.clone(),
        relationship: payload.relationship.clone(),
        scopes: payload.scopes.clone(),
        constraints: payload.constraints.clone(),
        not_before: payload.not_before,
        expires_at: payload.expires_at,
        status,
        status_url,
        updated_at: updated_at.unwrap_or(envelope.event.created_at),
        event_id: envelope.hash.clone(),
    })
}

fn validate_principal_descriptor(principal: &PrincipalDescriptor) -> Result<()> {
    validate_https_url(&principal.id, "principal.id")
}

fn validate_https_url(value: &str, field: &str) -> Result<()> {
    let parsed = Url::parse(value)
        .map_err(|_| SdkError::InvalidPayload(format!("{field} must be an HTTPS URL")))?;
    if parsed.scheme() == "https" && parsed.host_str().is_some() {
        Ok(())
    } else {
        Err(SdkError::InvalidPayload(format!(
            "{field} must be an HTTPS URL"
        )))
    }
}

fn validate_non_empty(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(SdkError::InvalidPayload(format!(
            "{field} must not be empty"
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentSigner;

    #[test]
    fn validates_and_materializes_grant() {
        let controller = AgentSigner::from_seed([31; 32]);
        let subject = AgentSigner::from_seed([32; 32]);
        let mut payload = DelegationGrantPayload::new(
            "del_01J8ZM7A3G2T9B4Q6X8R0N1P2Q",
            PrincipalDescriptor {
                id: "https://al.ink/yan".to_owned(),
                kind: Some("person".to_owned()),
                name: Some("Yan".to_owned()),
            },
            subject.agent_id(),
            vec!["inbox.screen".to_owned(), "meeting.propose".to_owned()],
        );
        payload.relationship = Some("primary_delegate".to_owned());
        payload.not_before = Some(1_779_753_600_000);
        payload.expires_at = Some(1_790_000_000_000);
        let envelope = controller
            .sign_event(delegation_grant_event(
                controller.agent_id(),
                1_779_753_600_000,
                1,
                payload,
            ))
            .unwrap();
        let envelope_value = serde_json::to_value(&envelope).unwrap();
        let envelope_for_validation: Envelope<DelegationPayload> =
            serde_json::from_value(envelope_value).unwrap();

        validate_delegation_envelope(&envelope_for_validation).unwrap();
        let credential = materialize_delegation_credential(
            &envelope,
            DelegationStatus::Active,
            Some("https://al.ink/v1/delegations/del/status".to_owned()),
            None,
        )
        .unwrap();

        assert_eq!(credential.protocol, PROTOCOL);
        assert_eq!(credential.controller, controller.agent_id());
        assert_eq!(credential.subject, subject.agent_id());
        assert_eq!(credential.event_id, envelope.hash);
    }

    #[test]
    fn validates_revoke_and_rejects_invalid_grants() {
        let controller = AgentSigner::from_seed([33; 32]);
        let envelope = controller
            .sign_event(delegation_revoke_event(
                controller.agent_id(),
                1_779_753_700_000,
                2,
                DelegationRevokePayload {
                    id: "del_01J8ZM7A3G2T9B4Q6X8R0N1P2Q".to_owned(),
                    principal_id: "https://al.ink/yan".to_owned(),
                    reason: Some("rotated_primary_agent".to_owned()),
                },
            ))
            .unwrap();
        let envelope: Envelope<DelegationPayload> =
            serde_json::from_value(serde_json::to_value(envelope).unwrap()).unwrap();
        validate_delegation_envelope(&envelope).unwrap();

        let invalid = DelegationGrantPayload::new(
            "del",
            PrincipalDescriptor::new("http://example.com"),
            controller.agent_id(),
            Vec::new(),
        );
        assert!(validate_delegation_grant_payload(&invalid, None).is_err());
    }

    #[test]
    fn validates_principal_document() {
        let controller = AgentSigner::from_seed([34; 32]);
        let document = PrincipalDocument {
            id: "https://profiles.example.com/org/acme".to_owned(),
            kind: None,
            name: None,
            description: None,
            avatar_url: None,
            links: Vec::new(),
            controllers: vec![controller.agent_id()],
            delegations_url: Some("https://profiles.example.com/v1/delegations/query".to_owned()),
            updated_at: None,
            extra: BTreeMap::new(),
        };
        validate_principal_document(&document).unwrap();

        let mut invalid = document;
        invalid.controllers.clear();
        assert!(validate_principal_document(&invalid).is_err());
    }

    #[test]
    fn rejects_malformed_https_like_urls() {
        let signer = AgentSigner::from_seed([35; 32]);
        for principal_id in ["https://", "https://[::1", "http://example.com"] {
            let payload = DelegationGrantPayload::new(
                "del",
                PrincipalDescriptor::new(principal_id),
                signer.agent_id(),
                vec!["scope".to_owned()],
            );
            assert!(validate_delegation_grant_payload(&payload, None).is_err());
        }
    }
}
