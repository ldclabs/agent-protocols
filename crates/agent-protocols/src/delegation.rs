//! Agent Delegation Protocol 1.0 types and validation helpers.
//!
//! Delegation events are ordinary Agent Identity envelopes whose actor is a
//! controller key for an HTTPS principal document.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

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

/// Same type for active and retired bindings. Missing delegation means signing-only.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Controller {
    pub id: AgentId,
    pub source: String,
    pub valid_from: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(
        default,
        deserialize_with = "non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub delegation: Option<DelegationAuthority>,
    #[serde(
        default,
        deserialize_with = "non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub retired_at: Option<i64>,
    #[serde(
        default,
        deserialize_with = "non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub invalid_from: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum DelegationAuthority {
    /// Only the literal "*" is valid; validation rejects all other strings.
    Unrestricted(String),
    Restricted(DelegationPolicy),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DelegationPolicy {
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationAcceptance {
    pub event_id: String,
    pub accepted_at: i64,
}

fn non_null_option<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
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
    /// Other HTTPS URLs that lead to this principal. Aliases are not identities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<PrincipalLink>,
    pub protocol: String,
    pub controllers: Vec<Controller>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retired_controllers: Vec<Controller>,
    /// Delegation query endpoint for this principal; answers existence checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_query_url: Option<String>,
    pub updated_at: i64,
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
    pub audiences: Vec<String>,
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
        audiences: Vec<String>,
    ) -> Self {
        Self {
            id: id.into(),
            principal,
            subject,
            relationship: None,
            scopes,
            audiences,
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
    pub owner_controller: AgentId,
    pub grant_event_id: String,
    pub accepted_at: i64,
    pub subject: AgentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub constraints: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    pub status: DelegationStatus,
    pub updated_at: i64,
    pub event_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationStatusDocument {
    pub protocol: String,
    pub grant_event_id: String,
    pub accepted_at: i64,
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
    pub id: Option<String>,
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
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DelegationQueryResponse {
    pub result: Vec<DelegationSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DelegationEventsResponse {
    pub result: Vec<Envelope<DelegationPayload>>,
    pub acceptances: Vec<DelegationAcceptance>,
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

pub fn validate_controller(controller: &Controller, retired: bool) -> Result<()> {
    controller.id.public_key_bytes()?;
    if controller.source != "local" {
        validate_origin(&controller.source)?;
    }
    timestamp(controller.valid_from, "valid_from")?;
    if let Some(name) = &controller.name {
        validate_non_empty(name, "name")?;
    }
    match &controller.delegation {
        Some(DelegationAuthority::Unrestricted(value)) if value != "*" => {
            return fail("invalid delegation policy")
        }
        Some(DelegationAuthority::Restricted(policy)) => {
            strings(&policy.scopes, "scopes", false)?;
            strings(&policy.audiences, "audiences", false)?;
            for origin in &policy.audiences {
                validate_origin(origin)?;
            }
        }
        _ => {}
    }
    if retired {
        let end = controller
            .retired_at
            .ok_or_else(|| SdkError::InvalidPayload("retired_at required".into()))?;
        timestamp(end, "retired_at")?;
        if end < controller.valid_from {
            return fail("retired_at precedes valid_from");
        }
        if let Some(cutoff) = controller.invalid_from {
            timestamp(cutoff, "invalid_from")?;
            if cutoff < controller.valid_from || cutoff > end {
                return fail("invalid compromise interval");
            }
        }
    } else if controller.retired_at.is_some() || controller.invalid_from.is_some() {
        return fail("current controller has retirement fields");
    }
    Ok(())
}

pub fn validate_principal_document(document: &PrincipalDocument) -> Result<()> {
    validate_https_url(&document.id, "principal.id")?;
    if document.protocol != PROTOCOL {
        return fail("invalid principal protocol");
    }
    timestamp(document.updated_at, "updated_at")?;
    let mut seen = BTreeSet::new();
    for (records, retired) in [
        (&document.controllers, false),
        (&document.retired_controllers, true),
    ] {
        for record in records {
            validate_controller(record, retired)?;
            if !seen.insert(record.id.to_string()) {
                return fail("duplicate controller key");
            }
            if record.valid_from > document.updated_at
                || record.retired_at.is_some_and(|v| v > document.updated_at)
            {
                return fail("controller timestamp exceeds document update");
            }
        }
    }
    strings(&document.aliases, "aliases", true)?;
    for alias in &document.aliases {
        validate_https_url(alias, "alias")?;
    }
    if let Some(url) = &document.avatar_url {
        validate_https_url(url, "avatar_url")?;
    }
    if let Some(url) = &document.delegation_query_url {
        validate_https_url(url, "delegation_query_url")?;
    }
    Ok(())
}

/// Checks the authoritative-read rule of Agent Delegation Section 3: a
/// principal document binds controller keys only when it is read at its own
/// `id`. A document served anywhere else is a copy; its `controllers` must be
/// discarded and `document.id` resolved instead.
pub fn validate_principal_resolution(
    document: &PrincipalDocument,
    resolved_url: &str,
) -> Result<()> {
    if document.id == resolved_url {
        Ok(())
    } else {
        Err(SdkError::InvalidPayload(format!(
            "principal document id {} was served at {resolved_url}",
            document.id
        )))
    }
}

/// Reports whether `url` is an alias the principal itself acknowledges. Any
/// origin can redirect to any principal, so an alias must not be shown as a
/// name for the principal unless it is listed here.
pub fn is_principal_alias(document: &PrincipalDocument, url: &str) -> bool {
    document.aliases.iter().any(|alias| alias == url)
}

pub fn validate_delegation_grant_payload(
    payload: &DelegationGrantPayload,
    created_at: Option<i64>,
) -> Result<()> {
    validate_delegation_id(&payload.id)?;
    validate_principal_descriptor(&payload.principal)?;
    payload.subject.public_key_bytes()?;
    strings(&payload.scopes, "scopes", false)?;
    strings(&payload.audiences, "audiences", false)?;
    for origin in &payload.audiences {
        validate_origin(origin)?;
    }
    if let Some(time) = created_at {
        timestamp(time, "created_at")?;
    }
    if let Some(time) = payload.not_before {
        timestamp(time, "not_before")?;
    }
    if let Some(time) = payload.expires_at {
        timestamp(time, "expires_at")?;
    }
    if let Some(expires_at) = payload.expires_at {
        if matches!(payload.not_before, Some(not_before) if expires_at <= not_before) {
            return Err(SdkError::InvalidPayload(
                "expires_at must be greater than not_before".to_owned(),
            ));
        }
        if matches!(created_at, Some(created_at) if expires_at <= created_at) {
            return Err(SdkError::InvalidPayload(
                "expires_at must be greater than created_at".to_owned(),
            ));
        }
    }
    Ok(())
}

/// A public delegation query is an existence check and must include both
/// `subject` and `principal_id`. Omitting either side makes it an enumeration
/// query, which services must authorize before answering; pass
/// `allow_enumeration` when building such an authorized request. `limit`
/// defaults to 20; services SHOULD cap it at 100.
pub fn validate_delegation_query_request(
    request: &DelegationQueryRequest,
    allow_enumeration: bool,
) -> Result<()> {
    if allow_enumeration {
        if request.subject.is_none() && request.principal_id.is_none() {
            return Err(SdkError::InvalidPayload(
                "query must include at least one of subject or principal_id".to_owned(),
            ));
        }
    } else if request.subject.is_none() || request.principal_id.is_none() {
        return Err(SdkError::InvalidPayload(
            "public query must include both subject and principal_id".to_owned(),
        ));
    }
    if let Some(subject) = &request.subject {
        subject.public_key_bytes()?;
    }
    if let Some(principal_id) = &request.principal_id {
        validate_https_url(principal_id, "principal_id")?;
    }
    if let Some(id) = &request.id {
        validate_delegation_id(id)?;
    }
    if matches!(request.limit, Some(0)) {
        return Err(SdkError::InvalidPayload(
            "limit must be a positive integer".to_owned(),
        ));
    }
    Ok(())
}

pub fn validate_delegation_revoke_payload(payload: &DelegationRevokePayload) -> Result<()> {
    validate_delegation_id(&payload.id)?;
    validate_https_url(&payload.principal_id, "principal_id")
}

pub fn validate_delegation_id(value: &str) -> Result<()> {
    validate_non_empty(value, "delegation id")?;
    if matches!(value, "." | "..") {
        return fail("delegation id cannot be a dot segment");
    }
    Ok(())
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

/// Materializes an already accepted event with trusted previous state and the
/// service's actual acceptance time. This helper does not authorize the event.
pub fn materialize_delegation_credential(
    envelope: &Envelope<DelegationPayload>,
    status: DelegationStatus,
    accepted_at: i64,
    previous: Option<&DelegationCredential>,
) -> Result<DelegationCredential> {
    validate_delegation_envelope(envelope)?;
    timestamp(accepted_at, "accepted_at")?;
    check_previous(&envelope.event, previous)?;
    if previous.is_some_and(|p| accepted_at < p.accepted_at) {
        return fail("acceptance order reversed");
    }
    match &envelope.event.payload {
        DelegationPayload::Revoke(_) => {
            let mut result = previous
                .ok_or_else(|| {
                    SdkError::InvalidPayload("revocation requires previous credential".into())
                })?
                .clone();
            result.controller = envelope.event.actor.clone();
            result.status = DelegationStatus::Revoked;
            result.event_id = envelope.hash.clone();
            result.accepted_at = accepted_at;
            result.updated_at = accepted_at;
            Ok(result)
        }
        DelegationPayload::Grant(payload) => {
            if payload.expires_at.is_some_and(|t| t <= accepted_at) {
                return fail("grant expired at acceptance");
            }
            Ok(DelegationCredential {
                id: payload.id.clone(),
                protocol: PROTOCOL.into(),
                principal: payload.principal.clone(),
                controller: envelope.event.actor.clone(),
                owner_controller: previous
                    .map(|p| p.owner_controller.clone())
                    .unwrap_or_else(|| envelope.event.actor.clone()),
                grant_event_id: envelope.hash.clone(),
                accepted_at,
                subject: payload.subject.clone(),
                relationship: payload.relationship.clone(),
                scopes: payload.scopes.clone(),
                audiences: payload.audiences.clone(),
                constraints: payload.constraints.clone(),
                not_before: payload.not_before,
                expires_at: payload.expires_at,
                status,
                updated_at: accepted_at,
                event_id: envelope.hash.clone(),
            })
        }
    }
}

/// Pre-signing policy check over trusted document/state. No signature, HTTP,
/// cache-age, live timestamp-window, or nonce verification is performed.
pub fn validate_delegation_event_authority(
    event: &Event<DelegationPayload>,
    document: &PrincipalDocument,
    accepted_at: i64,
    previous: Option<&DelegationCredential>,
) -> Result<()> {
    check_authority(event, document, accepted_at, previous, false)
}

/// Caller also enforces fresh HTTPS, live Identity replay rules, and atomic persistence.
pub fn validate_delegation_acceptance(
    envelope: &Envelope<DelegationPayload>,
    document: &PrincipalDocument,
    resolved_url: &str,
    accepted_at: i64,
    previous: Option<&DelegationCredential>,
) -> Result<()> {
    validate_delegation_envelope(envelope)?;
    validate_principal_resolution(document, resolved_url)?;
    check_authority(&envelope.event, document, accepted_at, previous, false)
}

/// Caller authenticates acceptance evidence and previous state. This checks the
/// evidence's hash binding and historical policy, not current status or application constraints.
pub fn validate_historical_delegation(
    envelope: &Envelope<DelegationPayload>,
    acceptance: &DelegationAcceptance,
    document: &PrincipalDocument,
    resolved_url: &str,
    previous: Option<&DelegationCredential>,
) -> Result<()> {
    validate_delegation_envelope(envelope)?;
    if acceptance.event_id != envelope.hash {
        return fail("acceptance hash mismatch");
    }
    validate_principal_resolution(document, resolved_url)?;
    check_authority(
        &envelope.event,
        document,
        acceptance.accepted_at,
        previous,
        true,
    )
}

/// Per-result check; caller authenticates the actor and resolves the document.
pub fn validate_controller_enumeration(
    document: &PrincipalDocument,
    actor: &AgentId,
    now: i64,
    owner: &AgentId,
) -> Result<()> {
    validate_principal_document(document)?;
    timestamp(now, "now")?;
    owner.public_key_bytes()?;
    let c = document
        .controllers
        .iter()
        .find(|c| &c.id == actor)
        .ok_or_else(|| SdkError::InvalidPayload("controller cannot enumerate".into()))?;
    if now < c.valid_from || c.delegation.is_none() {
        return fail("controller cannot enumerate");
    }
    if !unrestricted(c) && owner != actor {
        return fail("controller does not own credential");
    }
    Ok(())
}

/// Audience/status/time only, after signature/history checks. Caller still
/// authenticates the subject and enforces scopes and constraints.
pub fn validate_delegation_use(
    credential: &DelegationCredential,
    audience: &str,
    now: i64,
) -> Result<()> {
    validate_origin(audience)?;
    timestamp(now, "now")?;
    let payload = DelegationGrantPayload {
        id: credential.id.clone(),
        principal: credential.principal.clone(),
        subject: credential.subject.clone(),
        relationship: credential.relationship.clone(),
        scopes: credential.scopes.clone(),
        audiences: credential.audiences.clone(),
        constraints: credential.constraints.clone(),
        not_before: credential.not_before,
        expires_at: credential.expires_at,
    };
    validate_delegation_grant_payload(&payload, None)?;
    if credential.protocol != PROTOCOL
        || credential.status != DelegationStatus::Active
        || !credential.audiences.iter().any(|a| a == audience)
        || credential.not_before.is_some_and(|t| now < t)
        || credential.expires_at.is_some_and(|t| now >= t)
    {
        return fail("delegation is not usable");
    }
    Ok(())
}

fn event_identity(event: &Event<DelegationPayload>) -> (&str, &str) {
    match &event.payload {
        DelegationPayload::Grant(p) => (&p.id, &p.principal.id),
        DelegationPayload::Revoke(p) => (&p.id, &p.principal_id),
    }
}
fn check_previous(
    event: &Event<DelegationPayload>,
    previous: Option<&DelegationCredential>,
) -> Result<()> {
    let (id, principal) = event_identity(event);
    if let Some(previous) = previous {
        previous.owner_controller.public_key_bytes()?;
        timestamp(previous.accepted_at, "previous.accepted_at")?;
        if previous.id != id || previous.principal.id != principal || previous.protocol != PROTOCOL
        {
            return fail("previous credential identity mismatch");
        }
    } else if event.kind == DELEGATION_REVOKE {
        return fail("revocation requires previous credential");
    }
    Ok(())
}
fn unrestricted(c: &Controller) -> bool {
    matches!(&c.delegation, Some(DelegationAuthority::Unrestricted(v)) if v == "*")
}
fn check_authority(
    event: &Event<DelegationPayload>,
    document: &PrincipalDocument,
    accepted_at: i64,
    previous: Option<&DelegationCredential>,
    historical: bool,
) -> Result<()> {
    validate_principal_document(document)?;
    timestamp(accepted_at, "accepted_at")?;
    timestamp(event.created_at, "created_at")?;
    event.actor.public_key_bytes()?;
    if event.protocol != PROTOCOL {
        return fail("invalid event protocol");
    }
    match (&event.kind[..], &event.payload) {
        (DELEGATION_GRANT, DelegationPayload::Grant(p)) => {
            validate_delegation_grant_payload(p, Some(event.created_at))?
        }
        (DELEGATION_REVOKE, DelegationPayload::Revoke(p)) => validate_delegation_revoke_payload(p)?,
        _ => return fail("event type does not match payload"),
    }
    if event_identity(event).1 != document.id {
        return fail("principal mismatch");
    }
    let c = document
        .controllers
        .iter()
        .chain(document.retired_controllers.iter().filter(|_| historical))
        .find(|c| c.id == event.actor)
        .ok_or_else(|| SdkError::InvalidPayload("actor has no delegation authority".into()))?;
    if c.delegation.is_none() {
        return fail("actor has no delegation authority");
    }
    for time in [event.created_at, accepted_at] {
        if time < c.valid_from
            || c.retired_at.is_some_and(|t| time >= t)
            || c.invalid_from.is_some_and(|t| time >= t)
        {
            return fail("outside controller authority interval");
        }
    }
    check_previous(event, previous)?;
    if let Some(previous) = previous {
        if accepted_at < previous.accepted_at {
            return fail("acceptance order reversed");
        }
        if !unrestricted(c) && previous.owner_controller != event.actor {
            return fail("controller does not own credential");
        }
    }
    if let DelegationPayload::Grant(payload) = &event.payload {
        if payload.expires_at.is_some_and(|t| t <= accepted_at) {
            return fail("grant expired at acceptance");
        }
        if let Some(DelegationAuthority::Restricted(policy)) = &c.delegation {
            if payload.scopes.iter().any(|x| !policy.scopes.contains(x))
                || payload
                    .audiences
                    .iter()
                    .any(|x| !policy.audiences.contains(x))
            {
                return fail("grant exceeds controller delegation policy");
            }
        }
    }
    Ok(())
}
fn fail<T>(message: &str) -> Result<T> {
    Err(SdkError::InvalidPayload(message.into()))
}
fn timestamp(value: i64, field: &str) -> Result<()> {
    if !(0..=9_007_199_254_740_991).contains(&value) {
        return fail(&format!("{field} must be a non-negative safe integer"));
    }
    Ok(())
}
fn strings(values: &[String], field: &str, empty: bool) -> Result<()> {
    if !empty && values.is_empty() {
        return fail(&format!("{field} must be a non-empty array"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_non_empty(value, field)?;
        if value == "*" || !seen.insert(value) {
            return fail(&format!("{field} has wildcard or duplicates"));
        }
    }
    Ok(())
}
fn validate_origin(value: &str) -> Result<()> {
    validate_https_url(value, "origin")?;
    let url = Url::parse(value).map_err(|_| SdkError::InvalidPayload("invalid origin".into()))?;
    if url.origin().ascii_serialization() != value {
        return fail("origin must be a serialized HTTPS origin");
    }
    Ok(())
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
                id: "https://api.al.ink/d9c6a99cne5g00a6scn0".to_owned(),
                kind: Some("person".to_owned()),
                name: Some("Yan".to_owned()),
            },
            subject.agent_id(),
            vec!["inbox.screen".to_owned(), "meeting.propose".to_owned()],
            vec!["https://dmsg.net".to_owned()],
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
            &envelope_for_validation,
            DelegationStatus::Active,
            1_779_753_600_000,
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
                    principal_id: "https://api.al.ink/d9c6a99cne5g00a6scn0".to_owned(),
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
            vec!["https://dmsg.net".to_owned()],
        );
        assert!(validate_delegation_grant_payload(&invalid, None).is_err());
    }

    #[test]
    fn grant_expiry_checked_against_not_before_and_created_at() {
        let controller = AgentSigner::from_seed([36; 32]);
        let base = DelegationGrantPayload::new(
            "del_1",
            PrincipalDescriptor::new("https://api.al.ink/d9c6a99cne5g00a6scn0"),
            controller.agent_id(),
            vec!["inbox.screen".to_owned()],
            vec!["https://dmsg.net".to_owned()],
        );

        let mut same_as_not_before = base.clone();
        same_as_not_before.not_before = Some(2000);
        same_as_not_before.expires_at = Some(2000);
        assert!(validate_delegation_grant_payload(&same_as_not_before, Some(1000)).is_err());

        let mut before_created_at = base.clone();
        before_created_at.not_before = Some(500);
        before_created_at.expires_at = Some(800);
        assert!(validate_delegation_grant_payload(&before_created_at, Some(1000)).is_err());

        let mut valid = base;
        valid.not_before = Some(500);
        valid.expires_at = Some(1500);
        validate_delegation_grant_payload(&valid, Some(1000)).unwrap();
    }

    #[test]
    fn public_delegation_queries_carry_both_subject_and_principal() {
        let subject = AgentSigner::from_seed([37; 32]).agent_id();
        let principal_id = "https://api.al.ink/d9c6a99cne5g00a6scn0".to_owned();
        let public = DelegationQueryRequest {
            subject: Some(subject.clone()),
            principal_id: Some(principal_id.clone()),
            limit: Some(20),
            ..DelegationQueryRequest::default()
        };
        validate_delegation_query_request(&public, false).unwrap();

        // Enumerating one side is not a public query.
        for one_sided in [
            DelegationQueryRequest {
                subject: Some(subject.clone()),
                ..DelegationQueryRequest::default()
            },
            DelegationQueryRequest {
                principal_id: Some(principal_id),
                ..DelegationQueryRequest::default()
            },
        ] {
            assert!(validate_delegation_query_request(&one_sided, false).is_err());
            validate_delegation_query_request(&one_sided, true).unwrap();
        }

        assert!(
            validate_delegation_query_request(&DelegationQueryRequest::default(), true).is_err()
        );
        assert!(validate_delegation_query_request(
            &DelegationQueryRequest {
                limit: Some(0),
                ..public
            },
            false
        )
        .is_err());
    }

    #[test]
    fn principal_documents_bind_controllers_only_at_their_own_id() {
        let controller = AgentSigner::from_seed([38; 32]);
        let document = PrincipalDocument {
            id: "https://api.al.ink/d9c6a99cne5g00a6scn0".to_owned(),
            kind: None,
            name: None,
            description: None,
            avatar_url: None,
            aliases: vec!["https://al.ink/yan".to_owned()],
            links: Vec::new(),
            protocol: PROTOCOL.into(),
            retired_controllers: vec![],
            controllers: vec![Controller {
                id: controller.agent_id(),
                source: "local".into(),
                valid_from: 0,
                name: None,
                delegation: None,
                retired_at: None,
                invalid_from: None,
            }],
            delegation_query_url: None,
            updated_at: 1000,
            extra: BTreeMap::new(),
        };

        validate_principal_resolution(&document, "https://api.al.ink/d9c6a99cne5g00a6scn0")
            .unwrap();
        // A copy served away from its identifier carries no authority.
        assert!(
            validate_principal_resolution(&document, "https://impostor.example.com/yan").is_err()
        );

        assert!(is_principal_alias(&document, "https://al.ink/yan"));
        assert!(!is_principal_alias(
            &document,
            "https://impostor.example.com/yan"
        ));
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
            aliases: vec!["https://profiles.example.com/acme".to_owned()],
            links: Vec::new(),
            protocol: PROTOCOL.into(),
            retired_controllers: vec![],
            controllers: vec![Controller {
                id: controller.agent_id(),
                source: "local".into(),
                valid_from: 0,
                name: None,
                delegation: None,
                retired_at: None,
                invalid_from: None,
            }],
            delegation_query_url: Some(
                "https://profiles.example.com/v1/delegations/query".to_owned(),
            ),
            updated_at: 1000,
            extra: BTreeMap::new(),
        };
        validate_principal_document(&document).unwrap();

        let mut invalid = document;
        invalid.protocol = "old-draft".into();
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
                vec!["https://dmsg.net".to_owned()],
            );
            assert!(validate_delegation_grant_payload(&payload, None).is_err());
        }
    }
}
