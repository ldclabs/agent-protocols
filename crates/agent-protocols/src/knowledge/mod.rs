//! Agent Knowledge 1.0 signed contributions and discovery.
//!
//! JSON boundary APIs preserve complete signed values. Typed payloads preserve
//! absent versus explicitly empty optional fields; application data stays opaque.
//! Core validation never fetches URLs, executes procedures, or certifies truth.

mod store;
mod types;
pub use store::*;
pub use types::*;

use crate::identity::{self, AgentId, Envelope, Event};
use crate::{Result, SdkError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Serialize;
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};

pub const PROTOCOL: &str = "agent-knowledge/1.0";
pub const SCHEMA_JSON: &str = include_str!("schema.json");
pub const EVENT_TYPES: [&str; 3] = ["knowledge.publish", "knowledge.assess", "knowledge.retract"];
pub const KNOWLEDGE_ERROR_CODES: [&str; 6] = [
    "missing_dependency",
    "invalid_target",
    "invalid_cursor",
    "query_too_broad",
    "query_unavailable",
    "unsupported_search_mode",
];
pub(crate) fn fail(code: &'static str, message: impl Into<String>) -> SdkError {
    SdkError::protocol(code, message)
}
pub(crate) fn arr(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or(&[])
}
pub(crate) fn string(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

/// JSON Schema integers include 1.0. These accessors accept all safe integral
/// IEEE-754 representations without truncation or unchecked numeric casts.
pub(crate) trait KnowledgeInteger {
    fn knowledge_u64(&self) -> Option<u64>;
    fn knowledge_i64(&self) -> Option<i64>;
}
impl KnowledgeInteger for Value {
    fn knowledge_u64(&self) -> Option<u64> {
        self.as_u64()
            .filter(|n| *n <= identity::MAX_SAFE_NONCE)
            .or_else(|| {
                self.as_f64()
                    .filter(|n| {
                        n.is_finite()
                            && n.fract() == 0.0
                            && *n >= 0.0
                            && *n <= identity::MAX_SAFE_NONCE as f64
                    })
                    .map(|n| n as u64)
            })
    }
    fn knowledge_i64(&self) -> Option<i64> {
        self.as_i64()
            .filter(|n| n.unsigned_abs() <= identity::MAX_SAFE_NONCE)
            .or_else(|| {
                self.as_f64()
                    .filter(|n| {
                        n.is_finite()
                            && n.fract() == 0.0
                            && n.abs() <= identity::MAX_SAFE_NONCE as f64
                    })
                    .map(|n| n as i64)
            })
    }
}
pub(crate) fn normalized_json(value: &Value) -> Value {
    match value {
        Value::Number(_) => value
            .knowledge_i64()
            .map(Value::from)
            .unwrap_or_else(|| value.clone()),
        Value::Array(items) => Value::Array(items.iter().map(normalized_json).collect()),
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(k, v)| (k.clone(), normalized_json(v)))
                .collect(),
        ),
        _ => value.clone(),
    }
}

/// Validate a bundled structural definition. This does not establish semantics.
pub fn validate_knowledge_schema(value: &Value, definition: &str) -> Result<()> {
    static VALIDATORS: OnceLock<Mutex<BTreeMap<String, jsonschema::Validator>>> = OnceLock::new();
    let mut validators = VALIDATORS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| fail("invalid_event", "schema cache unavailable"))?;
    if !validators.contains_key(definition) {
        let schema: Value = serde_json::from_str(SCHEMA_JSON)?;
        if schema["$defs"].get(definition).is_none() {
            return Err(fail("invalid_event", "unknown schema definition"));
        }
        let validator = jsonschema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .should_validate_formats(true)
            .build(&json!({"$ref": format!("#/$defs/{definition}"), "$defs": schema["$defs"]}))
            .map_err(|e| fail("invalid_event", e.to_string()))?;
        validators.insert(definition.to_owned(), validator);
    }
    validators[definition]
        .validate(value)
        .map_err(|e| fail("invalid_event", e.to_string()))
}

/// Strict JSON parsing suitable for signed objects (duplicate members rejected).
pub fn parse_knowledge_envelope(text: &str) -> Result<Value> {
    let value = identity::parse_strict_json(text)?;
    validate_knowledge_envelope(&value)?;
    Ok(value)
}

pub fn parse_knowledge_read_json(text: &str) -> Result<Value> {
    identity::parse_strict_json(text).map_err(|e| fail("invalid_request", e.to_string()))
}

pub fn validate_knowledge_digest(value: &str) -> Result<()> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| fail("invalid_event", "invalid digest encoding"))?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(fail(
            "invalid_event",
            "digest must canonically encode 32 bytes",
        ));
    }
    Ok(())
}

pub(crate) fn https_url(value: &str) -> Result<url::Url> {
    let parsed = url::Url::parse(value).map_err(|_| fail("invalid_event", "invalid HTTPS URL"))?;
    let authority = value
        .strip_prefix("https://")
        .unwrap_or("")
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || authority.is_empty()
        || authority.contains('@')
        || value.contains('\\')
        || value.chars().any(|c| c <= ' ')
    {
        return Err(fail(
            "invalid_event",
            "URL must be absolute HTTPS with host and no userinfo",
        ));
    }
    Ok(parsed)
}

/// Validate structure, strict I-JSON, Identity hash/signature, URLs, timestamps,
/// canonical references and profile binding uniqueness. No dependency fetching.
pub fn validate_knowledge_envelope(value: &Value) -> Result<Envelope<Value>> {
    identity::parse_strict_json(&serde_json::to_string(value)?)?;
    validate_knowledge_schema(value, "signedEnvelope")?;
    let envelope: Envelope<Value> = serde_json::from_value(normalized_json(value))
        .map_err(|e| fail("invalid_event", e.to_string()))?;
    identity::verify_envelope(&envelope)?;
    validate_knowledge_digest(&envelope.hash)?;
    let p = &envelope.event.payload;
    https_url(string(&p["license"]))?;
    for evidence in arr(&p["evidence"]) {
        https_url(string(&evidence["url"]))?;
        if let Some(digest) = evidence.get("digest") {
            validate_knowledge_digest(string(digest))?;
        }
    }
    let mut profiles = BTreeSet::new();
    for binding in arr(&p["profiles"]) {
        https_url(string(&binding["profile"]["url"]))?;
        let digest = string(&binding["profile"]["digest"]);
        validate_knowledge_digest(digest)?;
        if !profiles.insert(digest) {
            return Err(fail("invalid_event", "duplicate profile digest"));
        }
    }
    for target in knowledge_dependencies(value) {
        validate_knowledge_digest(&target)?;
    }
    if p.get("learned_at")
        .and_then(KnowledgeInteger::knowledge_i64)
        .is_some_and(|t| t > envelope.event.created_at)
    {
        return Err(fail("invalid_event", "learned_at exceeds created_at"));
    }
    Ok(envelope)
}

/// Sorted, deduplicated direct dependencies. Call after common validation.
pub fn knowledge_dependencies(value: &Value) -> Vec<String> {
    let p = &value["event"]["payload"];
    if value["event"]["type"] == "knowledge.publish" {
        arr(&p["relations"])
            .iter()
            .map(|r| string(&r["target"]).to_owned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    } else {
        vec![string(&p["target"]).to_owned()]
    }
}

/// Unresolved IDs are available separately for HTTP `error.data.missing`.
pub fn missing_knowledge_dependencies(
    value: &Value,
    retained: &BTreeMap<String, Value>,
) -> Vec<String> {
    knowledge_dependencies(value)
        .into_iter()
        .filter(|id| !retained.contains_key(id))
        .collect()
}

/// Resolve references against locally retained, already validated envelopes.
pub fn validate_knowledge_dependencies(
    value: &Value,
    retained: &BTreeMap<String, Value>,
) -> Result<()> {
    validate_knowledge_envelope(value)?;
    let missing = missing_knowledge_dependencies(value, retained);
    if !missing.is_empty() {
        return Err(SdkError::protocol_with_data(
            "missing_dependency",
            "unresolved dependencies",
            json!({"missing": missing}),
        ));
    }
    let event = &value["event"];
    let links = if event["type"] == "knowledge.publish" {
        arr(&event["payload"]["relations"]).to_vec()
    } else {
        vec![json!({"relation": event["type"], "target": event["payload"]["target"]})]
    };
    for link in links {
        let original = &retained[string(&link["target"])];
        let checked = validate_knowledge_envelope(original)?;
        if checked.hash != string(&link["target"]) {
            return Err(fail(
                "invalid_target",
                "dependency map key does not match hash",
            ));
        }
        let target = &original["event"];
        let relation = string(&link["relation"]);
        let allowed = target["type"] == "knowledge.publish"
            || (relation == "knowledge.retract" && target["type"] == "knowledge.assess");
        if !allowed
            || (relation == "addresses" && target["payload"]["kind"] != "question")
            || (relation == "tests" && target["payload"]["kind"] != "hypothesis")
        {
            return Err(fail(
                "invalid_target",
                "wrong target type or contribution kind",
            ));
        }
        if matches!(relation, "supersedes" | "knowledge.retract")
            && (target["actor"] != event["actor"]
                || target["nonce"].knowledge_u64() >= event["nonce"].knowledge_u64())
        {
            return Err(fail(
                "invalid_target",
                "author must match and target nonce must be smaller",
            ));
        }
    }
    Ok(())
}

/// Deterministic known-set lifecycle view. Rejects unvalidated or open sets.
pub fn materialize_knowledge(retained: &BTreeMap<String, Value>) -> Result<Value> {
    for (id, item) in retained {
        if string(&item["hash"]) != id {
            return Err(fail("invalid_event", "known-set key differs from hash"));
        }
        validate_knowledge_dependencies(item, retained)?;
    }
    let withdrawn: BTreeSet<&str> = retained
        .values()
        .filter(|v| v["event"]["type"] == "knowledge.retract")
        .map(|v| string(&v["event"]["payload"]["target"]))
        .collect();
    let mut successors: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut assessments: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (id, item) in retained {
        let event = &item["event"];
        if event["type"] == "knowledge.publish" {
            for link in arr(&event["payload"]["relations"]) {
                if link["relation"] == "supersedes" {
                    successors
                        .entry(string(&link["target"]))
                        .or_default()
                        .insert(id);
                }
            }
        } else if event["type"] == "knowledge.assess" {
            assessments
                .entry(string(&event["payload"]["target"]))
                .or_default()
                .insert(id);
        }
    }
    let mut result = serde_json::Map::new();
    for (id, item) in retained {
        if item["event"]["type"] == "knowledge.retract" {
            continue;
        }
        let mut view =
            json!({"status": if withdrawn.contains(id.as_str()) { "retracted" } else { "active" }});
        if item["event"]["type"] == "knowledge.publish" {
            let reports = assessments.get(id.as_str()).cloned().unwrap_or_default();
            view["active_assessments"] = json!(reports
                .iter()
                .filter(|id| !withdrawn.contains(**id))
                .collect::<Vec<_>>());
            view["assessments"] = json!(reports);
            view["successors"] = json!(successors.get(id.as_str()).cloned().unwrap_or_default());
        }
        result.insert(id.clone(), view);
    }
    Ok(Value::Object(result))
}

pub fn knowledge_publish_event(
    actor: AgentId,
    created_at: i64,
    nonce: u64,
    payload: KnowledgePublishPayload,
) -> Event<KnowledgePublishPayload> {
    Event::new(PROTOCOL, EVENT_TYPES[0], actor, created_at, nonce, payload)
}
pub fn knowledge_assess_event(
    actor: AgentId,
    created_at: i64,
    nonce: u64,
    payload: KnowledgeAssessPayload,
) -> Event<KnowledgeAssessPayload> {
    Event::new(PROTOCOL, EVENT_TYPES[1], actor, created_at, nonce, payload)
}
pub fn knowledge_retract_event(
    actor: AgentId,
    created_at: i64,
    nonce: u64,
    payload: KnowledgeRetractPayload,
) -> Event<KnowledgeRetractPayload> {
    Event::new(PROTOCOL, EVENT_TYPES[2], actor, created_at, nonce, payload)
}

pub fn validate_typed_knowledge_envelope<P: Serialize>(envelope: &Envelope<P>) -> Result<()> {
    validate_knowledge_envelope(&serde_json::to_value(envelope)?).map(|_| ())
}

/// Digest verification over complete decoded representation bytes, never text.
pub fn verify_knowledge_evidence(
    digest: Option<&str>,
    bytes: Option<&[u8]>,
    fetched: bool,
    complete: bool,
) -> EvidenceStatus {
    let Some(digest) = digest.filter(|_| fetched) else {
        return EvidenceStatus::Unchecked;
    };
    let Some(bytes) = bytes.filter(|_| complete) else {
        return EvidenceStatus::Unavailable;
    };
    if URL_SAFE_NO_PAD.encode(Sha3_256::digest(bytes)) == digest {
        EvidenceStatus::Matched
    } else {
        EvidenceStatus::Mismatched
    }
}

/// Portable ASCII-only case folding; Unicode normalization is not performed.
pub fn knowledge_text_terms(text: &str, lexical: bool) -> Result<Vec<String>> {
    if !(1..=1024).contains(&text.chars().count()) {
        return Err(fail(
            "invalid_request",
            "text needs 1..1024 Unicode scalars",
        ));
    }
    let terms: Vec<_> = text
        .split(|c: char| matches!(c, '\u{9}'..='\u{d}' | ' '))
        .filter(|p| !p.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    if terms.is_empty() || (lexical && terms.len() > 16) {
        return Err(fail("invalid_request", "empty text or too many terms"));
    }
    Ok(terms)
}

pub fn knowledge_text_matches(item: &Value, text: &str) -> Result<bool> {
    let p = &item["event"]["payload"];
    let names: &[&str] = match string(&item["event"]["type"]) {
        "knowledge.publish" => &["title", "statement", "basis"],
        "knowledge.assess" => &["summary", "basis"],
        _ => &["reason"],
    };
    let mut fields: Vec<String> = names
        .iter()
        .map(|name| string(&p[*name]).to_ascii_lowercase())
        .collect();
    if let Some(context) = p["context"].as_object() {
        for value in context.values() {
            if let Some(s) = value.as_str() {
                fields.push(s.to_ascii_lowercase());
            } else {
                fields.extend(arr(value).iter().map(|v| string(v).to_ascii_lowercase()));
            }
        }
    }
    Ok(knowledge_text_terms(text, true)?
        .iter()
        .all(|term| fields.iter().any(|field| field.contains(term))))
}

pub fn validate_knowledge_filters(filters: &Value) -> Result<()> {
    validate_knowledge_schema(filters, "searchFilters")
        .map_err(|e| fail("invalid_request", e.to_string()))?;
    for key in ["actor", "target", "profile"] {
        if let Some(value) = filters.get(key) {
            validate_knowledge_digest(
                string(value)
                    .strip_prefix("did:agent:")
                    .unwrap_or(string(value)),
            )
            .map_err(|e| fail("invalid_request", e.to_string()))?;
        }
    }
    if let (Some(from), Some(before)) = (
        filters["created_from"].knowledge_u64(),
        filters["created_before"].knowledge_u64(),
    ) {
        if from >= before {
            return Err(fail("invalid_request", "empty time range"));
        }
    }
    Ok(())
}

pub fn validate_knowledge_query(request: &Value) -> Result<()> {
    validate_knowledge_schema(request, "queryRequest")
        .map_err(|e| fail("invalid_request", e.to_string()))?;
    let mut filters = request.clone();
    for key in ["q", "cursor", "limit"] {
        filters.as_object_mut().unwrap().remove(key);
    }
    validate_knowledge_filters(&filters)?;
    if let Some(q) = request.get("q") {
        knowledge_text_terms(string(q), true)?;
    }
    Ok(())
}

pub fn parse_knowledge_query(parameters: &[(String, String)]) -> Result<Value> {
    parse_parameters(parameters, false)
}
pub fn parse_knowledge_changes(parameters: &[(String, String)]) -> Result<Value> {
    parse_parameters(parameters, true)
}
fn parse_parameters(parameters: &[(String, String)], changes: bool) -> Result<Value> {
    let mut request = serde_json::Map::new();
    for (key, text) in parameters {
        if request.contains_key(key) {
            return Err(fail("invalid_request", "repeated parameter"));
        }
        let value = if matches!(
            key.as_str(),
            "created_from" | "created_before" | "limit" | "after"
        ) {
            if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                return Err(fail(
                    "invalid_request",
                    "integer parameters require decimal digits",
                ));
            }
            let digits = text.trim_start_matches('0');
            if digits.len() > 16 {
                return Err(fail("invalid_request", "integer exceeds safe range"));
            }
            json!(if digits.is_empty() {
                0
            } else {
                digits
                    .parse::<u64>()
                    .map_err(|_| fail("invalid_request", "invalid integer"))?
            })
        } else {
            json!(text)
        };
        request.insert(key.clone(), value);
    }
    let request = Value::Object(request);
    if changes {
        validate_knowledge_changes_request(&request)?;
    } else {
        validate_knowledge_query(&request)?;
    }
    Ok(request)
}

pub fn validate_knowledge_changes_request(request: &Value) -> Result<()> {
    let obj = request
        .as_object()
        .ok_or_else(|| fail("invalid_request", "changes request must be object"))?;
    if obj
        .keys()
        .any(|k| !["after", "limit", "cursor"].contains(&k.as_str()))
    {
        return Err(fail("invalid_request", "unknown changes parameter"));
    }
    if request.get("after").is_some_and(|v| {
        v.knowledge_u64()
            .is_none_or(|n| n > identity::MAX_SAFE_NONCE)
    }) || request
        .get("limit")
        .is_some_and(|v| v.knowledge_u64().is_none_or(|n| !(1..=1000).contains(&n)))
        || request
            .get("cursor")
            .is_some_and(|v| v.as_str().is_none_or(str::is_empty))
    {
        return Err(fail("invalid_request", "malformed changes parameter"));
    }
    Ok(())
}

pub fn knowledge_query_matches(item: &Value, filters: &Value) -> Result<bool> {
    let e = &item["event"];
    let p = &e["payload"];
    let publish = e["type"] == "knowledge.publish";
    for key in ["actor", "type"] {
        if filters.get(key).is_some_and(|v| *v != e[key]) {
            return Ok(false);
        }
    }
    if let Some(q) = filters.get("q") {
        if !knowledge_text_matches(item, string(q))? {
            return Ok(false);
        }
    }
    if let Some(v) = filters.get("language") {
        if !publish || !string(v).eq_ignore_ascii_case(string(&p["language"])) {
            return Ok(false);
        }
    }
    if let Some(v) = filters.get("verdict") {
        if e["type"] != "knowledge.assess" || *v != p["verdict"] {
            return Ok(false);
        }
    }
    if filters["created_from"]
        .knowledge_i64()
        .is_some_and(|v| e["created_at"].knowledge_i64().unwrap_or(0) < v)
        || filters["created_before"]
            .knowledge_i64()
            .is_some_and(|v| e["created_at"].knowledge_i64().unwrap_or(0) >= v)
    {
        return Ok(false);
    }
    if let Some(v) = filters.get("kind") {
        if !publish || *v != p["kind"] {
            return Ok(false);
        }
    }
    if let Some(v) = filters.get("tag") {
        if !publish || !arr(&p["tags"]).contains(v) {
            return Ok(false);
        }
    }
    if let Some(v) = filters.get("profile") {
        if !arr(&p["profiles"])
            .iter()
            .any(|b| b["profile"]["digest"] == *v)
        {
            return Ok(false);
        }
    }
    if let Some(v) = filters.get("relation") {
        if !publish
            || !arr(&p["relations"]).iter().any(|r| {
                r["relation"] == *v && filters.get("target").is_none_or(|t| *t == r["target"])
            })
        {
            return Ok(false);
        }
    } else if let Some(v) = filters.get("target") {
        if !knowledge_dependencies(item)
            .iter()
            .any(|id| id == string(v))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn validate_knowledge_search_request(request: &Value, modes: &[String]) -> Result<()> {
    identity::parse_strict_json(&serde_json::to_string(request)?)
        .map_err(|e| fail("invalid_request", e.to_string()))?;
    if let Some(mode) = request["mode"].as_str() {
        if !["lexical", "semantic", "hybrid"].contains(&mode) || !modes.iter().any(|m| m == mode) {
            return Err(fail(
                "unsupported_search_mode",
                "explicit mode is not supported",
            ));
        }
    }
    validate_knowledge_schema(request, "searchRequest")
        .map_err(|e| fail("invalid_request", e.to_string()))?;
    knowledge_text_terms(string(&request["text"]), request["mode"] == "lexical")?;
    validate_knowledge_filters(request.get("filters").unwrap_or(&json!({})))
}

pub fn validate_knowledge_batch_request(request: &Value) -> Result<Vec<String>> {
    validate_knowledge_schema(request, "batchRequest")
        .map_err(|e| fail("invalid_request", e.to_string()))?;
    arr(&request["hashes"])
        .iter()
        .map(|v| {
            validate_knowledge_digest(string(v))
                .map_err(|e| fail("invalid_request", e.to_string()))?;
            Ok(string(v).to_owned())
        })
        .collect()
}
