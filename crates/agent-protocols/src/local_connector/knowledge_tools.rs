//! Agent Knowledge tools (local connector Section 4.3): signing and
//! submitting events, verified reads, and the lifecycle status check.

use super::*;

use crate::identity::validate_origin;
use crate::knowledge::{
    validate_knowledge_envelope, validate_knowledge_id, KnowledgePageTracker, EVENT_TYPES,
    PROTOCOL as KNOWLEDGE_PROTOCOL,
};

const MAX_SERVICES: usize = 8;
/// Reverse-link query pages a status check reads before reporting `complete: false`.
const STATUS_MAX_PAGES: usize = 10;
const STATUS_PAGE_LIMIT: u64 = 1000;

impl LocalConnector {
    pub(super) async fn knowledge_submit(&mut self, input: KnowledgeSubmitInput) -> Result<Value> {
        if input.services.is_empty() || input.services.len() > MAX_SERVICES {
            return Err(SdkError::InvalidPayload(
                "services must name one to eight services".to_owned(),
            ));
        }
        let mut services: Vec<String> = Vec::new();
        for service in &input.services {
            let origin = self.knowledge_origin(service)?;
            if services.contains(&origin) {
                return Err(SdkError::InvalidPayload("duplicate service".to_owned()));
            }
            services.push(origin);
        }
        if !EVENT_TYPES.contains(&input.event_type.as_str()) {
            return Err(SdkError::InvalidPayload(format!(
                "unknown Knowledge event type: {}",
                input.event_type
            )));
        }
        let created_at = unix_ms();
        let event = Event::new(
            KNOWLEDGE_PROTOCOL,
            input.event_type,
            self.agent_id(),
            created_at,
            self.nonce_manager.next_nonce_at(created_at)?,
            input.payload,
        );
        let envelope = self.signer.sign_event(event)?;
        let value = serde_json::to_value(&envelope)?;
        // A malformed contribution fails here, before anything is disclosed.
        validate_knowledge_envelope(&value)?;
        let mut results = Vec::new();
        let mut first_error = None;
        let mut accepted = false;
        for service in services {
            let submitted = match self.knowledge(&service).await {
                Ok(client) => {
                    let jwt = self.request_jwt(&service)?;
                    client.submit(&value, Some(&jwt)).await
                }
                Err(error) => Err(error),
            };
            match submitted.and_then(|record| knowledge_item(&record)) {
                Ok(item) => {
                    accepted = true;
                    results.push(json!({ "service": service, "item": item }));
                }
                Err(error) => {
                    results.push(json!({ "service": service, "error": error_json(&error) }));
                    first_error.get_or_insert(error);
                }
            }
        }
        if let (false, Some(error)) = (accepted, first_error) {
            return Err(error);
        }
        Ok(json!({ "id": envelope.hash, "envelope": envelope, "results": results }))
    }

    pub(super) async fn knowledge_query(&mut self, input: KnowledgeQueryInput) -> Result<Value> {
        let client = self.knowledge(&input.service).await?;
        let response = client.query(&Value::Object(input.query)).await?;
        let mut result = scoped(&response, json!({ "items": knowledge_items(&response)? }));
        if let Some(cursor) = response.get("next_cursor") {
            result["next_cursor"] = cursor.clone();
        }
        Ok(result)
    }

    pub(super) async fn knowledge_get(&mut self, input: KnowledgeGetInput) -> Result<Value> {
        let client = self.knowledge(&input.service).await?;
        let response = client.batch(&json!({ "hashes": input.ids })).await?;
        Ok(scoped(
            &response,
            json!({ "items": knowledge_items(&response)?, "missing": response["missing"] }),
        ))
    }

    pub(super) async fn knowledge_search(&mut self, input: KnowledgeSearchInput) -> Result<Value> {
        let client = self.knowledge(&input.service).await?;
        let response = client.search(&Value::Object(input.request)).await?;
        let hits = response["result"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|hit| {
                let mut out = json!({ "item": knowledge_item(&hit["record"])? });
                if let Some(explanation) = hit.get("explanation") {
                    out["explanation"] = explanation.clone();
                }
                Ok(out)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(scoped(
            &response,
            json!({ "hits": hits, "ranking": response["ranking"], "coverage": response["coverage"] }),
        ))
    }

    /// The lifecycle check of Agent Knowledge Section 9.6 at one service: the
    /// event, then every page of `target={id}` within the page bound.
    pub(super) async fn knowledge_status(&mut self, input: KnowledgeStatusInput) -> Result<Value> {
        validate_knowledge_id(&input.id)
            .map_err(|error| SdkError::protocol("invalid_request", error.to_string()))?;
        let client = self.knowledge(&input.service).await?;
        let batch = client.batch(&json!({ "hashes": [&input.id] })).await?;
        let record = batch["result"]
            .as_array()
            .and_then(|records| records.first())
            .cloned()
            .ok_or_else(|| SdkError::protocol("not_found", "event not found at this service"))?;
        let target = &record["envelope"]["event"];

        let mut tracker = KnowledgePageTracker::new(&self.knowledge_origin(&input.service)?)?;
        let mut request = json!({ "target": &input.id, "limit": STATUS_PAGE_LIMIT });
        let mut links = Vec::new();
        let mut scope = None;
        for _ in 0..STATUS_MAX_PAGES {
            let page = client.query(&request).await?;
            tracker.accept(&request, &page)?;
            links.extend(page["result"].as_array().into_iter().flatten().cloned());
            let next_cursor = page["next_cursor"].clone();
            scope.get_or_insert(page);
            if tracker.is_complete() {
                break;
            }
            request["cursor"] = next_cursor;
        }
        let scope = scope.unwrap_or_default();

        // The service checked target rules; same-author and nonce rules are
        // rechecked here so a hostile service cannot withdraw another's event.
        let author = &target["actor"];
        let nonce = target["nonce"].as_u64().unwrap_or(u64::MAX);
        let later_by_author =
            |event: &Value| &event["actor"] == author && event["nonce"].as_u64() > Some(nonce);
        let (mut retractions, mut successors, mut assessments) =
            (Vec::new(), Vec::new(), Vec::new());
        for link in &links {
            let event = &link["envelope"]["event"];
            let id = link["envelope"]["hash"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let payload = &event["payload"];
            match event["type"].as_str() {
                Some("knowledge.retract")
                    if payload["target"] == input.id && later_by_author(event) =>
                {
                    retractions.push(id)
                }
                Some("knowledge.assess") if payload["target"] == input.id => assessments.push(id),
                Some("knowledge.publish")
                    if later_by_author(event)
                        && payload["relations"].as_array().is_some_and(|relations| {
                            relations.iter().any(|relation| {
                                relation["relation"] == "supersedes"
                                    && relation["target"] == input.id
                            })
                        }) =>
                {
                    successors.push(id)
                }
                _ => {}
            }
        }
        for ids in [&mut retractions, &mut successors, &mut assessments] {
            ids.sort();
            ids.dedup();
        }
        let complete = tracker.is_complete();
        let mut result = scoped(
            &scope,
            json!({
                "item": knowledge_item(&record)?,
                "complete": complete,
                "retractions": retractions,
                "successors": successors,
                "assessments": assessments
            }),
        );
        if complete {
            result["status"] = json!(if retractions.is_empty() {
                "active"
            } else {
                "retracted"
            });
        }
        Ok(result)
    }

    /// A service origin the operator allows.
    fn knowledge_origin(&self, service: &str) -> Result<String> {
        let origin = normalize_host(service);
        validate_origin(&origin)?;
        self.require_allowed_host(&origin)?;
        Ok(origin)
    }

    /// The service's client, built from its discovery document on first use.
    async fn knowledge(&self, service: &str) -> Result<KnowledgeClient> {
        let origin = self.knowledge_origin(service)?;
        let cached = self.discovery.knowledge().get(&origin).cloned();
        if let Some(client) = cached {
            return Ok(client);
        }
        let mut client = KnowledgeClient::with_client(&origin, self.http.clone())?;
        client.discover().await?;
        self.discovery.knowledge().insert(origin, client.clone());
        Ok(client)
    }
}

/// Flattens a verified acceptance record.
fn knowledge_item(record: &Value) -> Result<KnowledgeItem> {
    let envelope = &record["envelope"];
    let event = &envelope["event"];
    let missing = || SdkError::protocol("invalid_response", "malformed acceptance record");
    Ok(KnowledgeItem {
        id: envelope["hash"].as_str().ok_or_else(missing)?.to_owned(),
        event_type: event["type"].as_str().ok_or_else(missing)?.to_owned(),
        actor: serde_json::from_value(event["actor"].clone())?,
        created_at: event["created_at"].as_i64().ok_or_else(missing)?,
        seq: record["seq"].as_u64().ok_or_else(missing)?,
        accepted_at: record["accepted_at"].as_i64().ok_or_else(missing)?,
        payload: event["payload"].clone(),
    })
}

fn knowledge_items(response: &Value) -> Result<Vec<KnowledgeItem>> {
    response["result"]
        .as_array()
        .into_iter()
        .flatten()
        .map(knowledge_item)
        .collect()
}

/// Adds the service's `service`, `checkpoint`, and `as_of` scope to a result.
fn scoped(response: &Value, mut result: Value) -> Value {
    for key in ["service", "checkpoint", "as_of"] {
        result[key] = response[key].clone();
    }
    result
}

fn error_json(error: &SdkError) -> Value {
    let mut out = json!({
        "code": error_code(error),
        "message": error.to_string()
    });
    if let Some(data) = error.data() {
        out["data"] = data.clone();
    }
    out
}
