use super::*;
use std::sync::Arc;

/// Validate a service receipt and optionally bind it to the requested ID.
pub fn validate_knowledge_record(record: &Value, expected_hash: Option<&str>) -> Result<()> {
    validate_knowledge_schema(record, "acceptanceRecord")
        .map_err(|e| fail("invalid_response", e.to_string()))?;
    validate_knowledge_envelope(&record["envelope"])
        .map_err(|e| fail("invalid_response", e.to_string()))?;
    if expected_hash.is_some_and(|id| id != string(&record["envelope"]["hash"])) {
        return Err(fail("invalid_response", "returned wrong event ID"));
    }
    Ok(())
}

fn response_records<'a>(
    response: &'a Value,
    definition: &str,
    origin: &str,
) -> Result<Vec<&'a Value>> {
    validate_knowledge_schema(response, definition)
        .map_err(|e| fail("invalid_response", e.to_string()))?;
    identity::validate_origin(string(&response["service"]))
        .map_err(|e| fail("invalid_response", e.to_string()))?;
    if response["service"] != origin {
        return Err(fail(
            "invalid_response",
            "response service differs from receiving origin",
        ));
    }
    let records: Vec<&Value> = arr(&response["result"])
        .iter()
        .map(|item| {
            if definition == "searchResponse" {
                &item["record"]
            } else {
                item
            }
        })
        .collect();
    let mut ids = BTreeSet::new();
    for record in &records {
        if !ids.insert(string(&record["envelope"]["hash"]))
            || record["seq"].knowledge_u64() > response["checkpoint"].knowledge_u64()
        {
            return Err(fail(
                "invalid_response",
                "duplicate event or record beyond checkpoint",
            ));
        }
        validate_knowledge_record(record, None)?;
    }
    Ok(records)
}

pub fn validate_knowledge_query_response(
    response: &Value,
    request: &Value,
    origin: &str,
) -> Result<()> {
    validate_knowledge_query(request)?;
    let records = response_records(response, "queryResponse", origin)?;
    if records.len() > request["limit"].knowledge_u64().unwrap_or(100) as usize {
        return Err(fail("invalid_response", "query page exceeds limit"));
    }
    let mut last = request["after_seq"].knowledge_u64().unwrap_or(0);
    for record in records {
        let seq = record["seq"].knowledge_u64().unwrap_or(0);
        if seq <= last || !knowledge_query_matches(&record["envelope"], request)? {
            return Err(fail("invalid_response", "query order or filters violated"));
        }
        last = seq;
    }
    Ok(())
}

pub fn validate_knowledge_batch_response(
    response: &Value,
    requested: &[String],
    origin: &str,
) -> Result<()> {
    validate_knowledge_batch_request(&json!({"hashes": requested}))?;
    let result: Vec<_> = response_records(response, "batchResponse", origin)?
        .iter()
        .map(|r| string(&r["envelope"]["hash"]).to_owned())
        .collect();
    let missing: Vec<_> = arr(&response["missing"])
        .iter()
        .map(|r| string(r).to_owned())
        .collect();
    let rset: BTreeSet<_> = result.iter().cloned().collect();
    let mset: BTreeSet<_> = missing.iter().cloned().collect();
    let ordered = |set: &BTreeSet<String>| -> Vec<String> {
        requested
            .iter()
            .filter(|id| set.contains(*id))
            .cloned()
            .collect()
    };
    if !rset.is_disjoint(&mset)
        || rset.union(&mset).cloned().collect::<BTreeSet<_>>()
            != requested.iter().cloned().collect()
        || result != ordered(&rset)
        || missing != ordered(&mset)
    {
        return Err(fail(
            "invalid_response",
            "batch is not an ordered complete partition",
        ));
    }
    Ok(())
}

pub fn validate_knowledge_search_response(
    response: &Value,
    request: &Value,
    origin: &str,
) -> Result<()> {
    validate_knowledge_search_request(request, &SEARCH_MODES.map(String::from))?;
    let records = response_records(response, "searchResponse", origin)?;
    if response["ranking"]["mode"] != request["mode"]
        || records.len() > request["limit"].knowledge_u64().unwrap_or(20) as usize
    {
        return Err(fail("invalid_response", "search mode or limit changed"));
    }
    let empty = json!({});
    for record in records {
        let item = &record["envelope"];
        if !knowledge_query_matches(item, request.get("filters").unwrap_or(&empty))?
            || (request["mode"] == "lexical"
                && !knowledge_text_matches(item, string(&request["text"]))?)
        {
            return Err(fail(
                "invalid_response",
                "search violated exact filters or lexical text",
            ));
        }
    }
    Ok(())
}

pub fn validate_knowledge_discovery(document: &Value, origin: &str) -> Result<()> {
    (|| -> Result<()> {
        validate_knowledge_schema(document, "discoveryDocument")?;
        identity::validate_origin(origin)?;
        identity::validate_origin(string(&document["service"]))?;
        if document["service"] != origin {
            return Err(fail("invalid_discovery", "wrong serving origin"));
        }
        if let Some(endpoints) = document["endpoints"].as_object() {
            for endpoint in endpoints.values() {
                let url = https_url(string(endpoint))?;
                if url.query().is_some()
                    || url.fragment().is_some()
                    || url.origin().ascii_serialization() != origin
                {
                    return Err(fail(
                        "invalid_discovery",
                        "endpoint must use receiving origin without query or fragment",
                    ));
                }
            }
        }
        for peer in arr(&document["peers"]) {
            identity::validate_origin(string(peer))?;
            if *peer == origin {
                return Err(fail("invalid_discovery", "self peer"));
            }
        }
        Ok(())
    })()
    .map_err(|e| fail("invalid_discovery", e.to_string()))
}

/// Effective query for cursor binding: no cursor, defaults applied.
fn query_binding(request: &Value) -> Value {
    let mut value = normalized_json(request);
    let obj = value.as_object_mut().expect("validated query is an object");
    obj.remove("cursor");
    obj.entry("limit").or_insert(json!(100));
    obj.entry("after_seq").or_insert(json!(0));
    value
}

/// Verifies that query pages form one complete, consistent enumeration.
#[derive(Clone, Debug)]
pub struct KnowledgePageTracker {
    origin: String,
    binding: Option<Value>,
    scope: Option<Value>,
    seen: BTreeSet<String>,
    last: u64,
    next_cursor: Option<String>,
}
impl KnowledgePageTracker {
    pub fn new(origin: &str) -> Result<Self> {
        identity::validate_origin(origin)?;
        Ok(Self {
            origin: origin.into(),
            binding: None,
            scope: None,
            seen: BTreeSet::new(),
            last: 0,
            next_cursor: None,
        })
    }
    pub fn accept(&mut self, request: &Value, response: &Value) -> Result<()> {
        validate_knowledge_query_response(response, request, &self.origin)?;
        let binding = query_binding(request);
        let scope = normalized_json(&json!({
            "service": response["service"],
            "checkpoint": response["checkpoint"],
            "as_of": response["as_of"],
        }));
        let mut last = self.last;
        if self.binding.is_none() {
            if request.get("cursor").is_some() {
                return Err(fail(
                    "invalid_response",
                    "a traversal must start without a cursor",
                ));
            }
            last = binding["after_seq"].knowledge_u64().unwrap_or(0);
        } else if self.next_cursor.is_none()
            || request["cursor"].as_str() != self.next_cursor.as_deref()
            || self.binding.as_ref() != Some(&binding)
            || self.scope.as_ref() != Some(&scope)
        {
            return Err(fail(
                "invalid_response",
                "pagination request or checkpoint scope changed",
            ));
        }
        let records = arr(&response["result"]);
        if records
            .first()
            .is_some_and(|r| r["seq"].knowledge_u64().unwrap_or(0) <= last)
            || records
                .iter()
                .any(|r| self.seen.contains(string(&r["envelope"]["hash"])))
        {
            return Err(fail(
                "invalid_response",
                "pagination repeated an event or moved backwards",
            ));
        }
        self.seen.extend(
            records
                .iter()
                .map(|r| string(&r["envelope"]["hash"]).to_owned()),
        );
        if let Some(record) = records.last() {
            last = record["seq"].knowledge_u64().unwrap_or(last);
        }
        self.last = last;
        self.binding = Some(binding);
        self.scope = Some(scope);
        self.next_cursor = response["next_cursor"].as_str().map(str::to_owned);
        Ok(())
    }
    pub fn is_complete(&self) -> bool {
        self.binding.is_some() && self.next_cursor.is_none()
    }
    /// The next poll's `after_seq`, available only after every page was consumed.
    pub fn checkpoint(&self) -> Option<u64> {
        self.scope
            .as_ref()
            .filter(|_| self.is_complete())
            .and_then(|scope| scope["checkpoint"].knowledge_u64())
    }
}

/// Admission hook run for each new acceptance after all protocol checks.
pub type KnowledgeAdmission = Arc<dyn Fn(&Value) -> Result<()> + Send + Sync>;

/// Single-process, in-memory reference repository with checkpoint-bound,
/// stateless query cursors. Mutations require `&mut self`; integrate behind
/// your application's lock/transaction. It performs no fetching, persistence,
/// HTTP serving, authorization or ranking. Returned values are owned clones.
#[derive(Clone)]
pub struct KnowledgeStore {
    origin: String,
    records: BTreeMap<String, Value>,
    by_seq: BTreeMap<u64, String>,
    hidden: BTreeSet<String>,
    seq: u64,
    admit: Option<KnowledgeAdmission>,
    /// Allowance for `created_at` ahead of the clock; there is no lower bound.
    pub future_skew_ms: i64,
    pub max_envelope_bytes: usize,
}
impl std::fmt::Debug for KnowledgeStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KnowledgeStore")
            .field("origin", &self.origin)
            .field("records", &self.records)
            .field("hidden", &self.hidden)
            .field("seq", &self.seq)
            .field("future_skew_ms", &self.future_skew_ms)
            .field("max_envelope_bytes", &self.max_envelope_bytes)
            .finish_non_exhaustive()
    }
}
impl KnowledgeStore {
    pub fn new(origin: impl Into<String>) -> Result<Self> {
        let origin = origin.into();
        identity::validate_origin(&origin)?;
        Ok(Self {
            origin,
            records: BTreeMap::new(),
            by_seq: BTreeMap::new(),
            hidden: BTreeSet::new(),
            seq: 0,
            admit: None,
            future_skew_ms: DEFAULT_FUTURE_SKEW_MS,
            max_envelope_bytes: DEFAULT_MAX_ENVELOPE_BYTES,
        })
    }
    /// Refuse otherwise valid objects under local policy; return an error to refuse.
    pub fn set_admission(&mut self, admit: impl Fn(&Value) -> Result<()> + Send + Sync + 'static) {
        self.admit = Some(Arc::new(admit));
    }
    pub fn checkpoint(&self) -> u64 {
        self.seq
    }
    /// Publicly visible envelopes keyed by event ID.
    pub fn known_envelopes(&self) -> BTreeMap<String, Value> {
        self.records
            .iter()
            .filter(|(id, _)| !self.hidden.contains(*id))
            .map(|(id, record)| (id.clone(), record["envelope"].clone()))
            .collect()
    }
    /// Accept a signed event, or return the original record of an exact resubmission.
    pub fn submit(&mut self, item: &Value, now: i64) -> Result<Value> {
        let envelope = validate_knowledge_envelope(item)?;
        if let Some(record) = self.records.get(&envelope.hash) {
            return Ok(record.clone());
        }
        if now < 0 || now as u64 > identity::MAX_SAFE_NONCE || self.future_skew_ms < 0 {
            return Err(fail("invalid_request", "invalid clock or skew allowance"));
        }
        if envelope.event.created_at > now.saturating_add(self.future_skew_ms) {
            return Err(SdkError::TimestampOutOfWindow);
        }
        check_dependencies(item, |id| self.records.get(id).map(|r| &r["envelope"]))?;
        if serde_json::to_vec(item)?.len() > self.max_envelope_bytes {
            return Err(fail(
                "payload_too_large",
                "envelope exceeds configured byte limit",
            ));
        }
        if self.seq == identity::MAX_SAFE_NONCE {
            return Err(fail("permission_denied", "sequence space exhausted"));
        }
        if let Some(admit) = &self.admit {
            admit(item)?;
        }
        self.seq += 1;
        let record = json!({"envelope": item, "accepted_at": now, "seq": self.seq});
        self.records.insert(envelope.hash.clone(), record.clone());
        self.by_seq.insert(self.seq, envelope.hash);
        Ok(record)
    }
    pub fn event(&self, hash: &str) -> Result<Value> {
        validate_knowledge_id(hash).map_err(|e| fail("invalid_request", e.to_string()))?;
        if self.hidden.contains(hash) {
            return Err(fail("not_found", "event unavailable"));
        }
        self.records
            .get(hash)
            .cloned()
            .ok_or_else(|| fail("not_found", "event unavailable"))
    }
    /// Withhold from public reads; the record still answers exact retries and resolves dependencies.
    pub fn hide(&mut self, hash: &str) {
        if self.records.contains_key(hash) {
            self.hidden.insert(hash.into());
        }
    }
    pub fn unhide(&mut self, hash: &str) {
        self.hidden.remove(hash);
    }
    /// Drop content and record; the sequence high-water mark is preserved.
    pub fn prune(&mut self, hash: &str) {
        if let Some(record) = self.records.remove(hash) {
            self.by_seq
                .remove(&record["seq"].knowledge_u64().unwrap_or(0));
        }
        self.hidden.remove(hash);
    }
    fn scope(&self, checkpoint: u64, as_of: i64) -> Result<Value> {
        if as_of < 0 || as_of as u64 > identity::MAX_SAFE_NONCE {
            return Err(fail("invalid_request", "invalid service clock"));
        }
        Ok(json!({"service": self.origin, "checkpoint": checkpoint, "as_of": as_of}))
    }
    fn visible(&self, hash: &str) -> Option<&Value> {
        self.records
            .get(hash)
            .filter(|_| !self.hidden.contains(hash))
    }
    pub fn batch(&self, request: &Value, now: i64) -> Result<Value> {
        let hashes = validate_knowledge_batch_request(request)?;
        let mut result = Vec::new();
        let mut missing = Vec::new();
        for id in hashes {
            match self.visible(&id) {
                Some(record) => result.push(record.clone()),
                None => missing.push(id),
            }
        }
        let mut response = self.scope(self.seq, now)?;
        response["result"] = json!(result);
        response["missing"] = json!(missing);
        Ok(response)
    }
    pub fn query(&self, request: &Value, now: i64) -> Result<Value> {
        validate_knowledge_query(request)?;
        let binding = query_binding(request);
        let digest = sha3_id(&serde_jcs::to_vec(&binding)?);
        let after = binding["after_seq"].knowledge_u64().unwrap_or(0);
        let limit = binding["limit"].knowledge_u64().unwrap_or(100) as usize;
        let (checkpoint, as_of, last) = match request["cursor"].as_str() {
            Some(cursor) => self.decode_cursor(cursor, &digest, after)?,
            None if after > self.seq => {
                return Err(fail(
                    "invalid_request",
                    "after_seq is greater than the current checkpoint",
                ))
            }
            None => (self.seq, now, after),
        };
        let mut result: Vec<Value> = Vec::new();
        let mut next_cursor = None;
        // `last == checkpoint` is an empty poll; BTreeMap ranges panic when start > end.
        let range = if last < checkpoint {
            self.by_seq.range(last + 1..=checkpoint)
        } else {
            self.by_seq.range(0..0)
        };
        for hash in range.map(|(_, hash)| hash) {
            let Some(record) = self.visible(hash) else {
                continue;
            };
            if !knowledge_query_matches(&record["envelope"], request)? {
                continue;
            }
            if result.len() == limit {
                let returned = result
                    .last()
                    .and_then(|r| r["seq"].knowledge_u64())
                    .unwrap_or(last);
                next_cursor = Some(format!("{checkpoint}.{as_of}.{returned}.{digest}"));
                break;
            }
            result.push(record.clone());
        }
        let mut response = self.scope(checkpoint, as_of)?;
        response["result"] = json!(result);
        if let Some(cursor) = next_cursor {
            response["next_cursor"] = json!(cursor);
        }
        Ok(response)
    }
    fn decode_cursor(&self, cursor: &str, digest: &str, after: u64) -> Result<(u64, i64, u64)> {
        let invalid = || fail("invalid_cursor", "malformed, expired or mismatched cursor");
        let parts: Vec<&str> = cursor.split('.').collect();
        if parts.len() != 4
            || parts[3] != digest
            || parts[..3]
                .iter()
                .any(|p| p.is_empty() || p.len() > 16 || !p.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(invalid());
        }
        let number = |p: &str| p.parse::<u64>().map_err(|_| invalid());
        let (checkpoint, as_of, last) = (number(parts[0])?, number(parts[1])?, number(parts[2])?);
        if !(after <= last && last <= checkpoint && checkpoint <= self.seq)
            || as_of > identity::MAX_SAFE_NONCE
        {
            return Err(invalid());
        }
        Ok((checkpoint, as_of as i64, last))
    }
    /// Return one page of caller-ranked candidates; no ranking model is implied.
    /// Only a lexical page containing every match may claim exhaustive coverage.
    pub fn search(
        &self,
        request: &Value,
        selection: &KnowledgeSearchSelection,
        modes: &[String],
        now: i64,
    ) -> Result<Value> {
        validate_knowledge_search_request(request, modes)?;
        let limit = request["limit"].knowledge_u64().unwrap_or(20) as usize;
        let empty = json!({});
        let filters = request.get("filters").unwrap_or(&empty);
        let mut eligible = BTreeSet::new();
        for (hash, record) in &self.records {
            if !self.hidden.contains(hash)
                && knowledge_query_matches(&record["envelope"], filters)?
                && (request["mode"] != "lexical"
                    || knowledge_text_matches(&record["envelope"], string(&request["text"]))?)
            {
                eligible.insert(hash.as_str());
            }
        }
        let ids = &selection.candidates;
        let candidates: BTreeSet<&str> = ids.iter().map(String::as_str).collect();
        if candidates.len() != ids.len() || !candidates.is_subset(&eligible) {
            return Err(fail(
                "invalid_response",
                "candidates repeat or violate exact filters",
            ));
        }
        if selection.coverage["exhaustive"] == true && (candidates != eligible || ids.len() > limit)
        {
            return Err(fail("invalid_response", "false exhaustive coverage"));
        }
        let hits: Vec<Value> = ids
            .iter()
            .take(limit)
            .map(|id| {
                let explanation = selection.explanations.get(id).cloned().unwrap_or_else(|| {
                    format!(
                        "Selected by ranking configuration {}",
                        string(&selection.ranking["id"])
                    )
                });
                json!({"record": self.records[id], "explanation": explanation})
            })
            .collect();
        let mut response = self.scope(self.seq, now)?;
        response["result"] = json!(hits);
        response["ranking"] = selection.ranking.clone();
        response["coverage"] = selection.coverage.clone();
        validate_knowledge_schema(&response, "searchResponse")
            .map_err(|e| fail("invalid_response", e.to_string()))?;
        if response["ranking"]["mode"] != request["mode"] {
            return Err(fail(
                "invalid_response",
                "ranking mode differs from requested mode",
            ));
        }
        Ok(response)
    }
}
