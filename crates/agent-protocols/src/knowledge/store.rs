use super::*;
use crate::identity::{LiveWriteOptions, MemoryNonceStore, NonceStore};

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

fn response_shape(response: &Value, definition: &str, origin: &str) -> Result<()> {
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
    let mut ids = BTreeSet::new();
    let mut sequences = BTreeSet::new();
    for item in arr(&response["result"]) {
        let record = if definition == "searchResponse" {
            &item["record"]
        } else {
            item
        };
        validate_knowledge_record(record, None)?;
        if !ids.insert(string(&record["envelope"]["hash"]))
            || !sequences.insert(record["seq"].knowledge_u64().unwrap())
            || record["seq"].knowledge_u64() > response["checkpoint"].knowledge_u64()
        {
            return Err(fail(
                "invalid_response",
                "duplicate event or sequence beyond checkpoint",
            ));
        }
    }
    Ok(())
}

pub fn validate_knowledge_query_response(
    response: &Value,
    request: &Value,
    origin: &str,
) -> Result<()> {
    validate_knowledge_query(request)?;
    response_shape(response, "queryResponse", origin)?;
    if arr(&response["result"]).len() > request["limit"].knowledge_u64().unwrap_or(100) as usize {
        return Err(fail("invalid_response", "query page exceeds limit"));
    }
    let mut last = 0;
    for record in arr(&response["result"]) {
        let seq = record["seq"].knowledge_u64().unwrap();
        if seq <= last || !knowledge_query_matches(&record["envelope"], request)? {
            return Err(fail("invalid_response", "query order or filters violated"));
        }
        last = seq;
    }
    Ok(())
}

pub fn validate_knowledge_changes_response(
    response: &Value,
    request: &Value,
    origin: &str,
) -> Result<()> {
    validate_knowledge_changes_request(request)?;
    // Changes requires checkpoint; service/as_of are optional extension fields.
    let records = response["result"]
        .as_array()
        .ok_or_else(|| fail("invalid_response", "changes result must be array"))?;
    let checkpoint = response["checkpoint"]
        .knowledge_u64()
        .filter(|n| *n <= identity::MAX_SAFE_NONCE)
        .ok_or_else(|| fail("invalid_response", "invalid checkpoint"))?;
    if response.get("service").is_some_and(|v| v != origin) {
        return Err(fail("invalid_response", "wrong service"));
    }
    if response
        .get("next_cursor")
        .is_some_and(|v| v.as_str().is_none_or(str::is_empty))
    {
        return Err(fail("invalid_response", "invalid cursor"));
    }
    let mut last = request["after"].knowledge_u64().unwrap_or(0);
    let mut ids = BTreeSet::new();
    if last > checkpoint || records.len() > request["limit"].knowledge_u64().unwrap_or(100) as usize
    {
        return Err(fail("invalid_response", "invalid changes range or limit"));
    }
    for record in records {
        validate_knowledge_record(record, None)?;
        let seq = record["seq"].knowledge_u64().unwrap();
        if seq <= last || seq > checkpoint || !ids.insert(string(&record["envelope"]["hash"])) {
            return Err(fail("invalid_response", "invalid changes ordering"));
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
    response_shape(response, "batchResponse", origin)?;
    let result: Vec<_> = arr(&response["result"])
        .iter()
        .map(|r| string(&r["envelope"]["hash"]).to_owned())
        .collect();
    let missing: Vec<_> = arr(&response["missing"])
        .iter()
        .map(|r| string(r).to_owned())
        .collect();
    let rset: BTreeSet<_> = result.iter().cloned().collect();
    let mset: BTreeSet<_> = missing.iter().cloned().collect();
    if !rset.is_disjoint(&mset)
        || rset.union(&mset).cloned().collect::<BTreeSet<_>>()
            != requested.iter().cloned().collect()
        || result
            != requested
                .iter()
                .filter(|id| rset.contains(*id))
                .cloned()
                .collect::<Vec<_>>()
        || missing
            != requested
                .iter()
                .filter(|id| mset.contains(*id))
                .cloned()
                .collect::<Vec<_>>()
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
    validate_knowledge_search_request(
        request,
        &["lexical".into(), "semantic".into(), "hybrid".into()],
    )?;
    response_shape(response, "searchResponse", origin)?;
    if response["ranking"]["mode"] != request["mode"]
        || arr(&response["result"]).len() > request["limit"].knowledge_u64().unwrap_or(20) as usize
    {
        return Err(fail("invalid_response", "search mode or limit changed"));
    }
    let mut last = 0;
    for hit in arr(&response["result"]) {
        let rank = hit["rank"].knowledge_u64().unwrap();
        let item = &hit["record"]["envelope"];
        if rank <= last
            || !knowledge_query_matches(item, request.get("filters").unwrap_or(&json!({})))?
            || (request["mode"] == "lexical"
                && !knowledge_text_matches(item, string(&request["text"]))?)
        {
            return Err(fail(
                "invalid_response",
                "search order, exact filters, or lexical predicate violated",
            ));
        }
        last = rank;
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
        let mut languages = BTreeSet::new();
        for language in arr(&document["collection_scope"]["languages"]) {
            if !languages.insert(string(language).to_ascii_lowercase()) {
                return Err(fail("invalid_discovery", "duplicate language hint"));
            }
        }
        for profile in arr(&document["collection_scope"]["profiles"]) {
            validate_knowledge_digest(string(profile))?;
        }
        Ok(())
    })()
    .map_err(|e| fail("invalid_discovery", e.to_string()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KnowledgeReadOperation {
    Query,
    Search,
    Changes,
}
fn binding(request: &Value, operation: KnowledgeReadOperation) -> Value {
    let mut value = normalized_json(request);
    let obj = value.as_object_mut().unwrap();
    obj.remove("cursor");
    obj.entry("limit")
        .or_insert(json!(if operation == KnowledgeReadOperation::Search {
            20
        } else {
            100
        }));
    if operation == KnowledgeReadOperation::Search {
        obj.entry("filters").or_insert(json!({}));
    }
    if operation == KnowledgeReadOperation::Changes {
        obj.entry("after").or_insert(json!(0));
    }
    value
}

/// Stateful consumer-side verifier. Binds requests, cursors, frozen scope,
/// ranking/coverage, strict ordering, and IDs across an entire page sequence.
#[derive(Clone, Debug)]
pub struct KnowledgePageValidator {
    origin: String,
    operation: KnowledgeReadOperation,
    request: Value,
    metadata: Option<Value>,
    ids: BTreeSet<String>,
    sequences: BTreeSet<u64>,
    last: u64,
    next_cursor: Option<String>,
    started: bool,
}
impl KnowledgePageValidator {
    pub fn new(origin: &str, operation: KnowledgeReadOperation, request: &Value) -> Result<Self> {
        identity::validate_origin(origin)?;
        match operation {
            KnowledgeReadOperation::Query => validate_knowledge_query(request)?,
            KnowledgeReadOperation::Search => validate_knowledge_search_request(
                request,
                &["lexical".into(), "semantic".into(), "hybrid".into()],
            )?,
            KnowledgeReadOperation::Changes => validate_knowledge_changes_request(request)?,
        }
        if request.get("cursor").is_some() {
            return Err(fail(
                "invalid_request",
                "page sequence must start without cursor",
            ));
        }
        Ok(Self {
            origin: origin.into(),
            operation,
            request: binding(request, operation),
            metadata: None,
            ids: BTreeSet::new(),
            sequences: BTreeSet::new(),
            last: 0,
            next_cursor: None,
            started: false,
        })
    }
    pub fn validate_page(&mut self, response: &Value, request: &Value) -> Result<()> {
        match self.operation {
            KnowledgeReadOperation::Query => validate_knowledge_query(request)?,
            KnowledgeReadOperation::Search => validate_knowledge_search_request(
                request,
                &["lexical".into(), "semantic".into(), "hybrid".into()],
            )?,
            KnowledgeReadOperation::Changes => validate_knowledge_changes_request(request)?,
        }
        if binding(request, self.operation) != self.request
            || (self.started
                && (self.next_cursor.is_none()
                    || request["cursor"].as_str() != self.next_cursor.as_deref()))
            || (!self.started && request.get("cursor").is_some())
        {
            return Err(fail("invalid_response", "request or continuation changed"));
        }
        match self.operation {
            KnowledgeReadOperation::Query => {
                validate_knowledge_query_response(response, request, &self.origin)?
            }
            KnowledgeReadOperation::Search => {
                validate_knowledge_search_response(response, request, &self.origin)?
            }
            KnowledgeReadOperation::Changes => {
                validate_knowledge_changes_response(response, request, &self.origin)?
            }
        }
        let mut metadata = json!({"checkpoint": response["checkpoint"]});
        if self.operation != KnowledgeReadOperation::Changes {
            metadata["service"] = response["service"].clone();
            metadata["as_of"] = response["as_of"].clone();
        }
        if self.operation == KnowledgeReadOperation::Search {
            metadata["ranking"] = response["ranking"].clone();
            metadata["coverage"] = response["coverage"].clone();
        }
        metadata = normalized_json(&metadata);
        if self.metadata.as_ref().is_some_and(|v| *v != metadata) {
            return Err(fail("invalid_response", "frozen scope or ranking changed"));
        }
        let mut ids = self.ids.clone();
        let mut sequences = self.sequences.clone();
        let mut last = self.last;
        for item in arr(&response["result"]) {
            let (record, order) = if self.operation == KnowledgeReadOperation::Search {
                (&item["record"], item["rank"].knowledge_u64().unwrap())
            } else {
                (item, item["seq"].knowledge_u64().unwrap())
            };
            if order <= last
                || !ids.insert(string(&record["envelope"]["hash"]).to_owned())
                || !sequences.insert(record["seq"].knowledge_u64().unwrap())
            {
                return Err(fail(
                    "invalid_response",
                    "duplicate or out-of-order result across pages",
                ));
            }
            last = order;
        }
        self.metadata = Some(metadata);
        self.ids = ids;
        self.sequences = sequences;
        self.last = last;
        self.started = true;
        self.next_cursor = response["next_cursor"].as_str().map(str::to_owned);
        Ok(())
    }
    pub fn is_complete(&self) -> bool {
        self.started && self.next_cursor.is_none()
    }
}

#[derive(Clone, Debug)]
struct Snapshot {
    expires_at: i64,
    binding: Value,
    operation: KnowledgeReadOperation,
    records: Vec<Value>,
    offset: usize,
    metadata: Value,
    ranking: Value,
    coverage: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KnowledgeAcceptanceMode {
    Live,
    Import,
}
#[derive(Clone, Debug, PartialEq)]
pub struct KnowledgeAcceptance {
    pub record: Value,
    pub resubmission: bool,
}

/// Single-process, in-memory reference repository. Mutations require `&mut self`;
/// integrate behind your application's lock/transaction and enforce local quotas.
/// It performs no fetching, persistence, HTTP serving, authorization or ranking.
/// Returned values are owned clones; callers cannot mutate accepted state.
#[derive(Clone, Debug)]
pub struct KnowledgeStore {
    origin: String,
    records: BTreeMap<String, Value>,
    retained: BTreeMap<String, Value>,
    nonces: MemoryNonceStore,
    seq: u64,
    snapshots: BTreeMap<String, Snapshot>,
    cursor_seq: u64,
    cursor_namespace: String,
    pub window_ms: i64,
    pub nonce_ttl_ms: i64,
    /// Bounded continuation retention; expiry may require restarting a query.
    pub max_snapshots: usize,
    pub snapshot_ttl_ms: i64,
}
impl KnowledgeStore {
    pub fn new(origin: impl Into<String>) -> Result<Self> {
        let origin = origin.into();
        identity::validate_origin(&origin)?;
        let mut namespace = [0u8; 16];
        rand::fill(&mut namespace);
        Ok(Self {
            origin,
            cursor_namespace: URL_SAFE_NO_PAD.encode(namespace),
            records: BTreeMap::new(),
            retained: BTreeMap::new(),
            nonces: MemoryNonceStore::new(),
            seq: 0,
            snapshots: BTreeMap::new(),
            cursor_seq: 0,
            window_ms: identity::DEFAULT_LIVE_WRITE_WINDOW_MS,
            nonce_ttl_ms: identity::DEFAULT_NONCE_TTL_MS,
            max_snapshots: 256,
            snapshot_ttl_ms: 300_000,
        })
    }
    pub fn checkpoint(&self) -> u64 {
        self.seq
    }
    pub fn visible_envelopes(&self) -> BTreeMap<String, Value> {
        self.retained.clone()
    }
    pub fn max_nonce(&self, actor: &AgentId, now: i64) -> Option<u64> {
        self.nonces.max_nonce(actor, now)
    }
    pub fn accept(
        &mut self,
        item: &Value,
        mode: KnowledgeAcceptanceMode,
        now: i64,
    ) -> Result<KnowledgeAcceptance> {
        let mut nonces = std::mem::take(&mut self.nonces);
        let result = self.accept_with_nonce_store(item, mode, now, &mut nonces);
        self.nonces = nonces;
        result
    }
    /// Supply the same nonce store used by other protocols at this origin.
    /// The caller must serialize this operation with their other acceptance
    /// transactions. Imports and failed/identical submissions do not touch it.
    pub fn accept_with_nonce_store<S: NonceStore>(
        &mut self,
        item: &Value,
        mode: KnowledgeAcceptanceMode,
        now: i64,
        nonces: &mut S,
    ) -> Result<KnowledgeAcceptance> {
        let envelope = validate_knowledge_envelope(item)?;
        if let Some(record) = self.records.get(&envelope.hash) {
            return Ok(KnowledgeAcceptance {
                record: record.clone(),
                resubmission: true,
            });
        }
        validate_knowledge_dependencies(item, &self.retained)?;
        if now < 0
            || now as u64 > identity::MAX_SAFE_NONCE
            || self.seq == identity::MAX_SAFE_NONCE
            || self.window_ms < 0
            || self.nonce_ttl_ms < self.window_ms.saturating_mul(2)
        {
            return Err(fail(
                "invalid_event",
                "invalid clock/window or exhausted sequence",
            ));
        }
        if mode == KnowledgeAcceptanceMode::Live {
            identity::verify_live_envelope(
                &envelope,
                &LiveWriteOptions {
                    now_ms: now,
                    window_ms: self.window_ms,
                    nonce_ttl_ms: self.nonce_ttl_ms,
                },
                nonces,
            )?;
        } else if envelope.event.created_at > now.saturating_add(self.window_ms) {
            return Err(SdkError::TimestampOutOfWindow);
        }
        self.seq += 1;
        let record = json!({"envelope": item, "seq": self.seq, "accepted_at": now});
        self.records.insert(envelope.hash.clone(), record.clone());
        self.retained.insert(envelope.hash, item.clone());
        Ok(KnowledgeAcceptance {
            record,
            resubmission: false,
        })
    }
    pub fn submit(&mut self, item: &Value, now: i64) -> Result<KnowledgeAcceptance> {
        self.accept(item, KnowledgeAcceptanceMode::Live, now)
    }
    pub fn import(&mut self, item: &Value, now: i64) -> Result<KnowledgeAcceptance> {
        self.accept(item, KnowledgeAcceptanceMode::Import, now)
    }
    pub fn hide(&mut self, hash: &str) {
        self.retained.remove(hash);
    }
    pub fn unhide(&mut self, hash: &str) -> Result<()> {
        let record = self
            .records
            .get(hash)
            .ok_or_else(|| fail("not_found", "no retained record"))?;
        self.retained
            .insert(hash.into(), record["envelope"].clone());
        Ok(())
    }
    pub fn prune(&mut self, hash: &str) {
        self.retained.remove(hash);
        self.records.remove(hash);
    }
    pub fn expire_cursors(&mut self) {
        self.snapshots.clear();
    }
    pub fn event(&self, hash: &str) -> Result<Value> {
        validate_knowledge_digest(hash).map_err(|e| fail("invalid_request", e.to_string()))?;
        if !self.retained.contains_key(hash) {
            return Err(fail("not_found", "event unavailable"));
        }
        Ok(self.records[hash].clone())
    }
    fn metadata(&self, now: i64) -> Value {
        json!({"service": self.origin, "checkpoint": self.seq, "as_of": now})
    }
    pub fn batch(&self, request: &Value, now: i64) -> Result<Value> {
        let hashes = validate_knowledge_batch_request(request)?;
        let mut result = Vec::new();
        let mut missing = Vec::new();
        for id in &hashes {
            if self.retained.contains_key(id) {
                result.push(self.records[id].clone());
            } else {
                missing.push(id.clone());
            }
        }
        let mut response = self.metadata(now);
        response["result"] = json!(result);
        response["missing"] = json!(missing);
        validate_knowledge_batch_response(&response, &hashes, &self.origin)?;
        Ok(response)
    }
    pub fn query(&mut self, request: &Value, now: i64) -> Result<Value> {
        self.query_available(request, now, true)
    }
    pub fn query_available(&mut self, request: &Value, now: i64, available: bool) -> Result<Value> {
        validate_knowledge_query(request)?;
        self.page(request, now, KnowledgeReadOperation::Query, None, available)
    }
    pub fn changes(&mut self, request: &Value, now: i64) -> Result<Value> {
        validate_knowledge_changes_request(request)?;
        self.page(request, now, KnowledgeReadOperation::Changes, None, true)
    }
    /// Caller supplies already selected candidate IDs, ranking configuration and
    /// honest coverage. Candidates are frozen; no embedding algorithm is implied.
    pub fn search(
        &mut self,
        request: &Value,
        candidates: &[String],
        ranking: &Value,
        coverage: &Value,
        modes: &[String],
        now: i64,
    ) -> Result<Value> {
        validate_knowledge_search_request(request, modes)?;
        self.page(
            request,
            now,
            KnowledgeReadOperation::Search,
            Some((candidates, ranking, coverage)),
            true,
        )
    }
    fn page(
        &mut self,
        request: &Value,
        now: i64,
        operation: KnowledgeReadOperation,
        search: Option<(&[String], &Value, &Value)>,
        available: bool,
    ) -> Result<Value> {
        if now < 0
            || now as u64 > identity::MAX_SAFE_NONCE
            || self.snapshot_ttl_ms <= 0
            || self.max_snapshots == 0
        {
            return Err(fail("invalid_request", "invalid clock or snapshot limits"));
        }
        self.snapshots
            .retain(|_, snapshot| snapshot.expires_at > now);
        let expected = binding(request, operation);
        let limit = expected["limit"].knowledge_u64().unwrap() as usize;
        let mut snapshot = if let Some(cursor) = request["cursor"].as_str() {
            let snapshot = self
                .snapshots
                .get(cursor)
                .ok_or_else(|| fail("invalid_cursor", "expired or unknown cursor"))?;
            if snapshot.operation != operation || snapshot.binding != expected {
                return Err(fail("invalid_cursor", "cursor bound to another request"));
            }
            snapshot.clone()
        } else {
            if !available {
                return Err(fail("query_unavailable", "exact enumeration unavailable"));
            }
            if operation == KnowledgeReadOperation::Changes
                && expected["after"].knowledge_u64().unwrap() > self.seq
            {
                return Err(fail("invalid_request", "after exceeds checkpoint"));
            }
            let empty = json!({});
            let filters = if operation == KnowledgeReadOperation::Search {
                &expected["filters"]
            } else if operation == KnowledgeReadOperation::Changes {
                &empty
            } else {
                request
            };
            let mut eligible = Vec::new();
            for (id, record) in &self.records {
                if self.retained.contains_key(id)
                    && knowledge_query_matches(&record["envelope"], filters)?
                    && (operation != KnowledgeReadOperation::Changes
                        || record["seq"].knowledge_u64() > expected["after"].knowledge_u64())
                    && (operation != KnowledgeReadOperation::Search
                        || request["mode"] != "lexical"
                        || knowledge_text_matches(&record["envelope"], string(&request["text"]))?)
                {
                    eligible.push(record.clone());
                }
            }
            eligible.sort_by_key(|r| r["seq"].knowledge_u64().unwrap());
            let (records, ranking, coverage) = if let Some((ids, ranking, coverage)) = search {
                let set: BTreeSet<_> = ids.iter().cloned().collect();
                let eligible_set: BTreeSet<_> = eligible
                    .iter()
                    .map(|r| string(&r["envelope"]["hash"]).to_owned())
                    .collect();
                if set.len() != ids.len()
                    || !set.is_subset(&eligible_set)
                    || (coverage["exhaustive"] == true && set != eligible_set)
                {
                    return Err(fail(
                        "invalid_response",
                        "candidates repeat, violate filters, or falsely claim completeness",
                    ));
                }
                (
                    ids.iter().map(|id| self.records[id].clone()).collect(),
                    ranking.clone(),
                    coverage.clone(),
                )
            } else {
                (eligible, Value::Null, Value::Null)
            };
            Snapshot {
                expires_at: now.saturating_add(self.snapshot_ttl_ms),
                binding: expected,
                operation,
                records,
                offset: 0,
                metadata: self.metadata(now),
                ranking,
                coverage,
            }
        };
        let mut response = snapshot.metadata.clone();
        let mut result = Vec::new();
        while snapshot.offset < snapshot.records.len() && result.len() < limit {
            let index = snapshot.offset;
            snapshot.offset += 1;
            let record = &snapshot.records[index];
            let id = string(&record["envelope"]["hash"]);
            // A fully pruned and reaccepted event is a new local record and must
            // not leak a historical receipt through the old frozen snapshot.
            if !self.retained.contains_key(id)
                || self
                    .records
                    .get(id)
                    .is_none_or(|r| r["seq"] != record["seq"])
            {
                continue;
            }
            result.push(if operation == KnowledgeReadOperation::Search { json!({"record": record, "rank": index + 1, "explanation": format!("Candidate selected under {}", string(&snapshot.ranking["id"]))}) } else { record.clone() });
        }
        response["result"] = json!(result);
        let more = snapshot.records[snapshot.offset..].iter().any(|r| {
            let id = string(&r["envelope"]["hash"]);
            self.retained.contains_key(id)
                && self
                    .records
                    .get(id)
                    .is_some_and(|current| current["seq"] == r["seq"])
        });
        if more {
            response["next_cursor"] =
                json!(format!("{}-{}", self.cursor_namespace, self.cursor_seq + 1));
        }
        if operation == KnowledgeReadOperation::Search {
            response["ranking"] = snapshot.ranking.clone();
            response["coverage"] = snapshot.coverage.clone();
        }
        match operation {
            KnowledgeReadOperation::Query => {
                validate_knowledge_query_response(&response, request, &self.origin)?
            }
            KnowledgeReadOperation::Search => {
                validate_knowledge_search_response(&response, request, &self.origin)?
            }
            KnowledgeReadOperation::Changes => {
                validate_knowledge_changes_response(&response, request, &self.origin)?
            }
        }
        if more {
            while self.snapshots.len() >= self.max_snapshots {
                let oldest = self
                    .snapshots
                    .iter()
                    .min_by_key(|(_, s)| s.expires_at)
                    .map(|(key, _)| key.clone())
                    .unwrap();
                self.snapshots.remove(&oldest);
            }
            self.cursor_seq += 1;
            self.snapshots
                .insert(string(&response["next_cursor"]).into(), snapshot);
        }
        Ok(response)
    }
}
