use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use crate::delegation::{
    validate_delegation_id, validate_delegation_query_request, validate_principal_document,
    validate_principal_resolution, DelegationCredential, DelegationEventsResponse,
    DelegationQueryRequest, DelegationQueryResponse, DelegationRecord, DelegationServiceDiscovery,
    DelegationServiceEndpoints, PrincipalDocument,
};
use crate::discourse::{
    AgentStatus, AgentStatusInput, AgentStatusListResponse, DiscourseProtocolDiscovery,
    RoomCreatePayload, RoomEventsResponse, RoomJoinPayload, RoomJoinRequest,
    RoomJoinRequestPayload, RoomLeavePayload, RoomResponse, ServerRecord,
};
use crate::error::Result;
use crate::error::SdkError;
use crate::identity::{AgentId, Envelope, ErrorResponse, ListResponse, MAX_NONCE_HEADER};
use crate::profile::{
    AgentProfile, ProfileBatchReadRequest, ProfileBatchReadResponse, ProfileEventsResponse,
    ProfileUpdatePayload,
};

/// Reads a JSON body, turning a non-2xx response into [`SdkError::HttpStatus`]
/// with the Agent Identity error code and `Max-Seen-Nonce` header when present.
async fn read_json<T: DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    if status.is_success() {
        return Ok(response.json().await?);
    }
    let max_seen_nonce = response
        .headers()
        .get(MAX_NONCE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = response.text().await.unwrap_or_default();
    let (code, data) = match serde_json::from_str::<ErrorResponse>(&body) {
        Ok(parsed) => (Some(parsed.error.code), parsed.error.data),
        Err(_) => (None, None),
    };
    Err(SdkError::HttpStatus {
        status: status.as_u16(),
        code,
        data,
        max_seen_nonce,
        body,
    })
}

async fn send_json<T: DeserializeOwned>(request: reqwest::RequestBuilder) -> Result<T> {
    read_json(request.send().await?).await
}

fn with_jwt(request: reqwest::RequestBuilder, jwt: Option<&str>) -> reqwest::RequestBuilder {
    match jwt {
        Some(jwt) => request.bearer_auth(jwt),
        None => request,
    }
}

fn join_url(base_url: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

#[derive(Clone, Debug)]
pub struct ProfileClient {
    base_url: String,
    inner: reqwest::Client,
}

impl ProfileClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_client(base_url, reqwest::Client::new())
    }

    pub fn with_client(base_url: impl Into<String>, inner: reqwest::Client) -> Self {
        Self {
            base_url: base_url.into(),
            inner,
        }
    }

    pub async fn get_profile(&self, agent_id: &AgentId) -> Result<AgentProfile> {
        send_json(
            self.inner
                .get(self.url(&format!("/v1/profiles/{agent_id}"))),
        )
        .await
    }

    pub async fn get_profiles(&self, agent_ids: &[AgentId]) -> Result<ProfileBatchReadResponse> {
        let request = ProfileBatchReadRequest {
            ids: agent_ids.to_vec(),
        };
        send_json(
            self.inner
                .post(self.url("/v1/profiles/batch"))
                .json(&request),
        )
        .await
    }

    pub async fn profile_events(
        &self,
        agent_id: &AgentId,
        limit: Option<usize>,
    ) -> Result<ProfileEventsResponse> {
        self.profile_events_page(agent_id, limit, None).await
    }

    pub async fn profile_events_page(
        &self,
        agent_id: &AgentId,
        limit: Option<usize>,
        cursor: Option<&str>,
    ) -> Result<ProfileEventsResponse> {
        let mut pairs = Vec::new();
        if let Some(limit) = limit {
            pairs.push(format!("limit={limit}"));
        }
        push_query_pair(&mut pairs, "cursor", cursor);
        let path = with_query(format!("/v1/profiles/{agent_id}/events"), &pairs);
        send_json(self.inner.get(self.url(&path))).await
    }

    pub async fn submit_profile_update(
        &self,
        envelope: &Envelope<ProfileUpdatePayload>,
    ) -> Result<AgentProfile> {
        send_json(self.inner.post(self.url("/v1/profiles")).json(envelope)).await
    }

    fn url(&self, path: &str) -> String {
        join_url(&self.base_url, path)
    }
}

#[derive(Clone, Debug)]
pub struct DiscourseClient {
    base_url: String,
    inner: reqwest::Client,
}

impl DiscourseClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_client(base_url, reqwest::Client::new())
    }

    pub fn with_client(base_url: impl Into<String>, inner: reqwest::Client) -> Self {
        Self {
            base_url: base_url.into(),
            inner,
        }
    }

    pub async fn protocol(&self) -> Result<DiscourseProtocolDiscovery> {
        send_json(self.inner.get(self.url("/.well-known/agent-discourse"))).await
    }

    pub async fn create_room(
        &self,
        envelope: &Envelope<RoomCreatePayload>,
    ) -> Result<RoomResponse> {
        send_json(self.inner.post(self.url("/v1/rooms")).json(envelope)).await
    }

    /// Submits a signed `room.join.request`; the signature authenticates the applicant.
    pub async fn request_join(
        &self,
        room_id: &str,
        envelope: &Envelope<RoomJoinRequestPayload>,
    ) -> Result<RoomJoinRequest> {
        send_json(
            self.inner
                .post(self.url(&format!("/v1/rooms/{room_id}/join-requests")))
                .json(envelope),
        )
        .await
    }

    pub async fn join_request(
        &self,
        room_id: &str,
        request_id: &str,
        jwt: &str,
    ) -> Result<RoomJoinRequest> {
        send_json(
            self.inner
                .get(self.url(&format!("/v1/rooms/{room_id}/join-requests/{request_id}")))
                .bearer_auth(jwt),
        )
        .await
    }

    pub async fn join_requests(
        &self,
        room_id: &str,
        jwt: &str,
        options: &JoinRequestsOptions,
    ) -> Result<ListResponse<RoomJoinRequest>> {
        let path = with_query(
            format!("/v1/rooms/{room_id}/join-requests"),
            &options.pairs(),
        );
        send_json(self.inner.get(self.url(&path)).bearer_auth(jwt)).await
    }

    pub async fn room(&self, room_id: &str, jwt: Option<&str>) -> Result<RoomResponse> {
        send_json(with_jwt(
            self.inner.get(self.url(&format!("/v1/rooms/{room_id}"))),
            jwt,
        ))
        .await
    }

    /// Public room discovery (ADP Section 17): `GET /v1/rooms` lists the
    /// public and restricted rooms of the host.
    pub async fn public_rooms(
        &self,
        options: &PublicRoomsOptions,
    ) -> Result<ListResponse<RoomResponse>> {
        let path = with_query("/v1/rooms".to_owned(), &options.pairs());
        send_json(self.inner.get(self.url(&path))).await
    }

    pub async fn my_rooms(&self, jwt: &str) -> Result<ListResponse<RoomResponse>> {
        self.my_rooms_with_options(jwt, &MyRoomsOptions::default())
            .await
    }

    pub async fn my_rooms_with_options(
        &self,
        jwt: &str,
        options: &MyRoomsOptions,
    ) -> Result<ListResponse<RoomResponse>> {
        let path = with_query("/v1/me/rooms".to_owned(), &options.pairs());
        send_json(self.inner.get(self.url(&path)).bearer_auth(jwt)).await
    }

    pub async fn join_room(
        &self,
        room_id: &str,
        envelope: &Envelope<RoomJoinPayload>,
    ) -> Result<ServerRecord<RoomJoinPayload>> {
        self.submit_typed(room_id, envelope).await
    }

    pub async fn leave_room(
        &self,
        room_id: &str,
        envelope: &Envelope<RoomLeavePayload>,
    ) -> Result<ServerRecord<RoomLeavePayload>> {
        self.submit_typed(room_id, envelope).await
    }

    pub async fn submit_event<P>(
        &self,
        room_id: &str,
        envelope: &Envelope<P>,
    ) -> Result<ServerRecord>
    where
        P: Serialize,
    {
        self.submit_typed(room_id, envelope).await
    }

    async fn submit_typed<P, R>(&self, room_id: &str, envelope: &Envelope<P>) -> Result<R>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        send_json(
            self.inner
                .post(self.url(&format!("/v1/rooms/{room_id}")))
                .json(envelope),
        )
        .await
    }

    pub async fn events(&self, room_id: &str) -> Result<RoomEventsResponse> {
        self.events_with_options(room_id, &RoomEventsOptions::default())
            .await
    }

    pub async fn events_with_options(
        &self,
        room_id: &str,
        options: &RoomEventsOptions,
    ) -> Result<RoomEventsResponse> {
        let path = with_query(format!("/v1/rooms/{room_id}/events"), &options.pairs());
        send_json(with_jwt(
            self.inner.get(self.url(&path)),
            options.jwt.as_deref(),
        ))
        .await
    }

    pub async fn agent_statuses(
        &self,
        room_id: &str,
        jwt: Option<&str>,
    ) -> Result<AgentStatusListResponse> {
        send_json(with_jwt(
            self.inner
                .get(self.url(&format!("/v1/rooms/{room_id}/agent-status"))),
            jwt,
        ))
        .await
    }

    pub async fn agent_status(
        &self,
        room_id: &str,
        agent_id: &AgentId,
        jwt: Option<&str>,
    ) -> Result<AgentStatus> {
        send_json(with_jwt(
            self.inner
                .get(self.url(&format!("/v1/rooms/{room_id}/agent-status/{agent_id}"))),
            jwt,
        ))
        .await
    }

    pub async fn set_agent_status(
        &self,
        room_id: &str,
        jwt: &str,
        status: &AgentStatusInput,
    ) -> Result<AgentStatus> {
        send_json(
            self.inner
                .put(self.url(&format!("/v1/rooms/{room_id}/agent-status")))
                .bearer_auth(jwt)
                .json(status),
        )
        .await
    }

    pub fn sse_events_url(&self, room_id: &str) -> String {
        sse_events_url(&self.base_url, room_id)
    }

    pub async fn archive(&self, room_id: &str) -> Result<Value> {
        send_json(
            self.inner
                .get(self.url(&format!("/v1/rooms/{room_id}/archive"))),
        )
        .await
    }

    fn url(&self, path: &str) -> String {
        join_url(&self.base_url, path)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RoomEventsOptions {
    pub after_seq: Option<u64>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
    pub jwt: Option<String>,
}

impl RoomEventsOptions {
    fn pairs(&self) -> Vec<String> {
        let mut pairs = Vec::new();
        if let Some(after_seq) = self.after_seq {
            pairs.push(format!("after_seq={after_seq}"));
        }
        if let Some(limit) = self.limit {
            pairs.push(format!("limit={limit}"));
        }
        push_query_pair(&mut pairs, "cursor", self.cursor.as_deref());
        pairs
    }
}

#[derive(Clone, Debug, Default)]
pub struct JoinRequestsOptions {
    pub status: Option<String>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

impl JoinRequestsOptions {
    fn pairs(&self) -> Vec<String> {
        let mut pairs = Vec::new();
        push_query_pair(&mut pairs, "status", self.status.as_deref());
        if let Some(limit) = self.limit {
            pairs.push(format!("limit={limit}"));
        }
        push_query_pair(&mut pairs, "cursor", self.cursor.as_deref());
        pairs
    }
}

/// Agent Delegation client. Without endpoints it uses the RECOMMENDED paths
/// under `base_url`; [`DelegationClient::discover`] reads the service's
/// discovery document instead, whose endpoints clients MUST prefer.
#[derive(Clone, Debug)]
pub struct DelegationClient {
    base_url: String,
    delegations_url: String,
    query_url: String,
    inner: reqwest::Client,
}

impl DelegationClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_client(base_url, https_redirect_client())
    }

    pub fn with_client(base_url: impl Into<String>, inner: reqwest::Client) -> Self {
        Self::with_endpoints(base_url, inner, &DelegationServiceEndpoints::default())
    }

    pub fn with_endpoints(
        base_url: impl Into<String>,
        inner: reqwest::Client,
        endpoints: &DelegationServiceEndpoints,
    ) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        let delegations_url = endpoints
            .delegations
            .clone()
            .unwrap_or_else(|| format!("{base_url}/v1/delegations"))
            .trim_end_matches('/')
            .to_owned();
        let query_url = endpoints
            .query
            .clone()
            .unwrap_or_else(|| format!("{delegations_url}/query"));
        Self {
            base_url,
            delegations_url,
            query_url,
            inner,
        }
    }

    /// Builds a client for the service at `origin` from its discovery
    /// document, falling back to the default paths when the service publishes none.
    pub async fn discover(origin: &str) -> Self {
        Self::discover_with_client(origin, https_redirect_client()).await
    }

    pub async fn discover_with_client(origin: &str, inner: reqwest::Client) -> Self {
        let base = origin.trim_end_matches('/');
        let discovered: Result<DelegationServiceDiscovery> =
            send_json(inner.get(format!("{base}/.well-known/agent-delegation"))).await;
        match discovered {
            Ok(discovery) => Self::with_endpoints(base, inner, &discovery.endpoints),
            // Discovery is optional; the default paths apply.
            Err(_) => Self::with_client(base, inner),
        }
    }

    pub async fn protocol(&self) -> Result<DelegationServiceDiscovery> {
        send_json(
            self.inner
                .get(format!("{}/.well-known/agent-delegation", self.base_url)),
        )
        .await
    }

    /// Resolves a principal document per Agent Delegation Section 3. A
    /// document is authoritative only when read at its own `id`, so one served
    /// elsewhere (an alias hosting a copy rather than redirecting) is discarded
    /// and `document.id` is resolved once more.
    pub async fn principal(&self, principal_url: Option<&str>) -> Result<PrincipalDocument> {
        let start = principal_url.unwrap_or(&self.base_url);
        let (first, resolved) = self.read_principal(start).await?;
        let id = first
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| SdkError::InvalidPayload("principal.id required".into()))?;
        let (value, resolved) = if id == resolved {
            (first, resolved)
        } else {
            self.read_principal(id).await?
        };
        let document: PrincipalDocument = serde_json::from_value(value)?;
        validate_principal_resolution(&document, &resolved)?;
        validate_principal_document(&document)?;
        Ok(document)
    }

    async fn read_principal(&self, url: &str) -> Result<(Value, String)> {
        let parsed = url::Url::parse(url)
            .map_err(|_| SdkError::InvalidPayload("invalid principal URL".into()))?;
        if parsed.scheme() != "https" {
            return Err(SdkError::InvalidPayload(
                "principal resolution requires HTTPS".into(),
            ));
        }
        let response = self
            .inner
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?;
        if response.url().scheme() != "https" {
            return Err(SdkError::InvalidPayload(
                "principal resolution requires HTTPS".into(),
            ));
        }
        let resolved = response.url().to_string();
        // A copy is parsed only for its canonical ID; its authority shape is irrelevant.
        Ok((read_json(response).await?, resolved))
    }

    pub async fn delegation(&self, delegation_id: &str) -> Result<DelegationCredential> {
        validate_delegation_id(delegation_id)?;
        send_json(
            self.inner
                .get(format!("{}/{delegation_id}", self.delegations_url)),
        )
        .await
    }

    pub async fn delegation_events(
        &self,
        delegation_id: &str,
        cursor: Option<&str>,
    ) -> Result<DelegationEventsResponse> {
        validate_delegation_id(delegation_id)?;
        let mut pairs = Vec::new();
        push_query_pair(&mut pairs, "cursor", cursor);
        let url = with_query(
            format!("{}/{delegation_id}/events", self.delegations_url),
            &pairs,
        );
        send_json(self.inner.get(url)).await
    }

    /// Every accepted record of a credential, following `next_cursor`.
    pub async fn all_delegation_events(
        &self,
        delegation_id: &str,
    ) -> Result<Vec<DelegationRecord>> {
        let mut records = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = self
                .delegation_events(delegation_id, cursor.as_deref())
                .await?;
            records.extend(page.result);
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => return Ok(records),
            }
        }
    }

    pub async fn submit_delegation_event<P>(
        &self,
        envelope: &Envelope<P>,
    ) -> Result<DelegationCredential>
    where
        P: Serialize,
    {
        send_json(self.inner.post(&self.delegations_url).json(envelope)).await
    }

    /// Public queries are existence checks and carry both `subject` and
    /// `principal_id`. Passing a request JWT authorizes an enumeration query,
    /// which a service must otherwise refuse.
    pub async fn query_delegations(
        &self,
        request: &DelegationQueryRequest,
        jwt: Option<&str>,
    ) -> Result<DelegationQueryResponse> {
        self.query_delegations_at(&self.query_url, request, jwt)
            .await
    }

    /// Queries the endpoint a principal document names in its
    /// `delegation_query_url`. That is how a relying party reaches the
    /// authoritative service for a principal without trusting a URL supplied
    /// by whoever presented the credential.
    pub async fn query_delegations_at(
        &self,
        query_url: &str,
        request: &DelegationQueryRequest,
        jwt: Option<&str>,
    ) -> Result<DelegationQueryResponse> {
        validate_delegation_query_request(request, jwt.is_some())?;
        send_json(with_jwt(self.inner.post(query_url).json(request), jwt)).await
    }
}

fn https_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.url().scheme() != "https" || attempt.previous().len() > 5 {
                attempt.error("principal redirect must use HTTPS with at most five hops")
            } else {
                attempt.follow()
            }
        }))
        .build()
        .expect("valid HTTPS redirect policy")
}

#[derive(Clone, Debug, Default)]
pub struct MyRoomsOptions {
    pub status: Option<String>,
    pub membership: Option<String>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

impl MyRoomsOptions {
    fn pairs(&self) -> Vec<String> {
        let mut pairs = Vec::new();
        push_query_pair(&mut pairs, "status", self.status.as_deref());
        push_query_pair(&mut pairs, "membership", self.membership.as_deref());
        if let Some(limit) = self.limit {
            pairs.push(format!("limit={limit}"));
        }
        push_query_pair(&mut pairs, "cursor", self.cursor.as_deref());
        pairs
    }
}

#[derive(Clone, Debug, Default)]
pub struct PublicRoomsOptions {
    pub status: Option<String>,
    pub tag: Option<String>,
    pub keyword: Option<String>,
    pub creator: Option<String>,
    pub starts_after: Option<i64>,
    pub ends_before: Option<i64>,
    pub language: Option<String>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

impl PublicRoomsOptions {
    fn pairs(&self) -> Vec<String> {
        let mut pairs = Vec::new();
        push_query_pair(&mut pairs, "status", self.status.as_deref());
        push_query_pair(&mut pairs, "tag", self.tag.as_deref());
        push_query_pair(&mut pairs, "keyword", self.keyword.as_deref());
        push_query_pair(&mut pairs, "creator", self.creator.as_deref());
        if let Some(starts_after) = self.starts_after {
            pairs.push(format!("starts_after={starts_after}"));
        }
        if let Some(ends_before) = self.ends_before {
            pairs.push(format!("ends_before={ends_before}"));
        }
        push_query_pair(&mut pairs, "language", self.language.as_deref());
        if let Some(limit) = self.limit {
            pairs.push(format!("limit={limit}"));
        }
        push_query_pair(&mut pairs, "cursor", self.cursor.as_deref());
        pairs
    }
}

pub fn sse_events_url(base_url: &str, room_id: &str) -> String {
    format!(
        "{}/v1/rooms/{}/events/live",
        base_url.trim_end_matches('/'),
        encode_query_component(room_id)
    )
}

fn with_query(path: String, pairs: &[String]) -> String {
    if pairs.is_empty() {
        path
    } else {
        format!("{path}?{}", pairs.join("&"))
    }
}

fn push_query_pair(pairs: &mut Vec<String>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        pairs.push(format!("{key}={}", encode_query_component(value)));
    }
}

fn encode_query_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

/// Public Knowledge discovery/retrieval and optionally authenticated submissions.
/// Default transport rejects all redirects, preventing cross-origin forwarding
/// of queries, envelopes, and bearer credentials. Custom transports supplied to
/// `with_client` must provide the same redirect policy; final origin is checked
/// as defense in depth, after the supplied transport has made its request.
#[derive(Clone, Debug)]
pub struct KnowledgeClient {
    origin: String,
    inner: reqwest::Client,
    discovery: Option<Value>,
}
impl KnowledgeClient {
    pub fn new(origin: impl Into<String>) -> Result<Self> {
        Self::with_client(
            origin,
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        )
    }
    pub fn with_client(origin: impl Into<String>, inner: reqwest::Client) -> Result<Self> {
        let origin = origin.into();
        crate::identity::validate_origin(&origin)?;
        Ok(Self {
            origin,
            inner,
            discovery: None,
        })
    }
    /// Install independently obtained discovery after origin/capability checks.
    pub fn set_discovery(&mut self, document: Value) -> Result<()> {
        crate::knowledge::validate_knowledge_discovery(&document, &self.origin)?;
        self.discovery = Some(document);
        Ok(())
    }
    pub async fn discover(&mut self) -> Result<Value> {
        let document = self
            .send(
                self.inner
                    .get(format!("{}/.well-known/agent-knowledge", self.origin)),
            )
            .await?;
        self.set_discovery(document.clone())?;
        Ok(document)
    }
    fn endpoint(&self, key: &str) -> Result<String> {
        let discovery = self.discovery.as_ref();
        if key == "search"
            && !discovery
                .and_then(|d| d["features"].as_array())
                .is_some_and(|f| f.iter().any(|v| v == "ranked-search"))
        {
            return Err(SdkError::protocol(
                "unsupported_search_mode",
                "ranked search is not advertised; discover first",
            ));
        }
        Ok(discovery
            .and_then(|d| d["endpoints"][key].as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{}/v1/knowledge/{key}", self.origin)))
    }
    async fn send(&self, request: reqwest::RequestBuilder) -> Result<Value> {
        let response = request.send().await?;
        if response.url().origin().ascii_serialization() != self.origin {
            return Err(SdkError::protocol(
                "invalid_response",
                "transport followed a cross-origin redirect",
            ));
        }
        if response.status() != reqwest::StatusCode::OK {
            let status = response.status().as_u16();
            let max_seen_nonce = response
                .headers()
                .get(MAX_NONCE_HEADER)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let body = response.text().await.unwrap_or_default();
            let (code, data) = serde_json::from_str::<ErrorResponse>(&body)
                .map(|error| (Some(error.error.code), error.error.data))
                .unwrap_or((None, None));
            return Err(SdkError::HttpStatus {
                status,
                code,
                data,
                max_seen_nonce,
                body,
            });
        }
        let bytes = response.bytes().await?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|e| SdkError::protocol("invalid_response", e.to_string()))?;
        crate::identity::parse_strict_json(text)
            .map_err(|e| SdkError::protocol("invalid_response", e.to_string()))
    }
    pub async fn event(&self, hash: &str) -> Result<Value> {
        crate::knowledge::validate_knowledge_id(hash)
            .map_err(|e| SdkError::protocol("invalid_request", e.to_string()))?;
        let url = format!("{}/{hash}", self.endpoint("events")?);
        let response = self.send(self.inner.get(url)).await?;
        crate::knowledge::validate_knowledge_record(&response, Some(hash))?;
        Ok(response)
    }
    pub async fn submit(&self, envelope: &Value, jwt: Option<&str>) -> Result<Value> {
        let verified = crate::knowledge::validate_knowledge_envelope(envelope)?;
        if let Some(jwt) = jwt {
            crate::identity::verify_request_jwt(
                jwt,
                &crate::identity::RequestAuthContext::new(&self.origin),
            )?;
        }
        let response = self
            .send(with_jwt(
                self.inner.post(self.endpoint("events")?).json(envelope),
                jwt,
            ))
            .await?;
        crate::knowledge::validate_knowledge_record(&response, Some(&verified.hash))?;
        Ok(response)
    }
    pub async fn query(&self, request: &Value) -> Result<Value> {
        crate::knowledge::validate_knowledge_query(request)?;
        let mut url = url::Url::parse(&self.endpoint("query")?)
            .map_err(|e| SdkError::protocol("invalid_request", e.to_string()))?;
        for (key, value) in crate::knowledge::normalized_json(request)
            .as_object()
            .expect("validated query is an object")
        {
            let value = value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string());
            url.query_pairs_mut().append_pair(key, &value);
        }
        let response = self.send(self.inner.get(url)).await?;
        crate::knowledge::validate_knowledge_query_response(&response, request, &self.origin)?;
        Ok(response)
    }
    /// Complete one checkpoint-bound query within `max_pages`, checking every
    /// page against the same request and scope. Persist the returned checkpoint
    /// as the next `after_seq`. No peer requests are made.
    pub async fn query_all(&self, request: &Value, max_pages: usize) -> Result<(Vec<Value>, u64)> {
        let mut tracker = crate::knowledge::KnowledgePageTracker::new(&self.origin)?;
        let mut next = request.clone();
        let mut records = Vec::new();
        for _ in 0..max_pages {
            let page = self.query(&next).await?;
            tracker.accept(&next, &page)?;
            records.extend(page["result"].as_array().into_iter().flatten().cloned());
            if let Some(checkpoint) = tracker.checkpoint() {
                return Ok((records, checkpoint));
            }
            next["cursor"] = page["next_cursor"].clone();
        }
        Err(SdkError::PageLimitExceeded(max_pages))
    }
    pub async fn batch(&self, request: &Value) -> Result<Value> {
        let hashes = crate::knowledge::validate_knowledge_batch_request(request)?;
        let response = self
            .send(self.inner.post(self.endpoint("batch")?).json(request))
            .await?;
        crate::knowledge::validate_knowledge_batch_response(&response, &hashes, &self.origin)?;
        Ok(response)
    }
    pub async fn search(&self, request: &Value) -> Result<Value> {
        let modes: Vec<String> = self
            .discovery
            .as_ref()
            .and_then(|d| d["search_modes"].as_array())
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        crate::knowledge::validate_knowledge_search_request(request, &modes)?;
        let endpoint = self.endpoint("search")?;
        let response = self.send(self.inner.post(endpoint).json(request)).await?;
        crate::knowledge::validate_knowledge_search_response(&response, request, &self.origin)?;
        Ok(response)
    }
}
