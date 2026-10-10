use std::collections::BTreeMap;
use std::time::Duration;

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
    ProfileServiceDiscovery, ProfileServiceEndpoints, ProfileUpdatePayload,
};

/// Principal URLs come from signed events that anyone can submit, so every
/// principal read is bounded in time and size (Agent Identity Section 10).
const PRINCIPAL_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PRINCIPAL_DOCUMENT_BYTES: usize = 1024 * 1024;

/// Reads a JSON body, turning a non-2xx response into [`SdkError::HttpStatus`]
/// with the Agent Identity error code and `Max-Seen-Nonce` header when present.
async fn read_json<T: DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    if status.is_success() {
        return Ok(response.json().await?);
    }
    let max_seen_nonce = max_seen_nonce(&response);
    let body = response.text().await.unwrap_or_default();
    Err(http_status_error(status.as_u16(), max_seen_nonce, body))
}

/// Like [`read_json`], but rejects a body over `limit` bytes.
async fn read_bounded_json<T: DeserializeOwned>(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<T> {
    let too_large = || {
        SdkError::protocol(
            "payload_too_large",
            format!("response exceeds {limit} bytes"),
        )
    };
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return Err(too_large());
    }
    let status = response.status();
    let max_seen_nonce = max_seen_nonce(&response);
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(too_large());
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        let body = String::from_utf8_lossy(&bytes).into_owned();
        return Err(http_status_error(status.as_u16(), max_seen_nonce, body));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn max_seen_nonce(response: &reqwest::Response) -> Option<String> {
    response
        .headers()
        .get(MAX_NONCE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn http_status_error(status: u16, max_seen_nonce: Option<String>, body: String) -> SdkError {
    let (code, data) = match serde_json::from_str::<ErrorResponse>(&body) {
        Ok(parsed) => (Some(parsed.error.code), parsed.error.data),
        Err(_) => (None, None),
    };
    SdkError::HttpStatus {
        status,
        code,
        data,
        max_seen_nonce,
        body,
    }
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

/// Agent Profile client. Without endpoints it uses the RECOMMENDED paths under
/// `base_url`; [`ProfileClient::discover`] reads the service's discovery
/// document instead, whose endpoints clients MUST prefer.
#[derive(Clone, Debug)]
pub struct ProfileClient {
    profiles_url: String,
    batch_url: String,
    inner: reqwest::Client,
}

impl ProfileClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_client(base_url, reqwest::Client::new())
    }

    pub fn with_client(base_url: impl Into<String>, inner: reqwest::Client) -> Self {
        let profiles = join_url(&base_url.into(), "/v1/profiles");
        Self::with_endpoints(
            inner,
            &ProfileServiceEndpoints {
                profiles,
                profile_batch: None,
            },
        )
    }

    /// Uses the endpoints of a discovery document; `profile_batch` defaults to
    /// `{profiles}/batch`.
    pub fn with_endpoints(inner: reqwest::Client, endpoints: &ProfileServiceEndpoints) -> Self {
        let profiles_url = endpoints.profiles.trim_end_matches('/').to_owned();
        let batch_url = endpoints
            .profile_batch
            .clone()
            .unwrap_or_else(|| format!("{profiles_url}/batch"));
        Self {
            profiles_url,
            batch_url,
            inner,
        }
    }

    /// Builds a client for the service at `origin` from its discovery
    /// document, falling back to the default paths when the service publishes none.
    pub async fn discover(origin: &str) -> Self {
        Self::discover_with_client(origin, reqwest::Client::new()).await
    }

    pub async fn discover_with_client(origin: &str, inner: reqwest::Client) -> Self {
        let base = origin.trim_end_matches('/');
        let discovered: Result<ProfileServiceDiscovery> =
            send_json(inner.get(format!("{base}/.well-known/agent-profile"))).await;
        match discovered {
            Ok(discovery) => Self::with_endpoints(inner, &discovery.endpoints),
            // Discovery is optional; the default paths apply.
            Err(_) => Self::with_client(base, inner),
        }
    }

    /// Base URL of profile reads, event history, and submission (Section 7.1).
    pub fn profiles_url(&self) -> &str {
        &self.profiles_url
    }

    pub async fn get_profile(&self, agent_id: &AgentId) -> Result<AgentProfile> {
        send_json(self.inner.get(format!("{}/{agent_id}", self.profiles_url))).await
    }

    pub async fn get_profiles(&self, agent_ids: &[AgentId]) -> Result<ProfileBatchReadResponse> {
        let request = ProfileBatchReadRequest {
            ids: agent_ids.to_vec(),
        };
        send_json(self.inner.post(&self.batch_url).json(&request)).await
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
        let url = with_query(format!("{}/{agent_id}/events", self.profiles_url), &pairs);
        send_json(self.inner.get(url)).await
    }

    pub async fn submit_profile_update(
        &self,
        envelope: &Envelope<ProfileUpdatePayload>,
    ) -> Result<AgentProfile> {
        send_json(self.inner.post(&self.profiles_url).json(envelope)).await
    }
}

/// ADP host client. Without endpoints it uses the RECOMMENDED paths under
/// `base_url`; [`DiscourseClient::discover`] reads the host's discovery
/// document instead, whose endpoints clients MUST prefer.
#[derive(Clone, Debug)]
pub struct DiscourseClient {
    base_url: String,
    rooms_url: String,
    my_rooms_url: String,
    inner: reqwest::Client,
}

impl DiscourseClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_client(base_url, reqwest::Client::new())
    }

    pub fn with_client(base_url: impl Into<String>, inner: reqwest::Client) -> Self {
        Self::with_endpoints(base_url, inner, &BTreeMap::new())
    }

    /// Uses the `rooms` and `my_rooms` endpoints of a discovery document,
    /// falling back to the RECOMMENDED paths for the ones it omits.
    pub fn with_endpoints(
        base_url: impl Into<String>,
        inner: reqwest::Client,
        endpoints: &BTreeMap<String, String>,
    ) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        let rooms_url = endpoints
            .get("rooms")
            .cloned()
            .unwrap_or_else(|| format!("{base_url}/v1/rooms"))
            .trim_end_matches('/')
            .to_owned();
        let my_rooms_url = endpoints
            .get("my_rooms")
            .cloned()
            .unwrap_or_else(|| format!("{base_url}/v1/me/rooms"));
        Self {
            base_url,
            rooms_url,
            my_rooms_url,
            inner,
        }
    }

    /// Builds a client for the host at `origin` from its discovery document,
    /// falling back to the default paths when the host publishes none.
    pub async fn discover(origin: &str) -> Self {
        Self::discover_with_client(origin, reqwest::Client::new()).await
    }

    pub async fn discover_with_client(origin: &str, inner: reqwest::Client) -> Self {
        let base = origin.trim_end_matches('/');
        let discovered: Result<DiscourseProtocolDiscovery> =
            send_json(inner.get(format!("{base}/.well-known/agent-discourse"))).await;
        match discovered {
            Ok(discovery) => Self::with_endpoints(base, inner, &discovery.endpoints),
            // Discovery is optional; the default paths apply.
            Err(_) => Self::with_client(base, inner),
        }
    }

    /// The `rooms` endpoint: `POST` creates rooms, `GET` lists discoverable
    /// rooms, and each room URL extends it with `/{room_id}` (ADP Section 15.1).
    pub fn rooms_url(&self) -> &str {
        &self.rooms_url
    }

    pub async fn protocol(&self) -> Result<DiscourseProtocolDiscovery> {
        send_json(
            self.inner
                .get(format!("{}/.well-known/agent-discourse", self.base_url)),
        )
        .await
    }

    pub async fn create_room(
        &self,
        envelope: &Envelope<RoomCreatePayload>,
    ) -> Result<RoomResponse> {
        send_json(self.inner.post(&self.rooms_url).json(envelope)).await
    }

    /// Submits a signed `room.join.request`; the signature authenticates the applicant.
    pub async fn request_join(
        &self,
        room_id: &str,
        envelope: &Envelope<RoomJoinRequestPayload>,
    ) -> Result<RoomJoinRequest> {
        send_json(
            self.inner
                .post(format!("{}/join-requests", self.room_url(room_id)))
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
                .get(format!(
                    "{}/join-requests/{request_id}",
                    self.room_url(room_id)
                ))
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
            format!("{}/join-requests", self.room_url(room_id)),
            &options.pairs(),
        );
        send_json(self.inner.get(path).bearer_auth(jwt)).await
    }

    pub async fn room(&self, room_id: &str, jwt: Option<&str>) -> Result<RoomResponse> {
        send_json(with_jwt(
            self.inner.get(format!("{}", self.room_url(room_id))),
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
        let path = with_query(self.rooms_url.clone(), &options.pairs());
        send_json(self.inner.get(path)).await
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
        let path = with_query(self.my_rooms_url.clone(), &options.pairs());
        send_json(self.inner.get(path).bearer_auth(jwt)).await
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
                .post(format!("{}", self.room_url(room_id)))
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
        let path = with_query(
            format!("{}/events", self.room_url(room_id)),
            &options.pairs(),
        );
        send_json(with_jwt(self.inner.get(path), options.jwt.as_deref())).await
    }

    pub async fn agent_statuses(
        &self,
        room_id: &str,
        jwt: Option<&str>,
    ) -> Result<AgentStatusListResponse> {
        send_json(with_jwt(
            self.inner
                .get(format!("{}/agent-status", self.room_url(room_id))),
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
            self.inner.get(format!(
                "{}/agent-status/{agent_id}",
                self.room_url(room_id)
            )),
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
                .put(format!("{}/agent-status", self.room_url(room_id)))
                .bearer_auth(jwt)
                .json(status),
        )
        .await
    }

    pub fn sse_events_url(&self, room_id: &str) -> String {
        format!(
            "{}/{}/events/live",
            self.rooms_url,
            encode_query_component(room_id)
        )
    }

    pub async fn archive(&self, room_id: &str) -> Result<Value> {
        send_json(
            self.inner
                .get(format!("{}/archive", self.room_url(room_id))),
        )
        .await
    }

    fn room_url(&self, room_id: &str) -> String {
        format!("{}/{room_id}", self.rooms_url)
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
            .timeout(PRINCIPAL_TIMEOUT)
            .send()
            .await?;
        if response.url().scheme() != "https" {
            return Err(SdkError::InvalidPayload(
                "principal resolution requires HTTPS".into(),
            ));
        }
        let resolved = response.url().to_string();
        // A copy is parsed only for its canonical ID; its authority shape is irrelevant.
        Ok((
            read_bounded_json(response, MAX_PRINCIPAL_DOCUMENT_BYTES).await?,
            resolved,
        ))
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

    /// The query endpoint this client uses: discovered, or the RECOMMENDED default.
    pub fn query_url(&self) -> &str {
        &self.query_url
    }

    /// Queries an explicit endpoint, such as the `query` endpoint discovered at
    /// a principal's `delegation_service` origin. A relying party reaches a
    /// principal's authoritative service through that origin, never through a
    /// URL supplied by whoever presented the credential.
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

/// URL of a room's SSE stream. Send the request JWT in the `Authorization`
/// header, never in this URL; the host closes the stream by the JWT's `exp`
/// (Agent Discourse Section 16.1).
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
    /// Fetch and validate the discovery document without installing it.
    pub async fn protocol(&self) -> Result<Value> {
        let document = self
            .send(
                self.inner
                    .get(format!("{}/.well-known/agent-knowledge", self.origin)),
            )
            .await?;
        crate::knowledge::validate_knowledge_discovery(&document, &self.origin)?;
        Ok(document)
    }
    /// Fetch, validate and install the discovery document.
    pub async fn discover(&mut self) -> Result<Value> {
        let document = self.protocol().await?;
        self.discovery = Some(document.clone());
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

/// Agent Mail transport with anonymous delivery and owner-authorized reads.
pub use crate::mail::MailClient;
