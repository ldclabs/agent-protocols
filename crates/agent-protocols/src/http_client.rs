use serde::Serialize;
use serde_json::Value;

use crate::delegation::{
    validate_principal_document, validate_principal_resolution, DelegationCredential,
    DelegationEventsResponse, DelegationQueryRequest, DelegationQueryResponse,
    DelegationServiceDiscovery, DelegationStatusDocument, PrincipalDocument,
};
use crate::discourse::{
    AgentStatus, AgentStatusGetResponse, AgentStatusInput, AgentStatusListResponse,
    DiscourseProtocolDiscovery, RoomCreatePayload, RoomJoinPayload, RoomJoinRequestInput,
    RoomJoinRequestStatus, RoomLeavePayload, RoomResponse, ServerRecord,
};
use crate::error::Result;
use crate::identity::{AgentId, Envelope};
use crate::profile::{
    AgentProfile, ProfileBatchReadRequest, ProfileBatchReadResponse, ProfileEventsResponse,
    ProfileUpdatePayload,
};

#[derive(Clone, Debug)]
pub struct ProfileClient {
    base_url: String,
    inner: reqwest::Client,
}

impl ProfileClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            inner: reqwest::Client::new(),
        }
    }

    pub fn with_client(base_url: impl Into<String>, inner: reqwest::Client) -> Self {
        Self {
            base_url: base_url.into(),
            inner,
        }
    }

    pub async fn get_profile(&self, agent_id: &AgentId) -> Result<AgentProfile> {
        Ok(self
            .inner
            .get(self.url(&format!("/v1/profiles/{agent_id}")))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn get_profiles(&self, agent_ids: &[AgentId]) -> Result<ProfileBatchReadResponse> {
        let request = ProfileBatchReadRequest {
            ids: agent_ids.to_vec(),
        };
        Ok(self
            .inner
            .post(self.url("/v1/profiles/batch"))
            .json(&request)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
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
        let mut path = format!("/v1/profiles/{agent_id}/events");
        let mut pairs = Vec::new();
        if let Some(limit) = limit {
            pairs.push(format!("limit={limit}"));
        }
        push_query_pair(&mut pairs, "cursor", cursor);
        if !pairs.is_empty() {
            path.push('?');
            path.push_str(&pairs.join("&"));
        }
        Ok(self
            .inner
            .get(self.url(&path))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn submit_profile_update(
        &self,
        envelope: &Envelope<ProfileUpdatePayload>,
    ) -> Result<AgentProfile> {
        Ok(self
            .inner
            .post(self.url("/v1/profiles"))
            .json(envelope)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }
}

#[derive(Clone, Debug)]
pub struct DiscourseClient {
    base_url: String,
    inner: reqwest::Client,
}

impl DiscourseClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            inner: reqwest::Client::new(),
        }
    }

    pub fn with_client(base_url: impl Into<String>, inner: reqwest::Client) -> Self {
        Self {
            base_url: base_url.into(),
            inner,
        }
    }

    pub async fn protocol(&self) -> Result<DiscourseProtocolDiscovery> {
        Ok(self
            .inner
            .get(self.url("/.well-known/agent-discourse"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn create_room(
        &self,
        envelope: &Envelope<RoomCreatePayload>,
    ) -> Result<RoomResponse> {
        Ok(self
            .inner
            .post(self.url("/v1/rooms"))
            .json(envelope)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn request_join(
        &self,
        room_id: &str,
        jwt: &str,
        request: &RoomJoinRequestInput,
    ) -> Result<RoomJoinRequestStatus> {
        Ok(self
            .inner
            .post(self.url(&format!("/v1/rooms/{room_id}/join-requests")))
            .bearer_auth(jwt)
            .json(request)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn join_request(
        &self,
        room_id: &str,
        request_id: &str,
        jwt: &str,
    ) -> Result<RoomJoinRequestStatus> {
        Ok(self
            .inner
            .get(self.url(&format!("/v1/rooms/{room_id}/join-requests/{request_id}")))
            .bearer_auth(jwt)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn join_requests(
        &self,
        room_id: &str,
        jwt: &str,
    ) -> Result<Vec<RoomJoinRequestStatus>> {
        Ok(self
            .inner
            .get(self.url(&format!("/v1/rooms/{room_id}/join-requests")))
            .bearer_auth(jwt)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn room(&self, room_id: &str) -> Result<RoomResponse> {
        Ok(self
            .inner
            .get(self.url(&format!("/v1/rooms/{room_id}")))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn public_rooms(&self, options: &PublicRoomsOptions) -> Result<Vec<RoomResponse>> {
        let mut path = "/v1/rooms/public".to_owned();
        let query = options.query_string();
        if !query.is_empty() {
            path.push('?');
            path.push_str(&query);
        }
        Ok(self
            .inner
            .get(self.url(&path))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn my_rooms(&self, jwt: &str) -> Result<Vec<RoomResponse>> {
        self.my_rooms_with_options(jwt, &MyRoomsOptions::default())
            .await
    }

    pub async fn my_rooms_with_options(
        &self,
        jwt: &str,
        options: &MyRoomsOptions,
    ) -> Result<Vec<RoomResponse>> {
        let mut path = "/v1/me/rooms".to_owned();
        let query = options.query_string();
        if !query.is_empty() {
            path.push('?');
            path.push_str(&query);
        }
        Ok(self
            .inner
            .get(self.url(&path))
            .bearer_auth(jwt)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn join_room(
        &self,
        room_id: &str,
        envelope: &Envelope<RoomJoinPayload>,
    ) -> Result<ServerRecord<RoomJoinPayload>> {
        Ok(self
            .inner
            .post(self.url(&format!("/v1/rooms/{room_id}")))
            .json(envelope)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn leave_room(
        &self,
        room_id: &str,
        envelope: &Envelope<RoomLeavePayload>,
    ) -> Result<ServerRecord<RoomLeavePayload>> {
        Ok(self
            .inner
            .post(self.url(&format!("/v1/rooms/{room_id}")))
            .json(envelope)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn submit_event<P>(
        &self,
        room_id: &str,
        envelope: &Envelope<P>,
    ) -> Result<ServerRecord>
    where
        P: Serialize,
    {
        Ok(self
            .inner
            .post(self.url(&format!("/v1/rooms/{room_id}")))
            .json(envelope)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn events(&self, room_id: &str) -> Result<Vec<ServerRecord>> {
        self.events_with_options(room_id, &RoomEventsOptions::default())
            .await
    }

    pub async fn events_with_options(
        &self,
        room_id: &str,
        options: &RoomEventsOptions,
    ) -> Result<Vec<ServerRecord>> {
        let mut path = format!("/v1/rooms/{room_id}/events");
        let query = options.query_string();
        if !query.is_empty() {
            path.push('?');
            path.push_str(&query);
        }
        let mut request = self.inner.get(self.url(&path));
        if let Some(jwt) = &options.jwt {
            request = request.bearer_auth(jwt);
        }
        Ok(request.send().await?.error_for_status()?.json().await?)
    }

    pub async fn agent_statuses(
        &self,
        room_id: &str,
        jwt: Option<&str>,
    ) -> Result<AgentStatusListResponse> {
        let mut request = self
            .inner
            .get(self.url(&format!("/v1/rooms/{room_id}/agent-status")));
        if let Some(jwt) = jwt {
            request = request.bearer_auth(jwt);
        }
        Ok(request.send().await?.error_for_status()?.json().await?)
    }

    pub async fn agent_status(
        &self,
        room_id: &str,
        agent_id: &AgentId,
        jwt: Option<&str>,
    ) -> Result<AgentStatusGetResponse> {
        let mut request = self
            .inner
            .get(self.url(&format!("/v1/rooms/{room_id}/agent-status/{agent_id}")));
        if let Some(jwt) = jwt {
            request = request.bearer_auth(jwt);
        }
        Ok(request.send().await?.error_for_status()?.json().await?)
    }

    pub async fn set_agent_status(
        &self,
        room_id: &str,
        jwt: &str,
        status: &AgentStatusInput,
    ) -> Result<AgentStatus> {
        Ok(self
            .inner
            .put(self.url(&format!("/v1/rooms/{room_id}/agent-status")))
            .bearer_auth(jwt)
            .json(status)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub fn sse_events_url(&self, room_id: &str) -> String {
        sse_events_url(&self.base_url, room_id)
    }

    pub async fn archive(&self, room_id: &str) -> Result<Value> {
        Ok(self
            .inner
            .get(self.url(&format!("/v1/rooms/{room_id}/archive")))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
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
    fn query_string(&self) -> String {
        let mut pairs = Vec::new();
        if let Some(after_seq) = self.after_seq {
            pairs.push(format!("after_seq={after_seq}"));
        }
        if let Some(limit) = self.limit {
            pairs.push(format!("limit={limit}"));
        }
        if let Some(cursor) = &self.cursor {
            pairs.push(format!("cursor={}", encode_query_component(cursor)));
        }
        pairs.join("&")
    }
}

#[derive(Clone, Debug)]
pub struct DelegationClient {
    base_url: String,
    inner: reqwest::Client,
}

impl DelegationClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            inner: reqwest::Client::new(),
        }
    }

    pub fn with_client(base_url: impl Into<String>, inner: reqwest::Client) -> Self {
        Self {
            base_url: base_url.into(),
            inner,
        }
    }

    pub async fn protocol(&self) -> Result<DelegationServiceDiscovery> {
        Ok(self
            .inner
            .get(self.url("/.well-known/agent-delegation"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Resolves a principal document per Agent Delegation Section 5.3. A
    /// document is authoritative only when read at its own `id`, so one served
    /// elsewhere (an alias hosting a copy rather than redirecting) is discarded
    /// and `document.id` is resolved once more.
    pub async fn principal(&self, principal_url: Option<&str>) -> Result<PrincipalDocument> {
        let start = principal_url.unwrap_or_else(|| self.base_url.trim_end_matches('/'));
        let (document, resolved) = self.read_principal(start).await?;
        if document.id == resolved {
            return Ok(document);
        }
        let canonical_id = document.id.clone();
        let (canonical, resolved) = self.read_principal(&canonical_id).await?;
        validate_principal_resolution(&canonical, &resolved)?;
        Ok(canonical)
    }

    async fn read_principal(&self, url: &str) -> Result<(PrincipalDocument, String)> {
        let response = self
            .inner
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?
            .error_for_status()?;
        let resolved = response.url().to_string();
        let document: PrincipalDocument = response.json().await?;
        validate_principal_document(&document)?;
        Ok((document, resolved))
    }

    pub async fn delegation(&self, delegation_id: &str) -> Result<DelegationCredential> {
        Ok(self
            .inner
            .get(self.url(&format!("/v1/delegations/{delegation_id}")))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn delegation_status(&self, delegation_id: &str) -> Result<DelegationStatusDocument> {
        Ok(self
            .inner
            .get(self.url(&format!("/v1/delegations/{delegation_id}/status")))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn delegation_events(&self, delegation_id: &str) -> Result<DelegationEventsResponse> {
        Ok(self
            .inner
            .get(self.url(&format!("/v1/delegations/{delegation_id}/events")))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn submit_delegation_event<P>(&self, envelope: &Envelope<P>) -> Result<Value>
    where
        P: Serialize,
    {
        Ok(self
            .inner
            .post(self.url("/v1/delegations"))
            .json(envelope)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Public queries are existence checks and carry both `subject` and
    /// `principal_id`. Pass `allow_enumeration` only for a request the service
    /// has authorized to enumerate one side.
    pub async fn query_delegations(
        &self,
        request: &DelegationQueryRequest,
        allow_enumeration: bool,
    ) -> Result<DelegationQueryResponse> {
        crate::delegation::validate_delegation_query_request(request, allow_enumeration)?;
        Ok(self
            .inner
            .post(self.url("/v1/delegations/query"))
            .json(request)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct MyRoomsOptions {
    pub status: Option<String>,
    pub membership: Option<String>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

impl MyRoomsOptions {
    fn query_string(&self) -> String {
        let mut pairs = Vec::new();
        push_query_pair(&mut pairs, "status", self.status.as_deref());
        push_query_pair(&mut pairs, "membership", self.membership.as_deref());
        if let Some(limit) = self.limit {
            pairs.push(format!("limit={limit}"));
        }
        push_query_pair(&mut pairs, "cursor", self.cursor.as_deref());
        pairs.join("&")
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
    fn query_string(&self) -> String {
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
        pairs.join("&")
    }
}

pub fn sse_events_url(base_url: &str, room_id: &str) -> String {
    format!(
        "{}/v1/rooms/{}/events/live",
        base_url.trim_end_matches('/'),
        encode_query_component(room_id)
    )
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
