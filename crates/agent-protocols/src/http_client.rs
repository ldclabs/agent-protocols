use serde::Serialize;
use serde_json::Value;

use crate::discourse::{
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
        let mut path = format!("/v1/profiles/{agent_id}/events");
        if let Some(limit) = limit {
            path.push_str(&format!("?limit={limit}"));
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

    pub fn websocket_events_url(&self, room_id: &str, jwt: &str) -> String {
        websocket_events_url(&self.base_url, room_id, jwt)
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

pub fn websocket_events_url(base_url: &str, room_id: &str, jwt: &str) -> String {
    let mut websocket_base = base_url.trim_end_matches('/').to_owned();
    if let Some(rest) = websocket_base.strip_prefix("https://") {
        websocket_base = format!("wss://{rest}");
    } else if let Some(rest) = websocket_base.strip_prefix("http://") {
        websocket_base = format!("ws://{rest}");
    }
    format!(
        "{}/v1/rooms/{}/events/live?access_token={}",
        websocket_base,
        room_id,
        encode_query_component(jwt)
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_websocket_events_url() {
        assert_eq!(
            websocket_events_url("https://api.example.com", "room123", "jwt.token"),
            "wss://api.example.com/v1/rooms/room123/events/live?access_token=jwt.token"
        );
    }
}
