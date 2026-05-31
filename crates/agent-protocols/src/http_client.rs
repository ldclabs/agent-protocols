use serde::Serialize;
use serde_json::Value;

use crate::discourse::{
    DiscourseProtocolDiscovery, RoomCreatePayload, RoomCreateResponse, RoomJoinPayload,
    RoomLeavePayload, ServerRecord,
};
use crate::error::Result;
use crate::identity::{AgentId, Envelope};
use crate::profile::{AgentProfile, ProfileReadResponse, ProfileUpdatePayload};

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

    pub async fn get_profile(&self, agent_id: &AgentId) -> Result<ProfileReadResponse> {
        Ok(self
            .inner
            .get(self.url(&format!("/v1/profiles/{agent_id}")))
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
            .get(self.url("/v1/protocol"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn create_room(
        &self,
        envelope: &Envelope<RoomCreatePayload>,
    ) -> Result<RoomCreateResponse> {
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

    pub async fn join_room(
        &self,
        room_id: &str,
        envelope: &Envelope<RoomJoinPayload>,
    ) -> Result<Value> {
        Ok(self
            .inner
            .post(self.url(&format!("/v1/rooms/{room_id}/join")))
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
    ) -> Result<Value> {
        Ok(self
            .inner
            .post(self.url(&format!("/v1/rooms/{room_id}/leave")))
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
            .post(self.url(&format!("/v1/rooms/{room_id}/events")))
            .json(envelope)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn events(&self, room_id: &str) -> Result<Vec<ServerRecord>> {
        Ok(self
            .inner
            .get(self.url(&format!("/v1/rooms/{room_id}/events")))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
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
