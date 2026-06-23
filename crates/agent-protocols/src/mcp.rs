use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum McpAuthorizationMode {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "agent-jwt")]
    AgentJwt,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpAuthorizationMetadata {
    pub mode: McpAuthorizationMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_jwt_audience: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpServiceInterfaceDiscovery {
    pub spec_version: String,
    pub endpoint: String,
    pub transport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<McpAuthorizationMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prompts: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_service_interface_discovery_round_trips() {
        let discovery = McpServiceInterfaceDiscovery {
            spec_version: "2025-11-25".to_owned(),
            endpoint: "https://profiles.example.com/mcp".to_owned(),
            transport: "streamable-http".to_owned(),
            authorization: Some(McpAuthorizationMetadata {
                mode: McpAuthorizationMode::AgentJwt,
                agent_jwt_audience: Some("https://profiles.example.com".to_owned()),
            }),
            tools: vec!["agent_profile.get".to_owned()],
            resources: vec!["agent-profile://profiles/{agent_id}".to_owned()],
            prompts: Vec::new(),
            extra: BTreeMap::new(),
        };

        let encoded = serde_json::to_value(&discovery).unwrap();
        assert_eq!(encoded["spec_version"], "2025-11-25");
        assert_eq!(encoded["authorization"]["mode"], "agent-jwt");
        assert!(encoded.get("prompts").is_none());

        let decoded: McpServiceInterfaceDiscovery = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, discovery);
    }
}
