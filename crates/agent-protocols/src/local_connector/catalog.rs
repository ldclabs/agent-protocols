//! Static local connector catalog: tool and resource names plus the standard
//! tool/list declarations. This module is pure data — it never touches signing
//! keys or room state — so an MCP server can advertise the surface without a
//! live [`super::LocalConnector`].

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const TOOL_SERVICES_LIST: &str = "agent_protocols_services_list";
pub const TOOL_PROFILES_GET: &str = "agent_protocols_profiles_get";
pub const TOOL_PROFILE_HISTORY: &str = "agent_protocols_profile_history";
pub const TOOL_DELEGATION_HISTORY: &str = "agent_protocols_delegation_history";
pub const TOOL_MAIL_RESOLVE: &str = "agent_protocols_mail_resolve";
pub const TOOL_SCHEMA_GET: &str = "agent_protocols_schema_get";
pub const TOOL_ROOM_ARCHIVE: &str = "agent_protocols_room_archive";
pub const TOOL_ROOM_WATCH: &str = "agent_protocols_room_watch";

pub const TOOL_IDENTITY_CURRENT: &str = "agent_protocols_identity_current";
pub const TOOL_PRINCIPAL_RESOLVE: &str = "agent_protocols_principal_resolve";
pub const TOOL_DELEGATION_CHECK: &str = "agent_protocols_delegation_check";
pub const TOOL_DELEGATIONS_LIST: &str = "agent_protocols_delegations_list";
pub const TOOL_DELEGATION_GRANT: &str = "agent_protocols_delegation_grant";
pub const TOOL_DELEGATION_REVOKE: &str = "agent_protocols_delegation_revoke";
pub const TOOL_ROOMS_LIST: &str = "agent_protocols_rooms_list";
pub const TOOL_ROOM_STATE: &str = "agent_protocols_room_state";
pub const TOOL_ROOM_MEMBERS_LIST: &str = "agent_protocols_room_members_list";
pub const TOOL_AGENT_STATUS_LIST: &str = "agent_protocols_agent_status_list";
pub const TOOL_AGENT_STATUS_SET: &str = "agent_protocols_agent_status_set";
pub const TOOL_ROOM_TIMELINE: &str = "agent_protocols_room_timeline";
pub const TOOL_INBOX_NEXT: &str = "agent_protocols_inbox_next";
pub const TOOL_INBOX_ACK: &str = "agent_protocols_inbox_ack";
pub const TOOL_DRAFTS_LIST: &str = "agent_protocols_drafts_list";
pub const TOOL_DRAFT_COMMIT: &str = "agent_protocols_draft_commit";
pub const TOOL_PROFILE_UPDATE: &str = "agent_protocols_profile_update";
pub const TOOL_ROOM_CREATE: &str = "agent_protocols_room_create";
pub const TOOL_ROOM_JOIN: &str = "agent_protocols_room_join";
pub const TOOL_ROOM_SEND_MESSAGE: &str = "agent_protocols_room_send_message";
pub const TOOL_ROOM_SUBMIT_EVENT: &str = "agent_protocols_room_submit_event";
pub const TOOL_JOIN_REQUESTS_LIST: &str = "agent_protocols_join_requests_list";
pub const TOOL_JOIN_REQUEST_REVIEW: &str = "agent_protocols_join_request_review";
pub const TOOL_MAIL_MAILBOXES_LIST: &str = "agent_protocols_mail_mailboxes_list";
pub const TOOL_MAIL_MAILBOX_PUBLISH: &str = "agent_protocols_mail_mailbox_publish";
pub const TOOL_MAIL_SEND: &str = "agent_protocols_mail_send";
pub const TOOL_MAIL_SYNC: &str = "agent_protocols_mail_sync";
pub const TOOL_MAIL_LIST: &str = "agent_protocols_mail_list";
pub const TOOL_KNOWLEDGE_SUBMIT: &str = "agent_protocols_knowledge_submit";
pub const TOOL_KNOWLEDGE_QUERY: &str = "agent_protocols_knowledge_query";
pub const TOOL_KNOWLEDGE_GET: &str = "agent_protocols_knowledge_get";
pub const TOOL_KNOWLEDGE_SEARCH: &str = "agent_protocols_knowledge_search";
pub const TOOL_KNOWLEDGE_STATUS: &str = "agent_protocols_knowledge_status";

/// Every standard tool name, in `tools/list` order.
pub const TOOL_NAMES: [&str; 41] = [
    TOOL_SERVICES_LIST,
    TOOL_PROFILES_GET,
    TOOL_PROFILE_HISTORY,
    TOOL_DELEGATION_HISTORY,
    TOOL_MAIL_RESOLVE,
    TOOL_SCHEMA_GET,
    TOOL_ROOM_ARCHIVE,
    TOOL_ROOM_WATCH,
    TOOL_IDENTITY_CURRENT,
    TOOL_PRINCIPAL_RESOLVE,
    TOOL_DELEGATION_CHECK,
    TOOL_DELEGATIONS_LIST,
    TOOL_DELEGATION_GRANT,
    TOOL_DELEGATION_REVOKE,
    TOOL_ROOMS_LIST,
    TOOL_ROOM_STATE,
    TOOL_ROOM_MEMBERS_LIST,
    TOOL_AGENT_STATUS_LIST,
    TOOL_AGENT_STATUS_SET,
    TOOL_ROOM_TIMELINE,
    TOOL_INBOX_NEXT,
    TOOL_INBOX_ACK,
    TOOL_DRAFTS_LIST,
    TOOL_DRAFT_COMMIT,
    TOOL_PROFILE_UPDATE,
    TOOL_ROOM_CREATE,
    TOOL_ROOM_JOIN,
    TOOL_ROOM_SEND_MESSAGE,
    TOOL_ROOM_SUBMIT_EVENT,
    TOOL_JOIN_REQUESTS_LIST,
    TOOL_JOIN_REQUEST_REVIEW,
    TOOL_MAIL_MAILBOXES_LIST,
    TOOL_MAIL_MAILBOX_PUBLISH,
    TOOL_MAIL_SEND,
    TOOL_MAIL_SYNC,
    TOOL_MAIL_LIST,
    TOOL_KNOWLEDGE_SUBMIT,
    TOOL_KNOWLEDGE_QUERY,
    TOOL_KNOWLEDGE_GET,
    TOOL_KNOWLEDGE_SEARCH,
    TOOL_KNOWLEDGE_STATUS,
];

pub const RESOURCE_IDENTITY_CURRENT: &str = "agent-protocols://identity/current";
pub const RESOURCE_HOSTS: &str = "agent-protocols://hosts";
pub const RESOURCE_ROOMS: &str = "agent-protocols://rooms";
pub const RESOURCE_INBOX_PENDING: &str = "agent-protocols://inbox/pending";
pub const RESOURCE_DRAFTS_HELD: &str = "agent-protocols://drafts/held";
pub const RESOURCE_MAIL_MAILBOXES: &str = "agent-protocols://mail/mailboxes";
pub const RESOURCE_MAIL_MESSAGES: &str = "agent-protocols://mail/messages";
pub const RESOURCE_ROOM_AGENT_STATUS_SUFFIX: &str = "/agent-status";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LocalConnectorToolAnnotations {
    pub read_only_hint: bool,
    pub idempotent_hint: bool,
    pub destructive_hint: bool,
    pub open_world_hint: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LocalConnectorToolDefinition {
    pub name: String,
    pub description: String,
    #[serde(alias = "inputSchema")]
    pub input_schema: Value,
    #[serde(alias = "outputSchema")]
    pub output_schema: Value,
    pub annotations: LocalConnectorToolAnnotations,
}

pub(crate) fn catalog_data() -> &'static Value {
    static DATA: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!("catalog.json")).expect("bundled MCP catalog")
    })
}

pub fn standard_tool_definitions() -> Vec<LocalConnectorToolDefinition> {
    serde_json::from_value(catalog_data()["tools"].clone()).expect("bundled MCP tools")
}

/// Reject malformed tool inputs before networking/signing, with JSON Pointer paths.
pub(crate) fn validate_tool_input(name: &str, input: &Value) -> crate::error::Result<()> {
    static VALIDATORS: std::sync::OnceLock<
        std::collections::BTreeMap<String, jsonschema::Validator>,
    > = std::sync::OnceLock::new();
    let validators = VALIDATORS.get_or_init(|| {
        standard_tool_definitions()
            .into_iter()
            .map(|mut tool| {
                if tool.name == TOOL_KNOWLEDGE_SUBMIT {
                    tool.input_schema["properties"]["payload"] = serde_json::json!({});
                }
                let validator = jsonschema::options()
                    .with_draft(jsonschema::Draft::Draft202012)
                    .build(&tool.input_schema)
                    .expect("bundled tool schema");
                (tool.name, validator)
            })
            .collect()
    });
    let Some(validator) = validators.get(name) else {
        return Ok(());
    };
    let mut errors:Vec<Value>=validator.iter_errors(input).take(16).map(|error|serde_json::json!({"path":error.instance_path().to_string(),"message":error.to_string()})).collect();
    if errors.is_empty() {
        return Ok(());
    }
    let payload = name == TOOL_KNOWLEDGE_SUBMIT
        && errors.iter().all(|e| {
            e["path"]
                .as_str()
                .unwrap_or_default()
                .starts_with("/payload")
        });
    if payload {
        for error in &mut errors {
            error["path"] = Value::String(
                error["path"]
                    .as_str()
                    .unwrap_or_default()
                    .trim_start_matches("/payload")
                    .to_owned(),
            );
        }
    }
    let message = errors
        .iter()
        .map(|e| {
            format!(
                "{}: {}",
                e["path"].as_str().unwrap_or_default(),
                e["message"].as_str().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    Err(crate::error::SdkError::protocol_with_data(
        if payload {
            "invalid_event"
        } else {
            "invalid_payload"
        },
        message,
        serde_json::json!({"errors":errors}),
    ))
}

pub(crate) fn payload_schema(schema: &Value, definition: &str) -> Value {
    fn visit(value: &Value, source: &Value, definitions: &mut serde_json::Map<String, Value>) {
        match value {
            Value::Array(values) => {
                for value in values {
                    visit(value, source, definitions)
                }
            }
            Value::Object(object) => {
                if let Some(name) = object
                    .get("$ref")
                    .and_then(Value::as_str)
                    .and_then(|r| r.strip_prefix("#/$defs/"))
                {
                    if !definitions.contains_key(name) {
                        definitions.insert(name.into(), source[name].clone());
                        visit(&source[name], source, definitions);
                    }
                }
                for value in object.values() {
                    visit(value, source, definitions);
                }
            }
            _ => {}
        }
    }
    let mut root = serde_json::json!({"$ref":format!("#/$defs/{definition}")});
    let mut definitions = serde_json::Map::new();
    visit(&root, &schema["$defs"], &mut definitions);
    root["$defs"] = Value::Object(definitions);
    root
}
