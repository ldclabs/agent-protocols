//! End-to-end tests for the reqwest-based HTTP clients.
//!
//! These run against a minimal in-process HTTP/1.1 server that records requests
//! and replies with pre-queued responses, so the clients are exercised over a
//! real socket without any network access or mocking crates. The harness lives
//! in `tests/` so its defensive socket-handling branches are excluded from the
//! library coverage metric.
#![cfg(feature = "http-client")]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread;

use agent_protocols::delegation::{
    delegation_revoke_event, DelegationQueryRequest, DelegationRevokePayload,
    DelegationServiceEndpoints, DelegationStatus,
};
use agent_protocols::discourse::{
    build_server_record, discourse_event, event_type, room_create_event, room_join_request_event,
    AgentStatusInput, Role, RoomCreatePayload, RoomJoinPayload, RoomJoinRequestPayload,
    RoomLeavePayload, Visibility,
};
use agent_protocols::error::SdkError;
use agent_protocols::http_client::{
    sse_events_url, DelegationClient, DiscourseClient, JoinRequestsOptions, ProfileClient,
    PublicRoomsOptions, RoomEventsOptions,
};
use agent_protocols::identity::{AgentId, AgentSigner};
use agent_protocols::profile::{profile_update_event, ProfileUpdatePayload};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Builder;

#[derive(Clone, Debug)]
struct RecordedRequest {
    method: String,
    path: String,
    authorization: Option<String>,
    body: String,
}

type Response = (u16, String, Option<(String, String)>);

struct MockServer {
    base_url: String,
    responses: Arc<Mutex<VecDeque<Response>>>,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl MockServer {
    fn start() -> Self {
        let responses: Arc<Mutex<VecDeque<Response>>> = Arc::new(Mutex::new(VecDeque::new()));
        let requests: Arc<Mutex<Vec<RecordedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = std::sync::mpsc::channel();
        let responses_for_server = responses.clone();
        let requests_for_server = requests.clone();
        thread::spawn(move || {
            let runtime = Builder::new_current_thread().enable_all().build().unwrap();
            runtime.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                tx.send(listener.local_addr().unwrap()).unwrap();
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else {
                        break;
                    };
                    let request = read_request(&mut socket).await;
                    requests_for_server.lock().unwrap().push(request);
                    let (status, body, header) = responses_for_server
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or((200, "null".to_owned(), None));
                    write_response(&mut socket, status, &body, header).await;
                }
            });
        });
        let addr = rx.recv().unwrap();
        Self {
            base_url: format!("http://{addr}"),
            responses,
            requests,
        }
    }

    fn enqueue(&self, status: u16, body: impl Into<String>) {
        self.responses
            .lock()
            .unwrap()
            .push_back((status, body.into(), None));
    }

    fn enqueue_with_header(&self, status: u16, body: &str, name: &str, value: &str) {
        self.responses.lock().unwrap().push_back((
            status,
            body.to_owned(),
            Some((name.to_owned(), value.to_owned())),
        ));
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().unwrap().clone()
    }
}

async fn read_request(socket: &mut TcpStream) -> RecordedRequest {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        if let Some(pos) = find_subsequence(&buffer, b"\r\n\r\n") {
            break pos;
        }
        let read = socket.read(&mut chunk).await.unwrap();
        if read == 0 {
            break buffer.len();
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let header_text = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = header_text.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split(' ');
    let method = request_line.next().unwrap_or_default().to_owned();
    let path = request_line.next().unwrap_or_default().to_owned();
    let mut authorization = None;
    let mut content_length = 0_usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            match name.trim().to_ascii_lowercase().as_str() {
                "authorization" => authorization = Some(value.trim().to_owned()),
                "content-length" => content_length = value.trim().parse().unwrap_or(0),
                _ => {}
            }
        }
    }
    let mut body = buffer[(header_end + 4).min(buffer.len())..].to_vec();
    while body.len() < content_length {
        let read = socket.read(&mut chunk).await.unwrap();
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    RecordedRequest {
        method,
        path,
        authorization,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

async fn write_response(
    socket: &mut TcpStream,
    status: u16,
    body: &str,
    header: Option<(String, String)>,
) {
    let extra = header
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .unwrap_or_default();
    let response = format!(
        "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\n{extra}content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = socket.write_all(response.as_bytes()).await;
    let _ = socket.flush().await;
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

fn no_proxy_client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

fn sample_agent_id() -> String {
    AgentSigner::from_seed([1; 32]).agent_id().to_string()
}

fn server_record_body() -> String {
    let signer = AgentSigner::from_seed([2; 32]);
    let envelope = signer
        .sign_event(discourse_event(
            event_type::ROOM_JOIN,
            signer.agent_id(),
            1,
            1,
            "room1",
            1,
            "room-head-hash",
            RoomJoinPayload {
                role: Role::Speaker,
                perspective: None,
            },
        ))
        .unwrap();
    let record = build_server_record("room1", 1, None, 1, envelope).unwrap();
    serde_json::to_string(&record).unwrap()
}

#[test]
fn profile_client_round_trips_every_endpoint() {
    let server = MockServer::start();
    let aid = sample_agent_id();
    let profile_body =
        format!(r#"{{"id":"{aid}","name":"ResearchAgent","updated_at":1,"event_id":"e"}}"#);
    server.enqueue(200, profile_body.clone());
    server.enqueue(200, r#"{"result":[]}"#);
    server.enqueue(200, r#"{"result":[]}"#);
    server.enqueue(200, profile_body);

    block_on(async {
        let _default_client = ProfileClient::new(format!("{}/", server.base_url));
        let client = ProfileClient::with_client(format!("{}/", server.base_url), no_proxy_client());
        let agent_id: AgentId = aid.parse().unwrap();

        let profile = client.get_profile(&agent_id).await.unwrap();
        assert_eq!(profile.name, "ResearchAgent");

        let batch = client
            .get_profiles(std::slice::from_ref(&agent_id))
            .await
            .unwrap();
        assert!(batch.result.is_empty());

        let events = client.profile_events(&agent_id, Some(5)).await.unwrap();
        assert!(events.result.is_empty());

        let mut payload = ProfileUpdatePayload::new(agent_id.clone(), "ResearchAgent");
        payload.description = Some("desc".to_owned());
        let envelope = AgentSigner::from_seed([1; 32])
            .sign_event(profile_update_event(agent_id.clone(), 1, 1, payload))
            .unwrap();
        let updated = client.submit_profile_update(&envelope).await.unwrap();
        assert_eq!(updated.name, "ResearchAgent");
    });

    let requests = server.requests();
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].path, format!("/v1/profiles/{aid}"));
    assert_eq!(requests[1].method, "POST");
    assert_eq!(requests[1].path, "/v1/profiles/batch");
    assert!(requests[1].body.contains(&aid));
    assert_eq!(
        requests[2].path,
        format!("/v1/profiles/{aid}/events?limit=5")
    );
    assert_eq!(requests[3].method, "POST");
    assert_eq!(requests[3].path, "/v1/profiles");
}

#[test]
fn profile_events_without_limit_omits_query() {
    let server = MockServer::start();
    let aid = sample_agent_id();
    server.enqueue(200, r#"{"result":[]}"#);
    block_on(async {
        let client = ProfileClient::with_client(&server.base_url, no_proxy_client());
        let agent_id: AgentId = aid.parse().unwrap();
        client.profile_events(&agent_id, None).await.unwrap();
    });
    assert_eq!(
        server.requests()[0].path,
        format!("/v1/profiles/{aid}/events")
    );
}

#[test]
fn discourse_client_round_trips_every_endpoint() {
    let server = MockServer::start();
    let record_body = server_record_body();
    let aid = sample_agent_id();
    let applicant = AgentSigner::from_seed([5; 32]);
    let join_envelope = applicant
        .sign_event(room_join_request_event(
            applicant.agent_id(),
            1,
            1,
            "room1",
            RoomJoinRequestPayload::new(Role::Speaker),
        ))
        .unwrap();
    let join_status = serde_json::json!({
        "id": join_envelope.hash,
        "request": join_envelope,
        "status": "pending",
        "expires_at": 2
    })
    .to_string();
    let room_body =
        r#"{"id":"room1","status":"active","url":"http://x","seq":1,"hash":"h","accepted_at":1}"#;
    let status_body = format!(
        r#"{{"room_id":"room1","agent_id":"{aid}","state":"idle","expires_at":2,"updated_at":1}}"#
    );

    server.enqueue(
        200,
        r#"{"protocol":"agent-discourse/1.0","service":"https://api.example.com"}"#,
    );
    server.enqueue(200, room_body); // create_room
    server.enqueue(200, room_body); // room
    server.enqueue(200, r#"{"result":[]}"#); // public_rooms
    server.enqueue(200, r#"{"result":[]}"#); // my_rooms
    server.enqueue(200, join_status.clone()); // request_join
    server.enqueue(200, join_status.clone()); // join_request
    server.enqueue(200, format!(r#"{{"result":[{join_status}]}}"#)); // join_requests
    server.enqueue(200, record_body.clone()); // join_room
    server.enqueue(200, record_body.clone()); // leave_room
    server.enqueue(200, record_body.clone()); // submit_event
    server.enqueue(200, r#"{"result":[]}"#); // events
    server.enqueue(200, r#"{"result":[],"next_cursor":"n"}"#); // events_with_options
    server.enqueue(200, r#"{"result":[]}"#); // agent_statuses
    server.enqueue(200, status_body.clone()); // agent_status
    server.enqueue(200, status_body); // set_agent_status
    server.enqueue(200, r#"{"manifest":true}"#); // archive

    block_on(async {
        let _default_client = DiscourseClient::new(&server.base_url);
        let client = DiscourseClient::with_client(&server.base_url, no_proxy_client());
        let signer = AgentSigner::from_seed([3; 32]);

        let discovery = client.protocol().await.unwrap();
        assert_eq!(discovery.service, "https://api.example.com");

        let create_envelope = signer
            .sign_event(room_create_event(
                signer.agent_id(),
                1,
                1,
                RoomCreatePayload::new(
                    "https://api.example.com",
                    "Topic",
                    Visibility::Public,
                    1,
                    2,
                ),
            ))
            .unwrap();
        client.create_room(&create_envelope).await.unwrap();
        client.room("room1", None).await.unwrap();
        client
            .public_rooms(&PublicRoomsOptions {
                status: Some("active".to_owned()),
                tag: Some("a b".to_owned()),
                limit: Some(5),
                cursor: Some("c d".to_owned()),
                ..PublicRoomsOptions::default()
            })
            .await
            .unwrap();
        client.my_rooms("jwt-me").await.unwrap();

        let request = client.request_join("room1", &join_envelope).await.unwrap();
        assert_eq!(request.id, join_envelope.hash);
        client
            .join_request("room1", &join_envelope.hash, "jwt-b")
            .await
            .unwrap();
        let requests = client
            .join_requests(
                "room1",
                "jwt-c",
                &JoinRequestsOptions {
                    status: Some("pending".to_owned()),
                    ..JoinRequestsOptions::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(requests.result.len(), 1);

        let join = signer
            .sign_event(discourse_event(
                event_type::ROOM_JOIN,
                signer.agent_id(),
                1,
                1,
                "room1",
                1,
                "room-head-hash",
                RoomJoinPayload {
                    role: Role::Speaker,
                    perspective: None,
                },
            ))
            .unwrap();
        client.join_room("room1", &join).await.unwrap();

        let leave_envelope = signer
            .sign_event(discourse_event(
                event_type::ROOM_LEAVE,
                signer.agent_id(),
                1,
                2,
                "room1",
                1,
                "room-head-hash",
                RoomLeavePayload::default(),
            ))
            .unwrap();
        client.leave_room("room1", &leave_envelope).await.unwrap();

        let message_envelope = signer
            .sign_event(discourse_event(
                event_type::MESSAGE_CREATE,
                signer.agent_id(),
                1,
                3,
                "room1",
                1,
                "room-head-hash",
                serde_json::json!({"content_type": "text/plain", "content": "hi"}),
            ))
            .unwrap();
        client
            .submit_event("room1", &message_envelope)
            .await
            .unwrap();

        client.events("room1").await.unwrap();
        let page = client
            .events_with_options(
                "room1",
                &RoomEventsOptions {
                    after_seq: Some(7),
                    limit: Some(10),
                    cursor: Some("a b".to_owned()),
                    jwt: Some("jwt-d".to_owned()),
                },
            )
            .await
            .unwrap();
        assert_eq!(page.next_cursor.as_deref(), Some("n"));

        let agent_id: AgentId = aid.parse().unwrap();
        let statuses = client
            .agent_statuses("room1", Some("jwt-status-list"))
            .await
            .unwrap();
        assert!(statuses.result.is_empty());
        let status = client
            .agent_status("room1", &agent_id, Some("jwt-status-get"))
            .await
            .unwrap();
        assert_eq!(status.state, "idle");
        let status = client
            .set_agent_status(
                "room1",
                "jwt-status-set",
                &AgentStatusInput::new("idle").with_expires_at(2),
            )
            .await
            .unwrap();
        assert_eq!(status.agent_id, agent_id);

        assert_eq!(
            client.sse_events_url("room1"),
            sse_events_url(&server.base_url, "room1")
        );

        let archive = client.archive("room1").await.unwrap();
        assert_eq!(archive, serde_json::json!({"manifest": true}));
    });

    let requests = server.requests();
    assert_eq!(requests[0].path, "/.well-known/agent-discourse");
    assert_eq!(requests[1].path, "/v1/rooms");
    assert_eq!(requests[2].path, "/v1/rooms/room1");
    assert_eq!(
        requests[3].path,
        "/v1/rooms/public?status=active&tag=a%20b&limit=5&cursor=c%20d"
    );
    assert_eq!(requests[4].path, "/v1/me/rooms");
    assert_eq!(requests[4].authorization.as_deref(), Some("Bearer jwt-me"));
    // The signed request authenticates the applicant; no JWT is sent.
    assert_eq!(requests[5].path, "/v1/rooms/room1/join-requests");
    assert_eq!(requests[5].authorization, None);
    assert!(requests[5].body.contains("room.join.request"));
    assert_eq!(requests[6].authorization.as_deref(), Some("Bearer jwt-b"));
    assert_eq!(
        requests[7].path,
        "/v1/rooms/room1/join-requests?status=pending"
    );
    assert_eq!(requests[7].authorization.as_deref(), Some("Bearer jwt-c"));
    assert_eq!(requests[11].path, "/v1/rooms/room1/events");
    assert_eq!(
        requests[12].path,
        "/v1/rooms/room1/events?after_seq=7&limit=10&cursor=a%20b"
    );
    assert_eq!(requests[12].authorization.as_deref(), Some("Bearer jwt-d"));
    assert_eq!(requests[13].path, "/v1/rooms/room1/agent-status");
    assert_eq!(
        requests[13].authorization.as_deref(),
        Some("Bearer jwt-status-list")
    );
    assert_eq!(
        requests[14].path,
        format!("/v1/rooms/room1/agent-status/{aid}")
    );
    assert_eq!(
        requests[14].authorization.as_deref(),
        Some("Bearer jwt-status-get")
    );
    assert_eq!(requests[15].method, "PUT");
    assert_eq!(requests[15].path, "/v1/rooms/room1/agent-status");
    assert_eq!(
        requests[15].authorization.as_deref(),
        Some("Bearer jwt-status-set")
    );
    assert!(requests[15].body.contains("\"state\":\"idle\""));
    assert_eq!(requests[16].path, "/v1/rooms/room1/archive");
}

fn credential_body(id: &str) -> String {
    const PRINCIPAL_ID: &str = "https://api.al.ink/d9c6a99cne5g00a6scn0";
    let aid = sample_agent_id();
    format!(
        r#"{{"id":"{id}","protocol":"agent-delegation/1.0","principal_id":"{PRINCIPAL_ID}","controller":"{aid}","owner_controller":"{aid}","grant_event_id":"e","accepted_at":1,"subject":"{aid}","scopes":["inbox.screen"],"audiences":["https://dmsg.net"],"status":"active","updated_at":1,"checked_at":2,"event_id":"e"}}"#
    )
}

#[test]
fn delegation_client_round_trips_every_endpoint() {
    const PRINCIPAL_ID: &str = "https://api.al.ink/d9c6a99cne5g00a6scn0";
    let server = MockServer::start();
    let aid = sample_agent_id();

    server.enqueue(
        200,
        r#"{"protocol":"agent-delegation/1.0","service":"https://api.al.ink","endpoints":{"delegations":"https://api.al.ink/v1/delegations"}}"#,
    );
    server.enqueue(200, credential_body("del_1"));
    server.enqueue(200, r#"{"result":[]}"#);
    server.enqueue(200, credential_body("del_1"));
    server.enqueue(200, r#"{"result":[]}"#);

    block_on(async {
        let client =
            DelegationClient::with_client(format!("{}/", server.base_url), no_proxy_client());
        let signer = AgentSigner::from_seed([4; 32]);
        let agent_id: AgentId = aid.parse().unwrap();

        let discovery = client.protocol().await.unwrap();
        assert_eq!(discovery.protocol, "agent-delegation/1.0");
        // Principal identifiers must be HTTPS, so a plain-HTTP mock origin can
        // never publish a valid principal document.
        let err = client
            .principal(Some(&format!("{}/yan", server.base_url)))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("HTTPS"), "{err}");
        let credential = client.delegation("del_1").await.unwrap();
        assert_eq!(credential.id, "del_1");
        let events = client.delegation_events("del_1", None).await.unwrap();
        assert!(events.result.is_empty());

        let envelope = signer
            .sign_event(delegation_revoke_event(
                signer.agent_id(),
                1,
                1,
                DelegationRevokePayload {
                    id: "del_1".to_owned(),
                    principal_id: PRINCIPAL_ID.to_owned(),
                    reason: None,
                },
            ))
            .unwrap();
        let response = client.submit_delegation_event(&envelope).await.unwrap();
        assert_eq!(response.status, DelegationStatus::Active);
        let query = client
            .query_delegations(
                &DelegationQueryRequest {
                    subject: Some(agent_id),
                    principal_id: Some(PRINCIPAL_ID.to_owned()),
                    status: Some(DelegationStatus::Active),
                    limit: Some(20),
                    ..DelegationQueryRequest::default()
                },
                None,
            )
            .await
            .unwrap();
        assert!(query.result.is_empty());
    });

    let requests = server.requests();
    assert_eq!(requests[0].path, "/.well-known/agent-delegation");
    assert_eq!(requests[1].path, "/v1/delegations/del_1");
    assert_eq!(requests[2].path, "/v1/delegations/del_1/events");
    assert_eq!(requests[3].method, "POST");
    assert_eq!(requests[3].path, "/v1/delegations");
    assert_eq!(requests[4].method, "POST");
    assert_eq!(requests[4].path, "/v1/delegations/query");
    assert!(requests[4].body.contains("active"));
}

#[test]
fn delegation_client_prefers_discovered_endpoints_and_pages_history() {
    let server = MockServer::start();
    let base = server.base_url.clone();
    server.enqueue(
        200,
        format!(
            r#"{{"protocol":"agent-delegation/1.0","service":"{base}","endpoints":{{"delegations":"{base}/api/grants","query":"{base}/api/find"}}}}"#
        ),
    );
    server.enqueue(200, r#"{"result":[],"next_cursor":"c1"}"#);
    server.enqueue(200, r#"{"result":[]}"#);
    server.enqueue(200, r#"{"result":[]}"#);

    block_on(async {
        let client = DelegationClient::discover_with_client(&base, no_proxy_client()).await;
        let records = client.all_delegation_events("del_1").await.unwrap();
        assert!(records.is_empty());
        client
            .query_delegations(
                &DelegationQueryRequest {
                    subject: Some(sample_agent_id().parse().unwrap()),
                    principal_id: Some("https://example.com/p".to_owned()),
                    ..DelegationQueryRequest::default()
                },
                None,
            )
            .await
            .unwrap();
        // Invalid IDs are rejected before any request.
        for id in ["a/b", ".", "..", ""] {
            assert!(client.delegation(id).await.is_err(), "{id}");
        }
        // Without discovery, the RECOMMENDED paths apply.
        let fallback = DelegationClient::with_endpoints(
            &base,
            no_proxy_client(),
            &DelegationServiceEndpoints::default(),
        );
        drop(fallback);
    });

    let paths = server
        .requests()
        .iter()
        .map(|request| request.path.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        vec![
            "/.well-known/agent-delegation".to_owned(),
            "/api/grants/del_1/events".to_owned(),
            "/api/grants/del_1/events?cursor=c1".to_owned(),
            "/api/find".to_owned(),
        ]
    );
}

#[test]
fn delegation_discovery_falls_back_to_default_paths() {
    let server = MockServer::start();
    server.enqueue(404, r#"{"error":{"code":"not_found","message":"none"}}"#);
    server.enqueue(200, r#"{"result":[]}"#);
    block_on(async {
        let client =
            DelegationClient::discover_with_client(&server.base_url, no_proxy_client()).await;
        client.delegation_events("del_1", None).await.unwrap();
    });
    assert_eq!(server.requests()[1].path, "/v1/delegations/del_1/events");
}

#[test]
fn error_responses_carry_code_data_and_max_seen_nonce() {
    let server = MockServer::start();
    server.enqueue(500, "boom");
    server.enqueue_with_header(
        409,
        r#"{"error":{"code":"nonce_not_greater","message":"stale","data":{"max_nonce":10}}}"#,
        "Max-Seen-Nonce",
        "10",
    );
    let aid = sample_agent_id();
    block_on(async {
        let profile_client = ProfileClient::with_client(&server.base_url, no_proxy_client());
        let agent_id: AgentId = aid.parse().unwrap();
        match profile_client.get_profile(&agent_id).await {
            Err(SdkError::HttpStatus {
                status: 500,
                code: None,
                body,
                ..
            }) => assert_eq!(body, "boom"),
            other => panic!("unexpected {other:?}"),
        }

        let discourse_client = DiscourseClient::with_client(&server.base_url, no_proxy_client());
        let error = discourse_client.room("room1", None).await.unwrap_err();
        assert_eq!(error.code(), Some("nonce_not_greater"));
        match error {
            SdkError::HttpStatus {
                status,
                data,
                max_seen_nonce,
                ..
            } => {
                assert_eq!(status, 409);
                assert_eq!(data, Some(serde_json::json!({"max_nonce": 10})));
                assert_eq!(max_seen_nonce.as_deref(), Some("10"));
            }
            other => panic!("unexpected {other:?}"),
        }
    });
}

#[test]
fn builds_sse_events_url_variants() {
    assert_eq!(
        sse_events_url("https://api.example.com", "room123"),
        "https://api.example.com/v1/rooms/room123/events/live"
    );
    assert_eq!(
        sse_events_url("http://api.example.com/", "room 1"),
        "http://api.example.com/v1/rooms/room%201/events/live"
    );
    assert_eq!(
        sse_events_url("ftp://api.example.com", "r"),
        "ftp://api.example.com/v1/rooms/r/events/live"
    );
}

#[cfg(feature = "local-connector")]
mod connector_regressions {
    use super::*;
    use agent_protocols::discourse::{RoomResponse, ServerRecord};
    use agent_protocols::local_connector::*;
    use serde_json::{json, Value};

    fn fixture() -> (MockServer, LocalConnector, AgentSigner, ServerRecord) {
        let server = MockServer::start();
        let author = AgentSigner::from_seed([80; 32]);
        let envelope = author
            .sign_event(room_create_event(
                author.agent_id(),
                100,
                1,
                RoomCreatePayload::new(
                    "https://api.example.test",
                    "Room",
                    Visibility::Public,
                    1,
                    10_000_000_000_000,
                ),
            ))
            .unwrap();
        let genesis = build_server_record("room1", 1, None, 100, envelope).unwrap();
        let room: RoomResponse = serde_json::from_value(json!({
            "id": "room1", "status": "active", "visibility": "public",
            "url": format!("{}/v1/rooms/room1", server.base_url),
            "seq": 1, "pre_hash": null, "hash": genesis.hash, "accepted_at": 100,
            "head": { "seq": 1, "hash": genesis.hash }, "envelope": genesis.envelope,
        }))
        .unwrap();
        let mut connector = LocalConnector::new(AgentSigner::from_seed([81; 32]))
            .with_http_client(no_proxy_client());
        connector.add_host(AgentProtocolsHost {
            host: server.base_url.clone(),
            label: None,
            allowed: true,
            features: vec![],
            profile_service: None,
            last_checked_at: None,
        });
        // The same snapshot initialization is used by room_create and direct joins.
        connector.accept_room_response(&server.base_url, room);
        let genesis = serde_json::from_value(serde_json::to_value(genesis).unwrap()).unwrap();
        (server, connector, author, genesis)
    }

    fn next_record(
        author: &AgentSigner,
        kind: &str,
        payload: Value,
        head: &ServerRecord,
        previous: &ServerRecord,
    ) -> ServerRecord {
        let seq = previous.seq + 1;
        let envelope = author
            .sign_event(discourse_event(
                kind,
                author.agent_id(),
                100 + seq as i64,
                seq,
                "room1",
                head.seq,
                &head.hash,
                payload,
            ))
            .unwrap();
        build_server_record(
            "room1",
            seq,
            Some(previous.hash.clone()),
            100 + seq as i64,
            envelope,
        )
        .unwrap()
    }

    #[test]
    fn snapshot_head_advances_through_consecutive_own_messages() {
        let (server, mut connector, _, genesis) = fixture();
        let active = AgentSigner::from_seed([81; 32]);
        block_on(async {
            connector
                .call_tool(TOOL_ROOM_STATE, json!({"room_id": "room1"}))
                .await
                .unwrap();
            let mut head = genesis;
            for content in ["first", "second"] {
                let next = next_record(
                    &active,
                    event_type::MESSAGE_CREATE,
                    json!({"content_type": "text/plain", "content": content}),
                    &head,
                    &head,
                );
                server.enqueue(200, serde_json::to_string(&next).unwrap());
                let result = connector
                    .call_tool(
                        TOOL_ROOM_SEND_MESSAGE,
                        json!({"room_id": "room1", "content": content}),
                    )
                    .await
                    .unwrap();
                assert_eq!(result["status"], "sent");
                assert_eq!(result["sync"]["presented_seq"], next.seq);
                head = next;
            }
        });
    }

    #[test]
    fn failed_and_rejected_draft_commits_preserve_the_draft() {
        let (server, mut connector, other, genesis) = fixture();
        block_on(async {
            connector
                .call_tool(TOOL_ROOM_STATE, json!({"room_id": "room1"}))
                .await
                .unwrap();
            let message = json!({"content_type": "text/plain", "content": "context"});
            let second = next_record(
                &other,
                event_type::MESSAGE_CREATE,
                message.clone(),
                &genesis,
                &genesis,
            );
            connector
                .apply_host_record(&server.base_url, second.clone())
                .unwrap();
            let held = connector
                .call_tool(
                    TOOL_ROOM_SEND_MESSAGE,
                    json!({"room_id": "room1", "content": "draft"}),
                )
                .await
                .unwrap();
            let id = held["draft"]["id"].as_str().unwrap();
            server.enqueue(503, r#"{"error":{"code":"unavailable","message":"retry"}}"#);
            assert!(connector
                .call_tool(TOOL_DRAFT_COMMIT, json!({"draft_id": id, "action": "send"}))
                .await
                .is_err());
            let drafts = connector
                .call_tool(TOOL_DRAFTS_LIST, json!({}))
                .await
                .unwrap();
            assert_eq!(drafts["drafts"][0]["id"], id);

            let third = next_record(
                &other,
                event_type::MESSAGE_CREATE,
                message,
                &second,
                &second,
            );
            connector
                .apply_host_record(&server.base_url, third.clone())
                .unwrap();
            let rejected = connector
                .call_tool(
                    TOOL_DRAFT_COMMIT,
                    json!({"draft_id": id, "action": "send", "on_head_mismatch": "reject"}),
                )
                .await
                .unwrap();
            assert_eq!(rejected["status"], "rejected");
            let drafts = connector
                .call_tool(TOOL_DRAFTS_LIST, json!({}))
                .await
                .unwrap();
            assert_eq!(drafts["drafts"][0]["id"], id);

            let fourth = next_record(
                &AgentSigner::from_seed([81; 32]),
                event_type::MESSAGE_CREATE,
                json!({"content_type": "text/plain", "content": "draft"}),
                &third,
                &third,
            );
            server.enqueue(200, serde_json::to_string(&fourth).unwrap());
            let sent = connector
                .call_tool(TOOL_DRAFT_COMMIT, json!({"draft_id": id, "action": "send"}))
                .await
                .unwrap();
            assert_eq!(sent["status"], "sent");
            let drafts = connector
                .call_tool(TOOL_DRAFTS_LIST, json!({}))
                .await
                .unwrap();
            assert!(drafts["drafts"].as_array().unwrap().is_empty());
        });
    }

    #[test]
    fn banned_members_request_review_for_known_and_remote_bans() {
        for (known, nonce_retry) in [(true, false), (false, false), (false, true)] {
            let (server, mut connector, moderator, genesis) = fixture();
            let applicant = AgentSigner::from_seed([81; 32]);
            if known {
                let ban = next_record(
                    &moderator,
                    event_type::ROOM_MEMBER_REMOVE,
                    json!({"member": applicant.agent_id(), "ban": true}),
                    &genesis,
                    &genesis,
                );
                connector.apply_host_record(&server.base_url, ban).unwrap();
            } else {
                if nonce_retry {
                    server.enqueue_with_header(
                        409,
                        r#"{"error":{"code":"nonce_not_greater","message":"resync"}}"#,
                        "Max-Seen-Nonce",
                        "1",
                    );
                }
                server.enqueue(
                    403,
                    r#"{"error":{"code":"member_banned","message":"request review"}}"#,
                );
            }
            let request = applicant
                .sign_event(room_join_request_event(
                    applicant.agent_id(),
                    200,
                    3,
                    "room1",
                    RoomJoinRequestPayload::new(Role::Speaker),
                ))
                .unwrap();
            server.enqueue(
                200,
                json!({
                    "id": request.hash, "request": request, "status": "pending", "expires_at": 1000,
                })
                .to_string(),
            );
            let result = block_on(connector.call_tool(
                TOOL_ROOM_JOIN,
                json!({"room_id": "room1", "role": "speaker"}),
            ))
            .unwrap();
            assert_eq!(result["status"], "approval_required");
            let requests = server.requests();
            assert_eq!(
                requests.len(),
                if known {
                    1
                } else if nonce_retry {
                    3
                } else {
                    2
                }
            );
            let last = requests.last().unwrap();
            assert_eq!(last.path, "/v1/rooms/room1/join-requests");
            let envelope: Value = serde_json::from_str(&last.body).unwrap();
            assert_eq!(envelope["event"]["type"], event_type::ROOM_JOIN_REQUEST);
            assert!(envelope["event"].get("base_seq").is_none());
        }
    }
}
