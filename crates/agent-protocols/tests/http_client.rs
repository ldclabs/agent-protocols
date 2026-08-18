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
    delegation_revoke_event, DelegationQueryRequest, DelegationRevokePayload, DelegationStatus,
};
use agent_protocols::discourse::{
    build_server_record, discourse_event, event_type, room_create_event, AgentStatusInput, Role,
    RoomCreatePayload, RoomJoinPayload, RoomJoinRequestInput, RoomLeavePayload, Visibility,
};
use agent_protocols::error::SdkError;
use agent_protocols::http_client::{
    sse_events_url, DelegationClient, DiscourseClient, ProfileClient, PublicRoomsOptions,
    RoomEventsOptions,
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

struct MockServer {
    base_url: String,
    responses: Arc<Mutex<VecDeque<(u16, String)>>>,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl MockServer {
    fn start() -> Self {
        let responses: Arc<Mutex<VecDeque<(u16, String)>>> = Arc::new(Mutex::new(VecDeque::new()));
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
                    let (status, body) = responses_for_server
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or((200, "null".to_owned()));
                    write_response(&mut socket, status, &body).await;
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
            .push_back((status, body.into()));
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

async fn write_response(socket: &mut TcpStream, status: u16, body: &str) {
    let response = format!(
        "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
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
                request_id: Some("jr1".to_owned()),
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
    let join_status = format!(
        r#"{{"request":{{"id":"jr1","room_id":"room1","applicant":"{aid}","role":"speaker","created_at":1,"expires_at":2}},"status":"pending"}}"#
    );
    let room_body =
        r#"{"id":"room1","status":"active","url":"http://x","seq":1,"hash":"h","received_at":1}"#;
    let status_body = format!(
        r#"{{"room_id":"room1","agent_id":"{aid}","state":"idle","expires_at":2,"updated_at":1}}"#
    );

    server.enqueue(
        200,
        r#"{"protocol":"agent-discourse/1.0","host":"example"}"#,
    );
    server.enqueue(200, room_body); // create_room
    server.enqueue(200, room_body); // room
    server.enqueue(200, "[]"); // public_rooms
    server.enqueue(200, "[]"); // my_rooms
    server.enqueue(200, join_status.clone()); // request_join
    server.enqueue(200, join_status.clone()); // join_request
    server.enqueue(200, format!("[{join_status}]")); // join_requests
    server.enqueue(200, record_body.clone()); // join_room
    server.enqueue(200, record_body.clone()); // leave_room
    server.enqueue(200, record_body.clone()); // submit_event
    server.enqueue(200, "[]"); // events
    server.enqueue(200, "[]"); // events_with_options
    server.enqueue(200, r#"{"statuses":[]}"#); // agent_statuses
    server.enqueue(200, format!(r#"{{"status":{status_body}}}"#)); // agent_status
    server.enqueue(200, status_body); // set_agent_status
    server.enqueue(200, r#"{"manifest":true}"#); // archive

    block_on(async {
        let _default_client = DiscourseClient::new(&server.base_url);
        let client = DiscourseClient::with_client(&server.base_url, no_proxy_client());
        let signer = AgentSigner::from_seed([3; 32]);

        client.protocol().await.unwrap();

        let create_envelope = signer
            .sign_event(room_create_event(
                signer.agent_id(),
                1,
                1,
                RoomCreatePayload::new("Topic", Visibility::Public, 1, 2),
            ))
            .unwrap();
        client.create_room(&create_envelope).await.unwrap();
        client.room("room1").await.unwrap();
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

        let input = RoomJoinRequestInput::new(Role::Speaker);
        client.request_join("room1", "jwt-a", &input).await.unwrap();
        client.join_request("room1", "jr1", "jwt-b").await.unwrap();
        client.join_requests("room1", "jwt-c").await.unwrap();

        let join_envelope = signer
            .sign_event(discourse_event(
                event_type::ROOM_JOIN,
                signer.agent_id(),
                1,
                1,
                "room1",
                1,
                "room-head-hash",
                RoomJoinPayload {
                    request_id: Some("jr1".to_owned()),
                    role: Role::Speaker,
                    perspective: None,
                },
            ))
            .unwrap();
        client.join_room("room1", &join_envelope).await.unwrap();

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
        client
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

        let agent_id: AgentId = aid.parse().unwrap();
        let statuses = client
            .agent_statuses("room1", Some("jwt-status-list"))
            .await
            .unwrap();
        assert!(statuses.statuses.is_empty());
        let status = client
            .agent_status("room1", &agent_id, Some("jwt-status-get"))
            .await
            .unwrap();
        assert_eq!(status.status.state, "idle");
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
    assert_eq!(requests[5].authorization.as_deref(), Some("Bearer jwt-a"));
    assert_eq!(requests[6].authorization.as_deref(), Some("Bearer jwt-b"));
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

#[test]
fn delegation_client_round_trips_every_endpoint() {
    const PRINCIPAL_ID: &str = "https://api.al.ink/d9c6a99cne5g00a6scn0";
    let server = MockServer::start();
    let aid = sample_agent_id();
    let credential_body = format!(
        r#"{{"id":"del_1","protocol":"agent-delegation/1.0","principal":{{"id":"{PRINCIPAL_ID}"}},"controller":"{aid}","subject":"{aid}","scopes":["inbox.screen"],"status":"active","updated_at":1,"event_id":"e"}}"#
    );
    let status_body = r#"{"id":"del_1","status":"active","checked_at":2,"event_id":"e"}"#;

    server.enqueue(
        200,
        r#"{"protocol":"agent-delegation/1.0","service":"https://api.al.ink","endpoints":{"delegations":"https://api.al.ink/v1/delegations"}}"#,
    );
    // Served at its own `id` so resolution stops here instead of following the
    // document off to a real network host.
    server.enqueue(
        200,
        format!(
            r#"{{"id":"{}/yan","controllers":["{aid}"]}}"#,
            server.base_url
        ),
    );
    server.enqueue(200, credential_body);
    server.enqueue(200, status_body);
    server.enqueue(200, r#"{"result":[]}"#);
    server.enqueue(200, status_body);
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
        let status = client.delegation_status("del_1").await.unwrap();
        assert_eq!(status.status, DelegationStatus::Active);
        let events = client.delegation_events("del_1").await.unwrap();
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
        assert_eq!(response["status"], "active");
        let query = client
            .query_delegations(
                &DelegationQueryRequest {
                    subject: Some(agent_id),
                    principal_id: Some(PRINCIPAL_ID.to_owned()),
                    status: Some(DelegationStatus::Active),
                    limit: Some(20),
                    ..DelegationQueryRequest::default()
                },
                false,
            )
            .await
            .unwrap();
        assert!(query.result.is_empty());
    });

    let requests = server.requests();
    assert_eq!(requests[0].path, "/.well-known/agent-delegation");
    assert_eq!(requests[1].path, "/yan");
    assert_eq!(requests[2].path, "/v1/delegations/del_1");
    assert_eq!(requests[3].path, "/v1/delegations/del_1/status");
    assert_eq!(requests[4].path, "/v1/delegations/del_1/events");
    assert_eq!(requests[5].method, "POST");
    assert_eq!(requests[5].path, "/v1/delegations");
    assert_eq!(requests[6].method, "POST");
    assert_eq!(requests[6].path, "/v1/delegations/query");
    assert!(requests[6].body.contains("active"));
}

#[test]
fn error_status_is_propagated() {
    let server = MockServer::start();
    server.enqueue(500, r#"{"error":"boom"}"#);
    server.enqueue(503, r#"{"error":"unavailable"}"#);
    let aid = sample_agent_id();
    block_on(async {
        let profile_client = ProfileClient::with_client(&server.base_url, no_proxy_client());
        let agent_id: AgentId = aid.parse().unwrap();
        assert!(matches!(
            profile_client.get_profile(&agent_id).await,
            Err(SdkError::Http(_))
        ));

        let discourse_client = DiscourseClient::with_client(&server.base_url, no_proxy_client());
        assert!(matches!(
            discourse_client.room("room1").await,
            Err(SdkError::Http(_))
        ));
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
