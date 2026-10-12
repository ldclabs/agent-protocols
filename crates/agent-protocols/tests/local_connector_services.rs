//! The local connector's Mail and Knowledge tools against the SDK's own
//! reference relay and Knowledge store, served over an in-process HTTPS
//! server. Two connectors play sender and recipient.
#![cfg(feature = "local-connector")]

use agent_protocols::{
    identity::{unix_ms, AgentSigner},
    knowledge::{
        knowledge_query_matches, knowledge_text_matches, parse_knowledge_query,
        KnowledgeSearchSelection, KnowledgeStore,
    },
    local_connector::*,
    mail::MailRelayStore,
    SdkError,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig, ServerConnection, StreamOwned,
};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
};

const CERT: &[u8] = include_bytes!("fixtures/knowledge-tls/cert.der");
const KEY: &[u8] = include_bytes!("fixtures/knowledge-tls/key.der");

struct Request {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    authorization: Option<String>,
    body: String,
}

/// One origin serving both a Mail relay and a Knowledge service.
struct Services {
    origin: String,
    relay: Mutex<MailRelayStore>,
    knowledge: Mutex<KnowledgeStore>,
    /// Packet deliveries to answer with 503 before serving them.
    failing_deliveries: AtomicUsize,
    packets_deleted: AtomicUsize,
}

impl Services {
    fn start() -> Arc<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let services = Arc::new(Self {
            relay: Mutex::new(MailRelayStore::new(&origin).unwrap()),
            knowledge: Mutex::new(KnowledgeStore::new(&origin).unwrap()),
            origin,
            failing_deliveries: AtomicUsize::new(0),
            packets_deleted: AtomicUsize::new(0),
        });
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let config = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(CERT.to_vec())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec())),
                )
                .unwrap(),
        );
        let server = services.clone();
        thread::spawn(move || {
            for socket in listener.incoming() {
                let Ok(socket) = socket else { break };
                let mut stream =
                    StreamOwned::new(ServerConnection::new(config.clone()).unwrap(), socket);
                let Some(request) = read_request(&mut stream) else {
                    continue;
                };
                let (status, body, headers) = server.handle(request);
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        services
    }

    fn handle(&self, request: Request) -> (u16, String, String) {
        let now = unix_ms();
        let segments: Vec<&str> = request.path.trim_start_matches('/').split('/').collect();
        let body = || serde_json::from_str::<Value>(&request.body).unwrap_or(Value::Null);
        let jwt = || {
            request
                .authorization
                .as_deref()
                .and_then(|value| value.strip_prefix("Bearer "))
                .unwrap_or_default()
                .to_owned()
        };
        let result: Result<(u16, Value), SdkError> = match (request.method.as_str(), &segments[..])
        {
            ("POST", ["v1", "mailboxes"]) => self
                .relay
                .lock()
                .unwrap()
                .publish(&body(), now)
                .map(|record| (200, json!(record))),
            ("GET", ["v1", "mailboxes", mailbox, "card"]) => self
                .relay
                .lock()
                .unwrap()
                .card(mailbox)
                .map(|record| (200, json!(record))),
            ("POST", ["v1", "mailboxes", mailbox, "packets"]) => {
                let failing = self.failing_deliveries.load(Ordering::SeqCst);
                if failing > 0 {
                    self.failing_deliveries.store(failing - 1, Ordering::SeqCst);
                    return error(503, "service_unavailable", "relay restarting");
                }
                let packet = serde_json::from_value(body()).unwrap();
                self.relay
                    .lock()
                    .unwrap()
                    .deliver(mailbox, &packet, now)
                    .map(|result| (202, json!(result)))
            }
            ("GET", ["v1", "mailboxes", mailbox, "packets"]) => {
                let limit = query(&request, "limit").map_or(100, |v| v.parse().unwrap());
                self.relay
                    .lock()
                    .unwrap()
                    .list(mailbox, &jwt(), now, limit, query(&request, "cursor"))
                    .map(|list| (200, json!(list)))
            }
            ("DELETE", ["v1", "mailboxes", mailbox, "packets", packet]) => {
                let deleted = self
                    .relay
                    .lock()
                    .unwrap()
                    .delete(mailbox, packet, &jwt(), now);
                if deleted.is_ok() {
                    self.packets_deleted.fetch_add(1, Ordering::SeqCst);
                    return (204, String::new(), String::new());
                }
                deleted.map(|_| (204, Value::Null))
            }
            ("GET", [".well-known", "agent-knowledge"]) => Ok((
                200,
                json!({
                    "protocol": "agent-knowledge/1.0",
                    "service": self.origin,
                    "endpoints": {
                        "events": format!("{}/v1/knowledge/events", self.origin),
                        "query": format!("{}/v1/knowledge/query", self.origin),
                        "batch": format!("{}/v1/knowledge/batch", self.origin),
                        "search": format!("{}/v1/knowledge/search", self.origin)
                    },
                    "features": ["ranked-search"],
                    "search_modes": ["lexical"]
                }),
            )),
            ("POST", ["v1", "knowledge", "events"]) => self
                .knowledge
                .lock()
                .unwrap()
                .submit(&body(), now)
                .map(|record| (200, record)),
            ("GET", ["v1", "knowledge", "query"]) => parse_knowledge_query(&request.query)
                .and_then(|query| self.knowledge.lock().unwrap().query(&query, now))
                .map(|page| (200, page)),
            ("POST", ["v1", "knowledge", "batch"]) => self
                .knowledge
                .lock()
                .unwrap()
                .batch(&body(), now)
                .map(|page| (200, page)),
            ("POST", ["v1", "knowledge", "search"]) => {
                let request = body();
                let store = self.knowledge.lock().unwrap();
                // Every lexical match, so the page may claim exhaustive coverage.
                let candidates = store
                    .known_envelopes()
                    .into_iter()
                    .filter(|(_, envelope)| {
                        knowledge_query_matches(
                            envelope,
                            request.get("filters").unwrap_or(&json!({})),
                        )
                        .unwrap()
                            && knowledge_text_matches(envelope, request["text"].as_str().unwrap())
                                .unwrap()
                    })
                    .map(|(id, _)| id)
                    .collect();
                let selection = KnowledgeSearchSelection {
                    candidates,
                    ranking: json!({"mode": "lexical", "id": "test-1"}),
                    coverage: json!({"exhaustive": true, "reasons": []}),
                    explanations: Default::default(),
                };
                store
                    .search(&request, &selection, &["lexical".to_owned()], now)
                    .map(|page| (200, page))
            }
            _ => return error(404, "not_found", "no route"),
        };
        match result {
            Ok((status, value)) => (status, value.to_string(), String::new()),
            Err(SdkError::NonceNotGreater { max_nonce }) => {
                let (status, body, _) = error(409, "nonce_not_greater", "stale nonce");
                (status, body, format!("Max-Seen-Nonce: {max_nonce}\r\n"))
            }
            Err(failure) => {
                let code = failure.code().unwrap_or("invalid_request").to_owned();
                let status = match code.as_str() {
                    "mailbox_unavailable" | "not_found" => 404,
                    "stale_card" | "mailbox_conflict" | "missing_dependency" => 409,
                    "packet_expired" => 410,
                    "permission_denied" => 403,
                    "invalid_token" => 401,
                    "payload_too_large" => 413,
                    "rate_limited" => 429,
                    _ => 400,
                };
                let mut body = json!({"error": {"code": code, "message": failure.to_string()}});
                if let Some(data) = failure.data() {
                    body["error"]["data"] = data.clone();
                }
                (status, body.to_string(), String::new())
            }
        }
    }

    fn connector(&self, seed: u8) -> LocalConnector {
        let mut connector =
            LocalConnector::new(AgentSigner::from_seed([seed; 32])).with_http_client(tls_client());
        connector.add_host(allowed(&self.origin));
        connector
    }

    /// Packets the relay still holds for a mailbox.
    fn packets(&self, mailbox: &str) -> usize {
        let relay = self.relay.lock().unwrap();
        let snapshot = relay.snapshot().unwrap();
        snapshot["mailboxes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["current"]["envelope"]["event"]["payload"]["mailbox_id"] == mailbox)
            .map_or(0, |m| m["packets"].as_array().unwrap().len())
    }
}

fn error(status: u16, code: &str, message: &str) -> (u16, String, String) {
    (
        status,
        json!({"error": {"code": code, "message": message}}).to_string(),
        String::new(),
    )
}

fn query<'a>(request: &'a Request, key: &str) -> Option<&'a str> {
    request
        .query
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

fn read_request(stream: &mut impl Read) -> Option<Request> {
    let mut input = Vec::new();
    let mut buf = [0u8; 4096];
    let end = loop {
        if let Some(pos) = input.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        input.extend_from_slice(&buf[..n]);
    };
    let header = String::from_utf8_lossy(&input[..end]).into_owned();
    let mut lines = header.split("\r\n");
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.to_owned();
    let target = url::Url::parse(&format!("https://localhost{}", first.next()?)).ok()?;
    let mut length = 0;
    let mut authorization = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().ok()?;
            }
            if name.eq_ignore_ascii_case("authorization") {
                authorization = Some(value.trim().to_owned());
            }
        }
    }
    while input.len() - end - 4 < length {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        input.extend_from_slice(&buf[..n]);
    }
    Some(Request {
        method,
        path: target.path().to_owned(),
        query: target.query_pairs().into_owned().collect(),
        authorization,
        body: String::from_utf8_lossy(&input[end + 4..]).into_owned(),
    })
}

/// Trusts only the test certificate and, like the default transport, follows
/// no redirects.
fn tls_client() -> reqwest::Client {
    reqwest::Client::builder()
        .tls_certs_only(vec![reqwest::Certificate::from_der(CERT).unwrap()])
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap()
}

fn allowed(host: &str) -> AgentProtocolsHost {
    AgentProtocolsHost {
        host: host.to_owned(),
        label: None,
        allowed: true,
        features: Vec::new(),
        profile_service: None,
        last_checked_at: None,
    }
}

fn run<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

async fn call(connector: &mut LocalConnector, tool: &str, input: Value) -> Value {
    connector
        .call_tool(tool, input)
        .await
        .unwrap_or_else(|error| panic!("{tool}: {error}"))
}

async fn call_error(connector: &mut LocalConnector, tool: &str, input: Value) -> SdkError {
    match connector.call_tool(tool, input).await {
        Ok(value) => panic!("{tool} unexpectedly succeeded: {value}"),
        Err(error) => error,
    }
}

async fn open_mailbox(connector: &mut LocalConnector, services: &Services) -> Value {
    let published = call(
        connector,
        TOOL_MAIL_MAILBOX_PUBLISH,
        json!({ "routes": [services.origin] }),
    )
    .await;
    assert_eq!(published["published"], json!([services.origin]));
    assert_eq!(published["failed"], json!([]));
    published["mailbox"].clone()
}

#[test]
fn letters_round_trip_with_replies_retries_and_restored_keys() {
    let services = Services::start();
    run(async {
        let mut alice = services.connector(1);
        let mut bob = services.connector(2);
        let bob_box = open_mailbox(&mut bob, &services).await;
        assert_eq!(bob_box["status"], "open");
        assert_eq!(
            bob_box["address"],
            format!(
                "{}/mail/{}?route={}",
                bob.agent_id(),
                bob_box["mailbox_id"].as_str().unwrap(),
                services.origin
            )
        );
        let alice_box = open_mailbox(&mut alice, &services).await;

        // Alice writes with her reply card attached.
        let sent = call(
            &mut alice,
            TOOL_MAIL_SEND,
            json!({
                "to": bob_box["address"], "subject": "Draft review",
                "text": "Could you review section 4?",
                "parts": [{"media_type": "application/pdf", "name": "draft.pdf", "data": "JVBERi0"}],
                "reply_mailbox_id": alice_box["mailbox_id"]
            }),
        )
        .await;
        assert_eq!(sent["status"], "delivered");
        assert_eq!(sent["message"]["delivery"]["route"], json!(services.origin));
        let message_id = sent["message"]["message_id"].as_str().unwrap().to_owned();
        let bob_mailbox = bob_box["mailbox_id"].as_str().unwrap();

        // The first sync stores the letter and keeps the relay copy until the
        // state it produced has been saved; the next sync deletes it.
        let synced = call(&mut bob, TOOL_MAIL_SYNC, json!({})).await;
        assert_eq!(synced["received"].as_array().unwrap().len(), 1);
        assert_eq!(synced["errors"], json!([]));
        assert_eq!(services.packets(bob_mailbox), 1);
        let inbox = call(
            &mut bob,
            TOOL_INBOX_NEXT,
            json!({ "kinds": ["mail.received"] }),
        )
        .await;
        assert_eq!(inbox["items"][0]["actor"], json!(alice.agent_id()));
        assert_eq!(inbox["items"][0]["message"]["summary"], "Draft review");
        assert_eq!(inbox["items"][0]["requires_response"], false);
        let synced = call(&mut bob, TOOL_MAIL_SYNC, json!({})).await;
        assert_eq!(synced["received"], json!([]));
        assert_eq!(services.packets(bob_mailbox), 0);

        let read = call(
            &mut bob,
            TOOL_MAIL_LIST,
            json!({ "unread_only": true, "mark_read": true }),
        )
        .await;
        let letter = &read["messages"][0];
        assert_eq!(letter["message_id"], json!(message_id));
        assert_eq!(letter["parts"][0]["text"], "Could you review section 4?");
        assert_eq!(letter["parts"][1]["size"], 5);
        assert!(letter["parts"][1].get("data").is_none());
        assert_eq!(letter["reply_address"], alice_box["address"]);
        assert_eq!(read["unread_count"], 0);
        let with_data = call(
            &mut bob,
            TOOL_MAIL_LIST,
            json!({ "message_id": message_id, "include_data": true }),
        )
        .await;
        assert_eq!(with_data["messages"][0]["parts"][1]["data"], "JVBERi0");
        let mailboxes = call(&mut bob, TOOL_MAIL_MAILBOXES_LIST, json!({})).await;
        assert_eq!(mailboxes["mailboxes"][0]["unread_count"], 0);

        // A reply needs no address: the parent's reply card names Alice's mailbox.
        let reply = call(
            &mut bob,
            TOOL_MAIL_SEND,
            json!({ "in_reply_to": message_id, "text": "Done, see my notes." }),
        )
        .await;
        assert_eq!(reply["status"], "delivered");
        let synced = call(&mut alice, TOOL_MAIL_SYNC, json!({})).await;
        let answer = &synced["received"][0];
        assert_eq!(answer["in_reply_to"], json!(message_id));
        assert_eq!(answer["thread_id"], sent["message"]["thread_id"]);
        assert_eq!(answer["from"], json!(bob.agent_id()));

        // A transient relay failure queues the letter; the next sync delivers it.
        services.failing_deliveries.store(1, Ordering::SeqCst);
        let queued = call(
            &mut alice,
            TOOL_MAIL_SEND,
            json!({ "to": bob_box["address"], "text": "second" }),
        )
        .await;
        assert_eq!(queued["status"], "queued");
        assert_eq!(queued["message"]["delivery"]["status"], "queued");
        assert_eq!(
            queued["message"]["delivery"]["last_error"]["code"],
            "service_unavailable"
        );
        let retried = call(&mut alice, TOOL_MAIL_SYNC, json!({})).await;
        assert_eq!(
            retried["delivered"],
            json!([queued["message"]["message_id"]])
        );
        assert_eq!(retried["queued"], 0);

        // Bob restarts from his snapshot and his separately stored mail keys.
        let snapshot = bob.snapshot().unwrap();
        assert_eq!(snapshot["version"], LOCAL_CONNECTOR_SNAPSHOT_VERSION);
        assert!(!snapshot.to_string().contains("secret"));
        let keys = bob.mail_keys_snapshot();
        let copy =
            LocalConnector::from_snapshot(AgentSigner::from_seed([2; 32]), &snapshot).unwrap();
        assert_eq!(copy.snapshot().unwrap(), snapshot);
        let mut keyless = LocalConnector::from_snapshot(AgentSigner::from_seed([2; 32]), &snapshot)
            .unwrap()
            .with_http_client(tls_client());
        let undecryptable = call(&mut keyless, TOOL_MAIL_SYNC, json!({})).await;
        assert_eq!(undecryptable["received"], json!([]));
        assert_eq!(undecryptable["errors"][0]["code"], "invalid_event");
        let mut restored =
            LocalConnector::from_snapshot(AgentSigner::from_seed([2; 32]), &snapshot)
                .unwrap()
                .with_http_client(tls_client());
        restored.restore_mail_keys(&keys).unwrap();
        let synced = call(&mut restored, TOOL_MAIL_SYNC, json!({})).await;
        assert_eq!(synced["received"][0]["parts"][0]["text"], "second");
    });
}

#[test]
fn mailbox_rotation_closing_sender_policy_and_the_allowlist() {
    let services = Services::start();
    run(async {
        let mut alice = services.connector(3);
        let mut bob = services.connector(4);
        let bob_box = open_mailbox(&mut bob, &services).await;
        let mailbox_id = bob_box["mailbox_id"].as_str().unwrap().to_owned();
        call(
            &mut alice,
            TOOL_MAIL_SEND,
            json!({ "to": bob_box["address"], "text": "under the first key" }),
        )
        .await;

        // Rotation keeps the old key until its card's receive_until, so mail
        // queued under the old card still opens.
        let rotated = call(
            &mut bob,
            TOOL_MAIL_MAILBOX_PUBLISH,
            json!({ "mailbox_id": mailbox_id, "routes": [services.origin], "rotate_key": true }),
        )
        .await;
        assert_ne!(rotated["mailbox"]["card_hash"], bob_box["card_hash"]);
        assert_eq!(rotated["mailbox"]["address"], bob_box["address"]);
        let keys = bob.mail_keys_snapshot();
        assert_eq!(keys["keys"].as_object().unwrap().len(), 2);
        // The stable address works once the card is pinned, and the sender
        // reads the rotated card before encrypting.
        let stable = format!("{}/mail/{mailbox_id}", bob.agent_id());
        call(
            &mut alice,
            TOOL_MAIL_SEND,
            json!({ "to": stable, "text": "under the second key" }),
        )
        .await;
        let synced = call(
            &mut bob,
            TOOL_MAIL_SYNC,
            json!({ "mailbox_id": mailbox_id }),
        )
        .await;
        let mut texts = synced["received"]
            .as_array()
            .unwrap()
            .iter()
            .map(|message| message["parts"][0]["text"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        texts.sort();
        assert_eq!(texts, ["under the first key", "under the second key"]);

        // A blocked sender's packets are deleted unopened.
        bob.set_mail_sender_blocked(alice.agent_id(), true);
        call(&mut bob, TOOL_MAIL_SYNC, json!({})).await;
        call(
            &mut alice,
            TOOL_MAIL_SEND,
            json!({ "to": stable, "text": "blocked" }),
        )
        .await;
        let synced = call(&mut bob, TOOL_MAIL_SYNC, json!({})).await;
        assert_eq!(synced["received"], json!([]));
        assert_eq!(services.packets(&mailbox_id), 0);

        // A route outside the allowlist is never contacted; without a pinned
        // card for that mailbox the send is refused.
        let elsewhere = "https://relay.elsewhere.example";
        let carol = AgentSigner::from_seed([7; 32]).agent_id();
        let address = format!("{carol}/mail/AAECAwQFBgcICQoLDA0ODw?route={elsewhere}");
        let error = call_error(
            &mut alice,
            TOOL_MAIL_SEND,
            json!({ "to": address.clone(), "text": "hi" }),
        )
        .await;
        assert_eq!(error.code(), Some("permission_denied"));
        let error = call_error(
            &mut bob,
            TOOL_MAIL_MAILBOX_PUBLISH,
            json!({ "routes": [elsewhere] }),
        )
        .await;
        assert_eq!(error.code(), Some("permission_denied"));

        // Closing publishes an empty route list; senders then refuse.
        let closed = call(
            &mut bob,
            TOOL_MAIL_MAILBOX_PUBLISH,
            json!({ "mailbox_id": mailbox_id, "routes": [] }),
        )
        .await;
        assert_eq!(closed["mailbox"]["status"], "closed");
        assert_eq!(closed["published"], json!([services.origin]));
        let error = call_error(
            &mut alice,
            TOOL_MAIL_SEND,
            json!({ "to": bob_box["address"], "text": "too late" }),
        )
        .await;
        assert_eq!(error.code(), Some("mailbox_unavailable"));
    });
}

#[test]
fn unread_pages_marked_read_skip_no_letter() {
    let services = Services::start();
    run(async {
        let mut alice = services.connector(9);
        let mut bob = services.connector(10);
        let bob_box = open_mailbox(&mut bob, &services).await;
        for text in ["one", "two", "three"] {
            call(
                &mut alice,
                TOOL_MAIL_SEND,
                json!({ "to": bob_box["address"], "text": text }),
            )
            .await;
        }
        call(&mut bob, TOOL_MAIL_SYNC, json!({})).await;

        // Each page leaves the unread selection, so following next_cursor
        // still reaches every letter.
        let mut input = json!({ "unread_only": true, "mark_read": true, "limit": 2 });
        let mut texts = Vec::new();
        loop {
            let page = call(&mut bob, TOOL_MAIL_LIST, input.clone()).await;
            for message in page["messages"].as_array().unwrap() {
                texts.push(message["parts"][0]["text"].as_str().unwrap().to_owned());
            }
            match page.get("next_cursor") {
                Some(cursor) => input["cursor"] = cursor.clone(),
                None => break,
            }
        }
        texts.sort();
        assert_eq!(texts, ["one", "three", "two"]);
    });
}

#[test]
fn knowledge_publish_query_search_and_status() {
    let services = Services::start();
    run(async {
        let mut alice = services.connector(5);
        let mut bob = services.connector(6);
        let service = services.origin.clone();
        let payload = json!({
            "license": "https://creativecommons.org/licenses/by/4.0/",
            "kind": "observation",
            "title": "Cache keys need the language",
            "statement": "A user-only cache key returns the first language for later requests.",
            "language": "en",
            "context": {"scope": "An in-memory greeting cache.", "conditions": [], "limitations": []},
            "basis": "A two-request fixture.",
            "tags": ["caching"]
        });
        let published = call(
            &mut alice,
            TOOL_KNOWLEDGE_SUBMIT,
            json!({ "services": [service], "type": "knowledge.publish", "payload": payload }),
        )
        .await;
        let id = published["id"].as_str().unwrap().to_owned();
        assert_eq!(published["results"][0]["item"]["id"], json!(id));
        assert_eq!(published["results"][0]["item"]["seq"], 1);

        let page = call(
            &mut bob,
            TOOL_KNOWLEDGE_QUERY,
            json!({ "service": service, "tag": "caching" }),
        )
        .await;
        assert_eq!(page["items"][0]["id"], json!(id));
        assert_eq!(page["items"][0]["actor"], json!(alice.agent_id()));
        assert_eq!(page["service"], json!(service));
        assert_eq!(page["checkpoint"], 1);
        let unknown = "A".repeat(43);
        let got = call(
            &mut bob,
            TOOL_KNOWLEDGE_GET,
            json!({ "service": service, "ids": [id, unknown] }),
        )
        .await;
        assert_eq!(
            got["items"][0]["payload"]["title"],
            "Cache keys need the language"
        );
        assert_eq!(got["missing"], json!([unknown]));
        let found = call(
            &mut bob,
            TOOL_KNOWLEDGE_SEARCH,
            json!({ "service": service, "text": "cache LANGUAGE", "mode": "lexical" }),
        )
        .await;
        assert_eq!(found["hits"][0]["item"]["id"], json!(id));
        assert_eq!(found["coverage"]["exhaustive"], true);

        // Bob's assessment and a third party's attempted retraction leave the
        // capsule active; only the author's own retraction withdraws it.
        let assessment = call(
            &mut bob,
            TOOL_KNOWLEDGE_SUBMIT,
            json!({
                "services": [service], "type": "knowledge.assess",
                "payload": {
                    "license": "https://creativecommons.org/licenses/by/4.0/",
                    "target": id, "verdict": "supports", "summary": "Same result here.",
                    "context": {"scope": "The same fixture.", "conditions": [], "limitations": []},
                    "basis": "Reran the fixture."
                }
            }),
        )
        .await;
        let error = call_error(
            &mut bob,
            TOOL_KNOWLEDGE_SUBMIT,
            json!({ "services": [service], "type": "knowledge.retract", "payload": { "target": id, "reason": "not mine" } }),
        )
        .await;
        assert_eq!(error.code(), Some("invalid_target"));
        let status = call(
            &mut bob,
            TOOL_KNOWLEDGE_STATUS,
            json!({ "service": service, "id": id }),
        )
        .await;
        assert_eq!(status["complete"], true);
        assert_eq!(status["status"], "active");
        assert_eq!(status["assessments"], json!([assessment["id"]]));
        let retraction = call(
            &mut alice,
            TOOL_KNOWLEDGE_SUBMIT,
            json!({ "services": [service], "type": "knowledge.retract", "payload": { "target": id, "reason": "superseded" } }),
        )
        .await;
        let status = call(
            &mut bob,
            TOOL_KNOWLEDGE_STATUS,
            json!({ "service": service, "id": id }),
        )
        .await;
        assert_eq!(status["status"], "retracted");
        assert_eq!(status["retractions"], json!([retraction["id"]]));

        // Dependencies the service lacks keep their data; unknown services are refused.
        let error = call_error(
            &mut alice,
            TOOL_KNOWLEDGE_SUBMIT,
            json!({ "services": [service], "type": "knowledge.retract", "payload": { "target": unknown, "reason": "gone" } }),
        )
        .await;
        assert_eq!(error.code(), Some("missing_dependency"));
        assert_eq!(error.data().unwrap()["missing"], json!([unknown]));
        let error = call_error(
            &mut alice,
            TOOL_KNOWLEDGE_QUERY,
            json!({ "service": "https://knowledge.elsewhere.example" }),
        )
        .await;
        assert_eq!(error.code(), Some("permission_denied"));
        let error = call_error(
            &mut alice,
            TOOL_KNOWLEDGE_SUBMIT,
            json!({ "services": [service], "type": "knowledge.publish", "payload": { "title": "incomplete" } }),
        )
        .await;
        assert_eq!(error.code(), Some("invalid_event"));
    });
}

#[test]
fn one_nonce_sequence_spans_mail_and_knowledge() {
    let services = Services::start();
    run(async {
        // Another holder of the same key signs far ahead of this one.
        let far = unix_ms() as u64 + 3_600_000;
        let mut snapshot = services.connector(8).snapshot().unwrap();
        snapshot["next_nonce"] = json!(far);
        let mut ahead = LocalConnector::from_snapshot(AgentSigner::from_seed([8; 32]), &snapshot)
            .unwrap()
            .with_http_client(tls_client());
        open_mailbox(&mut ahead, &services).await;

        // The relay refuses this connector's card with Max-Seen-Nonce; it
        // resyncs and re-signs once.
        let mut behind = services.connector(8);
        let mailbox = open_mailbox(&mut behind, &services).await;
        let nonce =
            |state: &Value, pointer: &str| state.pointer(pointer).unwrap().as_u64().unwrap();
        let card = nonce(
            &behind.snapshot().unwrap(),
            "/mail/mailboxes/0/cards/0/event/nonce",
        );
        assert!(card > far);

        // Knowledge events and mail packets continue the same sequence.
        let submitted = call(
            &mut behind,
            TOOL_KNOWLEDGE_SUBMIT,
            json!({
                "services": [services.origin], "type": "knowledge.publish",
                "payload": {
                    "license": "https://creativecommons.org/licenses/by/4.0/",
                    "kind": "question", "title": "Nonce order", "statement": "Does one sequence cover every protocol?",
                    "language": "en", "context": {"scope": "One Agent ID.", "conditions": [], "limitations": []},
                    "basis": "A regression test."
                }
            }),
        )
        .await;
        let knowledge = nonce(&submitted, "/envelope/event/nonce");
        assert!(knowledge > card);
        call(
            &mut behind,
            TOOL_MAIL_SEND,
            json!({ "to": mailbox["address"], "text": "a note to self" }),
        )
        .await;
        let state = behind.snapshot().unwrap();
        let packet = nonce(&state, "/mail/messages/0/packet/event/nonce");
        assert!(packet > knowledge);
        assert!(nonce(&state, "/next_nonce") > packet);
    });
}
