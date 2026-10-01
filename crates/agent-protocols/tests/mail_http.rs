#![cfg(feature = "http-client")]
use agent_protocols::{
    http_client::MailClient,
    identity::{AgentSigner, RequestBinding, RequestJwtClaims},
    mail::*,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig, ServerConnection, StreamOwned,
};
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
};

const CERT: &[u8] = include_bytes!("fixtures/knowledge-tls/cert.der");
const KEY: &[u8] = include_bytes!("fixtures/knowledge-tls/key.der");
#[derive(Clone, Debug)]
struct Request {
    method: String,
    path: String,
    authorization: Option<String>,
    cookie: Option<String>,
    body: String,
}
type Replies = Arc<Mutex<VecDeque<(u16, String, Option<String>, String)>>>;
struct Server {
    origin: String,
    replies: Replies,
    requests: Arc<Mutex<Vec<Request>>>,
}
impl Server {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(CERT.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec())),
            )
            .unwrap();
        let config = Arc::new(config);
        let replies: Replies = Arc::new(Mutex::new(VecDeque::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let out = replies.clone();
        let recorded = requests.clone();
        thread::spawn(move || {
            for socket in listener.incoming() {
                let Ok(socket) = socket else { break };
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                    .unwrap();
                let mut stream =
                    StreamOwned::new(ServerConnection::new(config.clone()).unwrap(), socket);
                let mut input = Vec::new();
                let mut buf = [0u8; 2048];
                let end = loop {
                    if let Some(pos) = input.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos;
                    }
                    let Ok(n) = stream.read(&mut buf) else { return };
                    if n == 0 {
                        return;
                    }
                    input.extend_from_slice(&buf[..n]);
                };
                let header = String::from_utf8_lossy(&input[..end]).into_owned();
                let mut lines = header.split("\r\n");
                let mut first = lines.next().unwrap().split_whitespace();
                let method = first.next().unwrap().to_owned();
                let path = first.next().unwrap().to_owned();
                let mut length = 0;
                let mut authorization = None;
                let mut cookie = None;
                for line in lines {
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().unwrap();
                        }
                        if name.eq_ignore_ascii_case("cookie") {
                            cookie = Some(value.trim().to_owned());
                        }
                        if name.eq_ignore_ascii_case("authorization") {
                            authorization = Some(value.trim().to_owned());
                        }
                    }
                }
                while input.len() - end - 4 < length {
                    let n = stream.read(&mut buf).unwrap();
                    assert!(n > 0);
                    input.extend_from_slice(&buf[..n]);
                }
                recorded.lock().unwrap().push(Request {
                    method,
                    path,
                    authorization,
                    cookie,
                    body: String::from_utf8_lossy(&input[end + 4..]).into_owned(),
                });
                let (status, body, location, content_type) =
                    out.lock().unwrap().pop_front().unwrap();
                let extra = location
                    .map(|s| format!("Location: {s}\r\n"))
                    .unwrap_or_default();
                let response=format!("HTTP/1.1 {status} Test\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",body.len());
                stream.write_all(response.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
        });
        Self {
            origin: format!("https://localhost:{}", address.port()),
            replies,
            requests,
        }
    }
    fn reply(&self, value: &Value) {
        self.replies.lock().unwrap().push_back((
            200,
            value.to_string(),
            None,
            "application/json".into(),
        ));
    }
    fn raw(&self, status: u16, text: &str, location: Option<String>) {
        self.replies.lock().unwrap().push_back((
            status,
            text.into(),
            location,
            "application/json".into(),
        ));
    }
    fn mime(&self, status: u16, text: &str, mime: &str) {
        self.replies
            .lock()
            .unwrap()
            .push_back((status, text.into(), None, mime.into()));
    }
    fn client(&self) -> MailClient {
        MailClient::with_tls_roots(
            &self.origin,
            vec![reqwest::Certificate::from_der(CERT).unwrap()],
        )
        .unwrap()
    }
}
fn run<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}
fn objects(
    origin: &str,
) -> (
    agent_protocols::identity::AgentSigner,
    MailboxCard,
    MessagePayload,
    Packet,
    i64,
) {
    let now = agent_protocols::identity::unix_ms();
    let owner = AgentSigner::from_seed([31; 32]);
    let sender = AgentSigner::from_seed([32; 32]);
    let key = MailEncryptionKey::generate().unwrap();
    let card = sign_card(
        &owner,
        MailboxCardPayload {
            mailbox_id: random_id().unwrap(),
            expires_at: now + 100_000,
            receive_until: now + 200_000,
            public_key: key.public_key(),
            routes: vec![origin.into()],
            max_packet_bytes: 65536,
        },
        now,
        100,
    )
    .unwrap();
    let message = create_mail_message(
        &sender.agent_id(),
        now,
        json!({
            "to":owner.agent_id(),"expires_at":now+60_000,"thread_id":random_id().unwrap(),
            "parts":[{"media_type":"text/plain","data":encode_bytes(b"private mail")}]
        }),
    )
    .unwrap();
    let packet = encrypt_message(&message, &card, &sender, 800, now).unwrap();
    (owner, card, message, packet, now)
}
#[test]
fn mail_https_fixed_paths_owner_auth_and_sender_signed_delivery() {
    run(async {
        let server = Server::start();
        let client = server.client();
        let (owner, card, _, packet, now) = objects(&server.origin);
        let mailbox = &card.event.payload.mailbox_id;
        let discovery = json!({"protocol":PROTOCOL,"service":server.origin,"endpoints":{"mailboxes":format!("{}/ignored",server.origin)},"features":["future-feature"]});
        server.reply(&discovery);
        client.protocol().await.unwrap();
        let record = json!({"envelope":card,"accepted_at":now});
        server.reply(&record);
        assert_eq!(client.publish(&card).await.unwrap().envelope, card);
        server.reply(&record);
        assert_eq!(
            client
                .card(mailbox, &owner.agent_id())
                .await
                .unwrap()
                .envelope,
            card
        );
        let result = json!({"packet_id":packet_id(&packet).unwrap(),"accepted_at":now});
        server.raw(202, &result.to_string(), None);
        assert_eq!(client.deliver(&packet).await.unwrap().accepted_at, now);
        let jwt = owner
            .sign_request_jwt(&RequestJwtClaims::new(
                owner.agent_id(),
                RequestBinding::new(&server.origin),
                now / 1000,
                300,
            ))
            .unwrap();
        let item = json!({"packet_id":packet_id(&packet).unwrap(),"packet":packet,"accepted_at":now,"seq":1});
        server.reply(&json!({"result":[item]}));
        assert_eq!(
            client
                .list(mailbox, &owner.agent_id(), &jwt, now, 10, None)
                .await
                .unwrap()
                .result
                .len(),
            1
        );
        server.raw(204, "", None);
        client
            .delete(
                mailbox,
                &packet_id(&packet).unwrap(),
                &owner.agent_id(),
                &jwt,
                now,
            )
            .await
            .unwrap();
        // An authenticated read never contaminates the isolated anonymous delivery.
        server.raw(202, &result.to_string(), None);
        client.deliver(&packet).await.unwrap();
        let requests = server.requests.lock().unwrap();
        let paths: Vec<_> = requests
            .iter()
            .map(|r| (r.method.as_str(), r.path.as_str()))
            .collect();
        let card_path = format!("/v1/mailboxes/{mailbox}/card");
        let packets_path = format!("/v1/mailboxes/{mailbox}/packets");
        let list_path = format!("{packets_path}?limit=10");
        let delete_path = format!("{packets_path}/{}", packet_id(&packet).unwrap());
        assert_eq!(
            paths,
            [
                ("GET", "/.well-known/agent-mail"),
                ("POST", "/v1/mailboxes"),
                ("GET", card_path.as_str()),
                ("POST", packets_path.as_str()),
                ("GET", list_path.as_str()),
                ("DELETE", delete_path.as_str()),
                ("POST", packets_path.as_str()),
            ]
        );
        assert_eq!(
            serde_json::from_str::<Value>(&requests[1].body).unwrap(),
            serde_json::to_value(&card).unwrap()
        );
        for i in [0, 1, 2, 3, 6] {
            assert!(requests[i].authorization.is_none());
            assert!(requests[i].cookie.is_none());
        }
        for i in [4, 5] {
            assert_eq!(
                requests[i].authorization.as_deref(),
                Some(format!("Bearer {jwt}").as_str())
            );
        }
    });
}
#[test]
fn mail_https_redirects_malformed_and_misbound_responses_are_rejected() {
    run(async {
        let server = Server::start();
        let client = server.client();
        let (owner, card, _, packet, now) = objects(&server.origin);
        let mailbox = &card.event.payload.mailbox_id;
        server.raw(307, "{}", Some(format!("{}/leaked", server.origin)));
        assert!(client.deliver(&packet).await.is_err());
        assert_eq!(server.requests.lock().unwrap().len(), 1);
        server.raw(
            202,
            "{\"packet_id\":\"x\",\"packet_id\":\"x\",\"accepted_at\":1}",
            None,
        );
        assert!(client.deliver(&packet).await.is_err());
        server.raw(
            202,
            &json!({"packet_id":hash_bytes(b"wrong"),"accepted_at":now}).to_string(),
            None,
        );
        assert!(client.deliver(&packet).await.is_err());
        let jwt = owner
            .sign_request_jwt(&RequestJwtClaims::new(
                owner.agent_id(),
                RequestBinding::new(&server.origin),
                now / 1000,
                300,
            ))
            .unwrap();
        let item = json!({"packet_id":packet_id(&packet).unwrap(),"packet":packet,"accepted_at":now,"seq":1});
        server.reply(&json!({"result":[item.clone(),item.clone()]}));
        assert!(client
            .list(mailbox, &owner.agent_id(), &jwt, now, 10, None)
            .await
            .is_err());
        let mut late = item.clone();
        late["accepted_at"] = json!(packet.event.payload.header.expires_at);
        server.reply(&json!({"result":[late]}));
        assert!(client
            .list(mailbox, &owner.agent_id(), &jwt, now, 10, None)
            .await
            .is_err());
        server.reply(&json!({"result":[],"next_cursor":"loop"}));
        assert!(client
            .list(mailbox, &owner.agent_id(), &jwt, now, 10, None)
            .await
            .is_err());
        let other = AgentSigner::from_seed([44; 32]);
        let wrong = other
            .sign_request_jwt(&RequestJwtClaims::new(
                other.agent_id(),
                RequestBinding::new(&server.origin),
                now / 1000,
                300,
            ))
            .unwrap();
        let before = server.requests.lock().unwrap().len();
        assert!(client
            .list(mailbox, &owner.agent_id(), &wrong, now, 10, None)
            .await
            .is_err());
        assert_eq!(server.requests.lock().unwrap().len(), before);
        server.raw(
            202,
            &json!({"packet_id":packet_id(&packet).unwrap(),"seq":1,"accepted_at":now}).to_string(),
            None,
        );
        assert!(client.deliver(&packet).await.is_err());
        server.raw(
            429,
            "{\"error\":{\"code\":\"rate_limited\",\"message\":\"full\"}}",
            None,
        );
        assert_eq!(
            client.deliver(&packet).await.unwrap_err().code(),
            Some("rate_limited")
        );
        server.mime(
            202,
            &json!({"packet_id":packet_id(&packet).unwrap(),"accepted_at":now}).to_string(),
            "text/html",
        );
        assert_eq!(
            client.deliver(&packet).await.unwrap_err().code(),
            Some("invalid_response")
        );
        let bounded = server.client().with_response_limit(4096).unwrap();
        server.raw(202, &"x".repeat(4097), None);
        assert_eq!(
            bounded.deliver(&packet).await.unwrap_err().code(),
            Some("payload_too_large")
        );
    });
}
#[test]
fn card_reads_pin_closed_expired_and_conflicting_cards_across_clients() {
    run(async {
        let server = Server::start();
        let client = server.client();
        let (owner, original, _, _, now) = objects(&server.origin);
        let mailbox = &original.event.payload.mailbox_id;
        let mut long_payload = original.event.payload.clone();
        long_payload.expires_at = now + 10 * 86_400_000;
        long_payload.receive_until = now + 20 * 86_400_000;
        let long = sign_card(&owner, long_payload.clone(), now, 100).unwrap();
        let mut short_payload = long_payload.clone();
        short_payload.routes = vec![];
        short_payload.expires_at = now + 86_400_000;
        short_payload.receive_until = now + 2 * 86_400_000;
        let closed = sign_card(&owner, short_payload, now, 101).unwrap();
        server.reply(&json!({"envelope":long,"accepted_at":now}));
        client
            .card_at(mailbox, &owner.agent_id(), now)
            .await
            .unwrap();
        let clone = client.clone();
        server.reply(&json!({"envelope":closed,"accepted_at":now}));
        assert!(clone
            .card_at(mailbox, &owner.agent_id(), now)
            .await
            .unwrap()
            .envelope
            .event
            .payload
            .routes
            .is_empty());
        // A short closed card expiring does not revive the older open card.
        let later = now + 3 * 86_400_000;
        server.reply(&json!({"envelope":long,"accepted_at":now}));
        assert_eq!(
            client
                .card_at(mailbox, &owner.agent_id(), later)
                .await
                .unwrap_err()
                .code(),
            Some("stale_card")
        );
        let saved = clone.card_cache_snapshot().unwrap();
        let restored = Arc::new(Mutex::new(MailCardCache::from_snapshot(&saved).unwrap()));
        let other = server.client().with_card_cache(restored);
        server.reply(&json!({"envelope":long,"accepted_at":now}));
        assert_eq!(
            other
                .card_at(mailbox, &owner.agent_id(), later)
                .await
                .unwrap_err()
                .code(),
            Some("stale_card")
        );
        // A different card with the pinned nonce is rejected; the pin stays usable.
        let higher = sign_card(&owner, long_payload.clone(), now, 102).unwrap();
        server.reply(&json!({"envelope":higher,"accepted_at":now}));
        client
            .card_at(mailbox, &owner.agent_id(), later)
            .await
            .unwrap();
        long_payload.max_packet_bytes = 32768;
        let conflicting = sign_card(&owner, long_payload, now, 102).unwrap();
        server.reply(&json!({"envelope":conflicting,"accepted_at":now}));
        assert_eq!(
            clone
                .card_at(mailbox, &owner.agent_id(), later)
                .await
                .unwrap_err()
                .code(),
            Some("stale_card")
        );
        server.reply(&json!({"envelope":higher,"accepted_at":now}));
        client
            .card_at(mailbox, &owner.agent_id(), later)
            .await
            .unwrap();
    });
}
