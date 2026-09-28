#![cfg(feature = "http-client")]
use agent_protocols::{
    http_client::KnowledgeClient,
    identity::{unix_secs, AgentSigner, Event, RequestBinding, RequestJwtClaims},
    knowledge::{KnowledgeStore, PROTOCOL},
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
    body: String,
}
type Replies = Arc<Mutex<VecDeque<(u16, String, Option<String>)>>>;
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
                for line in lines {
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().unwrap();
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
                    body: String::from_utf8_lossy(&input[end + 4..]).into_owned(),
                });
                let (status, body, location) = out.lock().unwrap().pop_front().unwrap();
                let extra = location
                    .map(|s| format!("Location: {s}\r\n"))
                    .unwrap_or_default();
                let response=format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",body.len());
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
        self.replies
            .lock()
            .unwrap()
            .push_back((200, value.to_string(), None));
    }
    fn raw(&self, status: u16, text: &str, location: Option<String>) {
        self.replies
            .lock()
            .unwrap()
            .push_back((status, text.into(), location));
    }
    fn client(&self) -> KnowledgeClient {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(CERT.to_vec())).unwrap();
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let inner = reqwest::Client::builder()
            .no_proxy()
            .use_preconfigured_tls(tls)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        KnowledgeClient::with_client(&self.origin, inner).unwrap()
    }
}
fn run<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}
fn signed() -> Value {
    let signer = AgentSigner::from_seed([33; 32]);
    let payload = json!({"visibility":"public","license":"https://example.com/license","kind":"question","title":"Alpha?","statement":"Alpha question","language":"en","context":{"scope":"test","conditions":[],"limitations":[]},"basis":"A question from a fixture","extra":{"nested":{"opaque":true}}});
    serde_json::to_value(
        signer
            .sign_event(Event::new(
                PROTOCOL,
                "knowledge.publish",
                signer.agent_id(),
                1000,
                1,
                payload,
            ))
            .unwrap(),
    )
    .unwrap()
}
#[test]
fn knowledge_https_endpoints_and_unsigned_reads() {
    run(async {
        let server = Server::start();
        let mut client = server.client();
        let item = signed();
        let hash = item["hash"].as_str().unwrap();
        let mut store = KnowledgeStore::new(&server.origin).unwrap();
        let record = store.import(&item, 1000).unwrap().record;
        let discovery = json!({"protocol":PROTOCOL,"service":server.origin,"features":["import","ranked-search"],"search_modes":["lexical"],"endpoints":{"events":format!("{}/custom/events",server.origin),"import":format!("{}/custom/import",server.origin),"search":format!("{}/custom/search",server.origin)}});
        server.reply(&discovery);
        assert_eq!(client.discover().await.unwrap(), discovery);
        server.reply(&record);
        assert_eq!(client.event(hash).await.unwrap(), record);
        let live_signer = AgentSigner::from_seed([33; 32]);
        let caller = AgentSigner::from_seed([34; 32]);
        let live_token = live_signer
            .sign_request_jwt(&RequestJwtClaims::new(
                live_signer.agent_id(),
                RequestBinding::new(&server.origin),
                unix_secs(),
                60,
            ))
            .unwrap();
        let import_token = caller
            .sign_request_jwt(&RequestJwtClaims::new(
                caller.agent_id(),
                RequestBinding::new(&server.origin),
                unix_secs(),
                60,
            ))
            .unwrap();
        assert_ne!(
            caller.agent_id().as_str(),
            item["event"]["actor"].as_str().unwrap()
        );
        server.reply(&record);
        client.submit(&item, Some(&live_token)).await.unwrap();
        server.reply(&record);
        client.import(&item, Some(&import_token)).await.unwrap();
        let request = json!({"q":"alpha","limit":1.0});
        server.reply(&store.query(&request, 1000).unwrap());
        assert_eq!(
            client.query_all(&request, 3).await.unwrap(),
            vec![record.clone()]
        );
        let request = json!({"hashes":[hash]});
        server.reply(&store.batch(&request, 1000).unwrap());
        client.batch(&request).await.unwrap();
        let request = json!({"after":0});
        server.reply(&store.changes(&request, 1000).unwrap());
        client.changes(&request).await.unwrap();
        let request = json!({"mode":"lexical","text":"alpha"});
        let search = store
            .search(
                &request,
                &[hash.into()],
                &json!({"mode":"lexical","id":"test"}),
                &json!({"exhaustive":true,"reasons":[]}),
                &["lexical".into()],
                1000,
            )
            .unwrap();
        server.reply(&search);
        client.search(&request).await.unwrap();
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 8);
        assert_eq!(requests[1].path, format!("/custom/events?hash={hash}"));
        assert_eq!(requests[4].path, "/knowledge/query?limit=1&q=alpha");
        assert_eq!(requests[2].method, "POST");
        assert_eq!(
            requests[2].authorization.as_deref(),
            Some(format!("Bearer {live_token}").as_str())
        );
        assert_eq!(
            requests[3].authorization.as_deref(),
            Some(format!("Bearer {import_token}").as_str())
        );
        assert_eq!(
            serde_json::from_str::<Value>(&requests[3].body).unwrap(),
            item
        );
        for index in [0, 1, 4, 5, 6, 7] {
            assert!(requests[index].authorization.is_none());
        }
    });
}
#[test]
fn knowledge_https_rejects_response_substitution_and_duplicates() {
    run(async {
        let server = Server::start();
        let client = server.client();
        let item = signed();
        let hash = item["hash"].as_str().unwrap();
        let mut store = KnowledgeStore::new(&server.origin).unwrap();
        let record = store.import(&item, 1000).unwrap().record;
        let mut wrong = record.clone();
        wrong["envelope"]["event"]["payload"]["title"] = json!("Tampered");
        server.reply(&wrong);
        assert_eq!(
            client.event(hash).await.unwrap_err().code(),
            Some("invalid_response")
        );
        let mut wrong = record.clone();
        wrong["envelope"]["extension"] = json!("must not disappear");
        server.reply(&wrong);
        assert!(client.event(hash).await.is_err());
        let raw = record
            .to_string()
            .replacen("\"seq\":1", "\"seq\":1,\"seq\":1", 1);
        server.raw(200, &raw, None);
        assert!(client.event(hash).await.is_err());
        let request = json!({"q":"does-not-match"});
        let page = json!({"result":[record],"service":server.origin,"checkpoint":1,"as_of":1000});
        server.reply(&page);
        assert!(client.query(&request).await.is_err());
        server.raw(302, "{}", Some("https://other.invalid/exfiltrate".into()));
        assert!(client.event(hash).await.is_err());
        assert_eq!(server.requests.lock().unwrap().len(), 5);
    });
}
#[test]
fn knowledge_client_rejects_bad_origins_and_unadvertised_modes() {
    for origin in [
        "http://localhost",
        "https://example.com/",
        "https://EXAMPLE.com",
        "https://example.com:443",
    ] {
        assert!(KnowledgeClient::new(origin).is_err());
    }
    let mut client = KnowledgeClient::new("https://knowledge.example.com").unwrap();
    assert!(client.set_discovery(json!({"protocol":PROTOCOL,"service":"https://knowledge.example.com","endpoints":{"query":"https://other.example/query"}})).is_err());
    run(async {
        assert_eq!(
            client
                .search(&json!({"mode":"semantic","text":"alpha"}))
                .await
                .unwrap_err()
                .code(),
            Some("unsupported_search_mode")
        );
    });
}

#[test]
fn knowledge_authentication_precedes_network_and_success_requires_200() {
    run(async {
        let server = Server::start();
        let client = server.client();
        let item = signed();
        let caller = AgentSigner::from_seed([41; 32]);
        let wrong_audience = caller
            .sign_request_jwt(&RequestJwtClaims::new(
                caller.agent_id(),
                RequestBinding::new("https://other.example"),
                unix_secs(),
                60,
            ))
            .unwrap();
        assert_eq!(
            client
                .submit(&item, Some(&wrong_audience))
                .await
                .unwrap_err()
                .code(),
            Some("invalid_token")
        );
        let expired = caller
            .sign_request_jwt(&RequestJwtClaims::new(
                caller.agent_id(),
                RequestBinding::new(&server.origin),
                unix_secs() - 120,
                60,
            ))
            .unwrap();
        assert_eq!(
            client
                .submit(&item, Some(&expired))
                .await
                .unwrap_err()
                .code(),
            Some("invalid_token")
        );
        assert!(server.requests.lock().unwrap().is_empty());
        let record = KnowledgeStore::new(&server.origin)
            .unwrap()
            .import(&item, 1000)
            .unwrap()
            .record;
        for status in [201, 202, 204] {
            server.raw(status, &record.to_string(), None);
            let error = client
                .event(item["hash"].as_str().unwrap())
                .await
                .unwrap_err();
            assert!(
                matches!(error,agent_protocols::SdkError::HttpStatus{status:s,..} if s==status)
            );
        }
    });
}
