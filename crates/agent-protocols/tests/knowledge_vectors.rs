use agent_protocols::{
    identity::{self, AgentSigner, Envelope},
    knowledge::*,
    Result,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
const SERVICE: &str = "https://knowledge.example.com";
fn vectors() -> Value {
    // The container deliberately holds one lone UTF-16 surrogate. Rust strings
    // cannot represent it; preserve its exact JSON lexeme and exercise the
    // public strict JSON boundary instead of attempting to construct a &str.
    let source = include_str!("../../../docs/protocols/agent-knowledge/1.0.vectors.json");
    let source = source.replace(r#""text": "\ud800""#, r#""raw_text_json": "\"\\ud800\"""#);
    serde_json::from_str(&source).unwrap()
}
fn array(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or(&[])
}
fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}
fn envelope(v: &Value, name: &Value) -> Value {
    v["fixtures"][text(name)]["envelope"].clone()
}
fn id(v: &Value, name: &Value) -> String {
    text(&v["fixtures"][text(name)]["envelope"]["hash"]).to_owned()
}
fn names(v: &Value, list: &Value) -> Vec<String> {
    array(list).iter().map(|n| id(v, n)).collect()
}
fn parameters(v: &Value) -> Vec<(String, String)> {
    array(v)
        .iter()
        .map(|p| (text(&p[0]).into(), text(&p[1]).into()))
        .collect()
}
fn modes(case: &Value) -> Vec<String> {
    case.get("modes")
        .map(|v| array(v).iter().map(|v| text(v).into()).collect())
        .unwrap_or_else(|| vec!["lexical".into(), "semantic".into(), "hybrid".into()])
}
fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
fn mutate(mut value: Value, changes: &Value) -> Value {
    for change in array(changes) {
        let path = text(&change["path"]);
        let (parent_path, key) = path.rsplit_once('/').unwrap();
        let parent = value.pointer_mut(parent_path).unwrap();
        match text(&change["op"]) {
            "set" => {
                if parent.is_array() {
                    parent[key.parse::<usize>().unwrap()] = change["value"].clone();
                } else {
                    parent[key] = change["value"].clone();
                }
            }
            "remove" => {
                if let Some(a) = parent.as_array_mut() {
                    a.remove(key.parse::<usize>().unwrap());
                } else {
                    parent.as_object_mut().unwrap().remove(key);
                }
            }
            _ => panic!("unexpected mutation"),
        }
    }
    value
}
fn assert_outcome<T>(result: &Result<T>, expected: &Value, case: &Value) {
    let actual = match result {
        Ok(_) => "valid",
        Err(e) => e.code().unwrap_or("unmapped_error"),
    };
    assert_eq!(
        actual,
        text(expected),
        "{}: {:?}",
        text(&case["name"]),
        result.as_ref().err()
    );
}
fn model(v: &Value, case: &Value) -> KnowledgeStore {
    let mut store = KnowledgeStore::new(SERVICE).unwrap();
    for name in array(&case["accepted"]) {
        store
            .import(&envelope(v, name), v["now"].as_i64().unwrap())
            .unwrap();
    }
    for name in array(&case["hidden"]) {
        store.hide(&id(v, name));
    }
    store
}

#[test]
fn bundled_schema_matches_normative_source() {
    assert_eq!(
        SCHEMA_JSON,
        include_str!("../../../docs/protocols/agent-knowledge/1.0.schema.json")
    );
}

#[test]
fn all_64_signature_fixtures() {
    let v = vectors();
    assert_eq!(v["fixtures"].as_object().unwrap().len(), 64);
    for (name, fixture) in v["fixtures"].as_object().unwrap() {
        let raw = &fixture["envelope"];
        let e: Envelope = serde_json::from_value(raw.clone()).unwrap();
        identity::verify_envelope(&e).unwrap();
        assert_eq!(
            String::from_utf8(identity::canonical_event_bytes(&e.event).unwrap()).unwrap(),
            text(&fixture["canonical_event_utf8"]),
            "{name}"
        );
        let signer = AgentSigner::from_seed(
            bytes(text(&v["seeds"][text(&fixture["signer"])]))
                .try_into()
                .unwrap(),
        );
        assert_eq!(signer.agent_id(), e.event.actor);
        assert_eq!(
            serde_json::to_value(signer.sign_event(e.event).unwrap()).unwrap(),
            *raw,
            "{name}"
        );
    }
}

#[test]
fn identity_and_schema_cases() {
    let v = vectors();
    for case in array(&v["identity_cases"]) {
        let result = if let Some(raw) = case["raw_json"].as_str() {
            identity::parse_strict_json(raw).map(|_| ())
        } else {
            validate_knowledge_envelope(&mutate(envelope(&v, &case["fixture"]), &case["changes"]))
                .map(|_| ())
        };
        assert_outcome(&result, &case["expected"], case);
    }
    for case in array(&v["schema_cases"]) {
        let value = case
            .get("value")
            .cloned()
            .unwrap_or_else(|| mutate(envelope(&v, &case["fixture"]), &case["changes"]));
        let result = validate_knowledge_schema(&value, text(&case["definition"]));
        assert_eq!(
            result.is_ok(),
            case["valid"].as_bool().unwrap(),
            "{}: {:?}",
            text(&case["name"]),
            result
        );
    }
}

#[test]
fn object_and_known_set_cases() {
    let v = vectors();
    for case in array(&v["object_cases"]) {
        let store = model(&v, case);
        let retained = store.visible_envelopes();
        let item = envelope(&v, &case["fixture"]);
        let result = validate_knowledge_envelope(&item)
            .and_then(|_| validate_knowledge_dependencies(&item, &retained));
        assert_outcome(&result, &case["expected"], case);
        if text(&case["expected"]) == "missing_dependency" {
            assert_eq!(
                json!(missing_knowledge_dependencies(&item, &retained)),
                case["missing"]
            );
            assert_eq!(
                result.unwrap_err().data(),
                Some(&json!({"missing":case["missing"]}))
            );
        }
    }
    for case in array(&v["view_cases"]) {
        for order in array(&case["arrival_orders"]) {
            let mut store = KnowledgeStore::new(SERVICE).unwrap();
            let mut pending: Vec<_> = array(order).to_vec();
            while !pending.is_empty() {
                let old = pending.len();
                let mut unresolved = Vec::new();
                for name in pending {
                    let before = format!("{store:?}");
                    match store.import(&envelope(&v, &name), v["now"].as_i64().unwrap()) {
                        Ok(_) => (),
                        Err(e) => {
                            assert_eq!(e.code(), Some("missing_dependency"));
                            assert_eq!(format!("{store:?}"), before);
                            unresolved.push(name);
                        }
                    }
                }
                pending = unresolved;
                assert!(pending.len() < old, "dependency deadlock");
            }
            assert_eq!(
                materialize_knowledge(&store.visible_envelopes()).unwrap(),
                case["expected"],
                "{}",
                text(&case["name"])
            );
            if let Some(links) = case["expected_relations"].as_object() {
                for (name, expected) in links {
                    assert_eq!(
                        store.event(&id(&v, &json!(name))).unwrap()["envelope"]["event"]["payload"]
                            ["relations"],
                        *expected
                    );
                }
            }
        }
    }
}

#[test]
fn acceptance_and_evidence_cases() {
    let v = vectors();
    for case in array(&v["acceptance_cases"]) {
        let mut store = KnowledgeStore::new(SERVICE).unwrap();
        for step in array(&case["steps"]) {
            if let Some(name) = step.get("withhold") {
                store.hide(&id(&v, name));
                continue;
            }
            let item = envelope(&v, &step["fixture"]);
            let now = step["now"].as_i64().unwrap();
            let before = format!("{store:?}");
            let actor = serde_json::from_value(item["event"]["actor"].clone()).unwrap();
            let max_before = store.max_nonce(&actor, now);
            let result = store.accept(
                &item,
                if step["mode"] == "live" {
                    KnowledgeAcceptanceMode::Live
                } else {
                    KnowledgeAcceptanceMode::Import
                },
                now,
            );
            let outcome = match &result {
                Ok(a) => {
                    if a.resubmission {
                        "resubmission"
                    } else {
                        "accepted"
                    }
                }
                Err(e) => e.code().unwrap_or("unmapped_error"),
            };
            assert_eq!(
                outcome,
                text(&step["expected"]),
                "{} / {}: {:?}",
                text(&case["name"]),
                text(&step["fixture"]),
                result
            );
            if let Ok(a) = &result {
                assert_eq!(a.record["seq"], step["seq"]);
            } else {
                assert_eq!(store.checkpoint(), step["seq"].as_u64().unwrap());
            }
            if outcome != "accepted" {
                assert_eq!(
                    format!("{store:?}"),
                    before,
                    "rejection/retry changed state"
                );
            }
            if let Ok(a) = result {
                if !a.resubmission {
                    assert_eq!(a.record["accepted_at"], step["now"]);
                }
            }
            if step["mode"] == "import" {
                assert_eq!(store.max_nonce(&actor, now), max_before);
            }
            assert_eq!(json!(store.max_nonce(&actor, now)), step["live_max"]);
        }
    }
    for case in array(&v["evidence_cases"]) {
        let raw = case["representation_hex"].as_str().map(bytes);
        let result = verify_knowledge_evidence(
            case["digest"].as_str(),
            raw.as_deref(),
            case["fetched"].as_bool().unwrap_or(true),
            case["complete"].as_bool().unwrap_or(false),
        );
        assert_eq!(
            serde_json::to_value(result).unwrap(),
            case["expected"],
            "{}",
            text(&case["name"])
        );
    }
}

#[test]
fn query_and_text_cases() {
    let v = vectors();
    for case in array(&v["query_cases"]) {
        let result = parse_knowledge_query(&parameters(&case["parameters"])).map(|request| {
            let matches: Vec<_> = array(&case["accepted"])
                .iter()
                .filter(|name| knowledge_query_matches(&envelope(&v, name), &request).unwrap())
                .cloned()
                .collect();
            assert_eq!(json!(matches), case["matches"], "{}", text(&case["name"]));
        });
        assert_outcome(&result, &case["expected"], case);
    }
    for case in array(&v["text_cases"]) {
        let result = case["raw_text_json"]
            .as_str()
            .map_or_else(
                || {
                    knowledge_text_terms(
                        text(&case["text"]),
                        case["lexical"].as_bool().unwrap_or(true),
                    )
                },
                |raw| parse_knowledge_read_json(raw).map(|_| Vec::new()),
            )
            .map(|terms| {
                assert_eq!(json!(terms), case["terms"], "{}", text(&case["name"]));
                if case.get("fixture").is_some() {
                    assert_eq!(
                        knowledge_text_matches(
                            &envelope(&v, &case["fixture"]),
                            text(&case["text"])
                        )
                        .unwrap(),
                        case["matches"].as_bool().unwrap()
                    );
                }
            });
        assert_outcome(&result, &case["expected"], case);
    }
}

#[test]
fn batch_and_search_cases() {
    let v = vectors();
    let now = v["now"].as_i64().unwrap();
    for case in array(&v["batch_cases"]) {
        let store = model(&v, case);
        let before = format!("{store:?}");
        let result = (|| -> Result<()> {
            let request = if let Some(raw) = case["raw_json"].as_str() {
                parse_knowledge_read_json(raw)?
            } else {
                case["request"].clone()
            };
            let response = mutate(store.batch(&request, now)?, &case["response_changes"]);
            validate_knowledge_batch_response(
                &response,
                &validate_knowledge_batch_request(&request)?,
                SERVICE,
            )?;
            assert_eq!(
                json!(array(&response["result"])
                    .iter()
                    .map(|r| r["envelope"]["hash"].clone())
                    .collect::<Vec<_>>()),
                case["result"]
            );
            assert_eq!(response["missing"], case["missing"]);
            Ok(())
        })();
        assert_outcome(&result, &case["expected"], case);
        assert_eq!(format!("{store:?}"), before);
    }
    for case in array(&v["search_cases"]) {
        let mut store = model(&v, case);
        let before = store.visible_envelopes();
        let checkpoint = store.checkpoint();
        let result = (|| -> Result<()> {
            let request = if let Some(raw) = case["raw_json"].as_str() {
                parse_knowledge_read_json(raw)?
            } else {
                case["request"].clone()
            };
            let ranking = case
                .get("ranking")
                .cloned()
                .unwrap_or(json!({"mode":request["mode"],"id":"fixture-v1"}));
            let coverage = case
                .get("coverage")
                .cloned()
                .unwrap_or(json!({"exhaustive":true,"reasons":[]}));
            let response = mutate(
                store.search(
                    &request,
                    &names(&v, &case["candidates"]),
                    &ranking,
                    &coverage,
                    &modes(case),
                    now,
                )?,
                &case["response_changes"],
            );
            validate_knowledge_search_response(&response, &request, SERVICE)?;
            let hashes: Vec<_> = array(&response["result"])
                .iter()
                .map(|r| r["record"]["envelope"]["hash"].clone())
                .collect();
            assert_eq!(
                json!(hashes),
                case.get("result").cloned().unwrap_or(json!([])),
                "{}",
                text(&case["name"])
            );
            Ok(())
        })();
        assert_outcome(&result, &case["expected"], case);
        assert_eq!(store.visible_envelopes(), before);
        assert_eq!(store.checkpoint(), checkpoint);
    }
}

#[test]
fn snapshot_and_discovery_cases() {
    let v = vectors();
    for case in array(&v["query_snapshot_cases"]) {
        let mut store = model(&v, case);
        let mut now = v["now"].as_i64().unwrap();
        let mut previous = Value::Null;
        let mut tracker = None;
        let search = case["operation"] == "search";
        for step in array(&case["steps"]) {
            for name in array(&step["add"]) {
                store
                    .import(&envelope(&v, name), v["now"].as_i64().unwrap())
                    .unwrap();
            }
            for name in array(&step["hide"]) {
                store.hide(&id(&v, name));
            }
            for name in array(&step["reveal"]) {
                store.unhide(&id(&v, name)).unwrap();
            }
            now += step["advance_ms"].as_i64().unwrap_or(0);
            if step["expire"] == true {
                store.expire_cursors();
            }
            let result = (|| -> Result<()> {
                let mut request = if search {
                    let r = step["request"].clone();
                    validate_knowledge_search_request(&r, &modes(case))?;
                    r
                } else {
                    parse_knowledge_query(&parameters(&step["parameters"]))?
                };
                if step["continue"] == true {
                    request["cursor"] = previous["next_cursor"].clone();
                } else {
                    tracker = Some(KnowledgePageValidator::new(
                        SERVICE,
                        if search {
                            KnowledgeReadOperation::Search
                        } else {
                            KnowledgeReadOperation::Query
                        },
                        &request,
                    )?);
                }
                let response = if search {
                    store.search(
                        &request,
                        &names(&v, step.get("candidates").unwrap_or(&case["candidates"])),
                        step.get("ranking").unwrap_or(&case["ranking"]),
                        step.get("coverage").unwrap_or(&case["coverage"]),
                        &modes(case),
                        now,
                    )?
                } else {
                    store.query_available(
                        &request,
                        now,
                        step["available"].as_bool().unwrap_or(true),
                    )?
                };
                let response = mutate(response, &step["response_changes"]);
                tracker
                    .as_mut()
                    .unwrap()
                    .validate_page(&response, &request)?;
                let hashes: Vec<_> = array(&response["result"])
                    .iter()
                    .map(|r| {
                        text(if search {
                            &r["record"]["envelope"]["hash"]
                        } else {
                            &r["envelope"]["hash"]
                        })
                        .to_owned()
                    })
                    .collect();
                assert_eq!(
                    hashes,
                    names(&v, &step["matches"]),
                    "{}",
                    text(&case["name"])
                );
                assert_eq!(
                    response.get("next_cursor").is_some(),
                    step["more"].as_bool().unwrap(),
                    "{}",
                    text(&case["name"])
                );
                if search {
                    assert_eq!(
                        json!(array(&response["result"])
                            .iter()
                            .map(|h| h["rank"].clone())
                            .collect::<Vec<_>>()),
                        step["ranks"]
                    );
                    assert_eq!(response["ranking"], case["ranking"]);
                    assert_eq!(response["coverage"], case["coverage"]);
                }
                previous = response;
                Ok(())
            })();
            assert_outcome(&result, &step["expected"], case);
        }
    }
    for case in array(&v["discovery_cases"]) {
        assert_outcome(
            &validate_knowledge_discovery(
                &case["document"],
                case["origin"].as_str().unwrap_or(SERVICE),
            ),
            &case["expected"],
            case,
        );
    }
}

#[test]
fn typed_roundtrip_and_builders_preserve_signed_data() {
    let v = vectors();
    let mut count = 0;
    for fixture in v["fixtures"].as_object().unwrap().values() {
        let raw = &fixture["envelope"];
        if validate_knowledge_envelope(raw).is_err() {
            continue;
        }
        let roundtrip = match text(&raw["event"]["type"]) {
            "knowledge.publish" => serde_json::to_value(
                serde_json::from_value::<Envelope<KnowledgePublishPayload>>(raw.clone()).unwrap(),
            )
            .unwrap(),
            "knowledge.assess" => serde_json::to_value(
                serde_json::from_value::<Envelope<KnowledgeAssessPayload>>(raw.clone()).unwrap(),
            )
            .unwrap(),
            _ => serde_json::to_value(
                serde_json::from_value::<Envelope<KnowledgeRetractPayload>>(raw.clone()).unwrap(),
            )
            .unwrap(),
        };
        assert_eq!(roundtrip, *raw);
        validate_knowledge_envelope(&roundtrip).unwrap();
        count += 1;
    }
    assert!(count > 30);
    let signer = AgentSigner::from_seed([7; 32]);
    let mut payload = envelope(&v, &json!("original"))["event"]["payload"].clone();
    payload["evidence"] = json!([]);
    payload["relations"] = json!([]);
    payload["tags"] = json!([]);
    payload["profiles"] = json!([]);
    payload["extra"] = json!({"arbitrary":{"nested":[{},[],null]},"duplicate_values":[1,1]});
    let payload: KnowledgePublishPayload = serde_json::from_value(payload).unwrap();
    let signed = signer
        .sign_event(knowledge_publish_event(
            signer.agent_id(),
            v["now"].as_i64().unwrap(),
            1,
            payload,
        ))
        .unwrap();
    validate_typed_knowledge_envelope(&signed).unwrap();
    let raw = serde_json::to_value(&signed).unwrap();
    let back: Envelope<KnowledgePublishPayload> = serde_json::from_value(raw.clone()).unwrap();
    assert_eq!(serde_json::to_value(back).unwrap(), raw);
    let mut unknown = raw.clone();
    unknown["unknown"] = json!(1);
    assert!(validate_knowledge_envelope(&unknown).is_err());
    let mut unknown = raw;
    unknown["event"]["unknown"] = json!(1);
    assert!(validate_knowledge_envelope(&unknown).is_err());
}

#[test]
fn changes_pruning_and_page_guards() {
    let v = vectors();
    let now = v["now"].as_i64().unwrap();
    let mut store = model(
        &v,
        &json!({"accepted":["original","branch_left","branch_right"]}),
    );
    let request = json!({"limit":1});
    let first = store.changes(&request, now).unwrap();
    let mut tracker =
        KnowledgePageValidator::new(SERVICE, KnowledgeReadOperation::Changes, &request).unwrap();
    tracker.validate_page(&first, &request).unwrap();
    let next = json!({"limit":1,"cursor":first["next_cursor"]});
    let second = store.changes(&next, now + 1).unwrap();
    tracker.validate_page(&second, &next).unwrap();
    assert!(store
        .changes(&json!({"after":store.checkpoint()+1}), now)
        .is_err());
    let original = envelope(&v, &json!("original"));
    store.hide(text(&original["hash"]));
    assert!(store.event(text(&original["hash"])).is_err());
    let retry = store.import(&original, now).unwrap();
    assert!(retry.resubmission);
    assert!(store.event(text(&original["hash"])).is_err());
    store.prune(text(&original["hash"]));
    let fresh = store.import(&original, now).unwrap();
    assert_eq!(fresh.record["seq"], 4);
    assert!(!fresh.resubmission);
    let request = json!({"limit":1});
    let mut tracker =
        KnowledgePageValidator::new(SERVICE, KnowledgeReadOperation::Query, &request).unwrap();
    let first = store.query(&request, now).unwrap();
    tracker.validate_page(&first, &request).unwrap();
    let next = json!({"limit":1,"cursor":first["next_cursor"]});
    let mut second = store.query(&next, now).unwrap();
    second["result"] = first["result"].clone();
    assert!(tracker.validate_page(&second, &next).is_err());
    assert!(materialize_knowledge(&BTreeMap::from([(
        text(&original["hash"]).into(),
        original
    )]))
    .is_ok());
}

#[test]
fn integral_json_numbers_shared_nonces_and_bounded_snapshots() {
    use agent_protocols::identity::{MemoryNonceStore, NonceStore};
    let v = vectors();
    let now = v["now"].as_i64().unwrap();
    let mut store = KnowledgeStore::new(SERVICE).unwrap();
    let mut original = envelope(&v, &json!("original"));
    original["event"]["nonce"] = json!(original["event"]["nonce"].as_u64().unwrap() as f64);
    original["event"]["created_at"] = json!(now as f64);
    // Event timestamp in this fixture is already `now`; JCS hashes 1 and 1.0
    // identically and protocol JSON integer semantics accept both.
    validate_knowledge_envelope(&original).unwrap();
    store.import(&original, now).unwrap();
    let page = store
        .query(&json!({"limit":1.0,"created_from":0.0}), now)
        .unwrap();
    let mut floated = page.clone();
    floated["checkpoint"] = json!(1.0);
    floated["result"][0]["seq"] = json!(1.0);
    floated["result"][0]["accepted_at"] = json!(now as f64);
    validate_knowledge_query_response(&floated, &json!({"limit":1.0}), SERVICE).unwrap();
    let mut tracker =
        KnowledgePageValidator::new(SERVICE, KnowledgeReadOperation::Query, &json!({"limit":1}))
            .unwrap();
    tracker
        .validate_page(&floated, &json!({"limit":1.0}))
        .unwrap();
    assert!(tracker.validate_page(&floated, &Value::Null).is_err());
    let mut shared = MemoryNonceStore::new();
    let actor = serde_json::from_value(original["event"]["actor"].clone()).unwrap();
    shared.check_and_update(&actor, 100, now, 600000).unwrap();
    let mut second = KnowledgeStore::new(SERVICE).unwrap();
    assert_eq!(
        second
            .accept_with_nonce_store(&original, KnowledgeAcceptanceMode::Live, now, &mut shared)
            .unwrap_err()
            .code(),
        Some("nonce_not_greater")
    );
    assert_eq!(second.checkpoint(), 0);
    second
        .accept_with_nonce_store(&original, KnowledgeAcceptanceMode::Import, now, &mut shared)
        .unwrap();
    assert_eq!(shared.max_nonce(&actor, now), Some(100));
    let mut invalid = KnowledgeStore::new(SERVICE).unwrap();
    invalid.nonce_ttl_ms = 1;
    assert!(invalid.submit(&original, now).is_err());
    assert_eq!(invalid.max_nonce(&actor, now), None);
    store
        .import(&envelope(&v, &json!("branch_left")), now)
        .unwrap();
    store.max_snapshots = 1;
    store.snapshot_ttl_ms = 10;
    let first = store.query(&json!({"limit":1}), now).unwrap();
    let second = store.query(&json!({"limit":1}), now).unwrap();
    assert!(store
        .query(&json!({"limit":1,"cursor":first["next_cursor"]}), now)
        .is_err());
    assert!(store
        .query(&json!({"limit":1,"cursor":second["next_cursor"]}), now + 10)
        .is_err());
}

#[test]
fn profile_conformance_is_scoped_and_requires_material() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha3::{Digest, Sha3_256};
    let artifact = b"profile rules";
    let digest = URL_SAFE_NO_PAD.encode(Sha3_256::digest(artifact));
    let binding = KnowledgeProfileBinding {
        profile: KnowledgeProfileReference {
            url: "https://example.com/profile".into(),
            digest: digest.clone(),
        },
        data: BTreeMap::new(),
    };
    type Validator = fn(&[u8], &BTreeMap<String, Value>) -> Result<bool>;
    let yes: Validator = |_, _| Ok(true);
    let no: Validator = |_, _| Ok(false);
    assert_eq!(
        validate_knowledge_profile(&binding, Some(artifact), true, None::<Validator>).unwrap(),
        ProfileStatus::Unchecked
    );
    assert_eq!(
        validate_knowledge_profile(&binding, None, true, Some(yes)).unwrap(),
        ProfileStatus::Unavailable
    );
    assert_eq!(
        validate_knowledge_profile(&binding, Some(b"wrong"), true, Some(yes)).unwrap(),
        ProfileStatus::Unavailable
    );
    assert_eq!(
        validate_knowledge_profile(&binding, Some(artifact), false, Some(yes)).unwrap(),
        ProfileStatus::Unavailable
    );
    assert_eq!(
        validate_knowledge_profile(&binding, Some(artifact), true, Some(no)).unwrap(),
        ProfileStatus::Nonconformant
    );
    let v = vectors();
    let mut payload = envelope(&v, &json!("original"))["event"]["payload"].clone();
    payload["profiles"] = json!([binding]);
    let signer = AgentSigner::from_seed([61; 32]);
    let item = serde_json::to_value(
        signer
            .sign_event(identity::Event::new(
                PROTOCOL,
                "knowledge.publish",
                signer.agent_id(),
                v["now"].as_i64().unwrap(),
                1,
                payload,
            ))
            .unwrap(),
    )
    .unwrap();
    let report =
        validate_knowledge_event_profile(&item, &digest, Some(artifact), true, Some(yes)).unwrap();
    assert_eq!(report.status, ProfileStatus::Conformant);
    assert_eq!(report.event_id, text(&item["hash"]));
    assert_eq!(report.profile_digest, digest);
}

#[test]
fn duplicate_service_sequences_are_rejected_within_and_across_pages() {
    let v = vectors();
    let now = v["now"].as_i64().unwrap();
    let mut store = model(&v, &json!({"accepted":["original","branch_left"]}));
    let ids = names(&v, &json!(["original", "branch_left"]));
    let request = json!({"hashes":ids});
    let mut batch = store.batch(&request, now).unwrap();
    batch["result"][1]["seq"] = batch["result"][0]["seq"].clone();
    assert_eq!(
        validate_knowledge_batch_response(&batch, &ids, SERVICE)
            .unwrap_err()
            .code(),
        Some("invalid_response")
    );
    let request = json!({"mode":"semantic","text":"research"});
    let ranking = json!({"mode":"semantic","id":"test"});
    let coverage = json!({"exhaustive":false,"reasons":["approximate"]});
    let modes = vec!["semantic".into()];
    let mut search = store
        .search(&request, &ids, &ranking, &coverage, &modes, now)
        .unwrap();
    search["result"][1]["record"]["seq"] = search["result"][0]["record"]["seq"].clone();
    assert_eq!(
        validate_knowledge_search_response(&search, &request, SERVICE)
            .unwrap_err()
            .code(),
        Some("invalid_response")
    );
    let request = json!({"mode":"semantic","text":"research","limit":1});
    let mut tracker =
        KnowledgePageValidator::new(SERVICE, KnowledgeReadOperation::Search, &request).unwrap();
    let first = store
        .search(&request, &ids, &ranking, &coverage, &modes, now)
        .unwrap();
    tracker.validate_page(&first, &request).unwrap();
    let mut next = request.clone();
    next["cursor"] = first["next_cursor"].clone();
    let mut second = store
        .search(&next, &ids, &ranking, &coverage, &modes, now)
        .unwrap();
    second["result"][0]["record"]["seq"] = first["result"][0]["record"]["seq"].clone();
    assert_eq!(
        tracker.validate_page(&second, &next).unwrap_err().code(),
        Some("invalid_response")
    );
}
