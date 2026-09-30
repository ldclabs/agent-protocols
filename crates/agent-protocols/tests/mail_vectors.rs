use agent_protocols::{
    identity::{self, AgentSigner, Envelope, NonceStore, RequestBinding, RequestJwtClaims},
    mail::*,
};
use serde_json::{json, Value};
fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../docs/protocols/agent-mail/1.0.vectors.json"
    ))
    .unwrap()
}
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn card(v: &Value, name: &str) -> MailboxCard {
    validate_card(&v["envelopes"][name]).unwrap()
}
fn packet(v: &Value, name: &str) -> Packet {
    validate_packet(&v["encryptions"][name]["packet"]).unwrap()
}
fn key(v: &Value, card: &MailboxCard) -> MailEncryptionKey {
    let original = validate_card(&v["envelopes"]["card"]).unwrap();
    let name = if original.event.payload.public_key == card.event.payload.public_key {
        "recipient_secret_hex"
    } else {
        "rotated_recipient_secret_hex"
    };
    MailEncryptionKey::from_secret(&hex(v["keys"][name].as_str().unwrap())).unwrap()
}
fn owner_signer(v: &Value) -> AgentSigner {
    AgentSigner::from_seed(
        hex(v["keys"]["recipient_seed_hex"].as_str().unwrap())
            .try_into()
            .unwrap(),
    )
}
fn token(signer: &AgentSigner, origin: &str, now: i64) -> String {
    signer
        .sign_request_jwt(&RequestJwtClaims::new(
            signer.agent_id(),
            RequestBinding::new(origin),
            now / 1000,
            300,
        ))
        .unwrap()
}
#[test]
fn shared_schema_signing_and_strict_json_vectors() {
    let v = vectors();
    assert_eq!(
        serde_json::from_str::<Value>(SCHEMA_JSON).unwrap(),
        serde_json::from_str::<Value>(include_str!(
            "../../../docs/protocols/agent-mail/1.0.schema.json"
        ))
        .unwrap()
    );
    for case in v["schema_cases"].as_array().unwrap() {
        assert_eq!(
            validate_mail_schema(&case["value"], case["definition"].as_str().unwrap()).is_ok(),
            case["valid"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
    for (name, s) in v["signing"].as_object().unwrap() {
        let value = &v["envelopes"][name];
        let e: Envelope<Value> = serde_json::from_value(value.clone()).unwrap();
        let signer =
            AgentSigner::from_seed(hex(s["seed_hex"].as_str().unwrap()).try_into().unwrap());
        assert_eq!(
            canonical_bytes(&e.event).unwrap(),
            s["event_jcs"].as_str().unwrap().as_bytes()
        );
        assert_eq!(
            canonical_bytes(&e).unwrap(),
            s["envelope_jcs"].as_str().unwrap().as_bytes()
        );
        assert_eq!(
            serde_json::to_value(signer.sign_event(e.event).unwrap()).unwrap(),
            *value
        );
        if value["event"]["type"] == "mailbox.publish" {
            validate_card(value).unwrap();
        } else {
            validate_letter(value).unwrap();
        }
    }
    for text in v["strict_json_rejections"].as_array().unwrap() {
        assert!(identity::parse_strict_json(text.as_str().unwrap()).is_err());
    }
    let mut value = v["envelopes"]["letter"].clone();
    value["event"]["payload"]["subject"] = Value::Null;
    assert!(parse_letter(&value.to_string()).is_err());
    let card_json = v["envelopes"]["card"].to_string().replacen(
        "\"nonce\":100",
        "\"nonce\":100,\"nonce\":100",
        1,
    );
    assert!(parse_card(&card_json).is_err());
}
#[test]
fn shared_hpke_vectors_and_random_roundtrips() {
    let v = vectors();
    let now = v["now"].as_i64().unwrap();
    for (name, e) in v["encryptions"].as_object().unwrap() {
        let c = card(&v, e["card"].as_str().unwrap());
        let p = packet(&v, name);
        let l = validate_letter(&v["envelopes"][e["letter"].as_str().unwrap()]).unwrap();
        assert_eq!(
            canonical_bytes(&p).unwrap(),
            e["packet_jcs"].as_str().unwrap().as_bytes()
        );
        assert_eq!(packet_id(&p).unwrap(), e["packet_id"]);
        assert_eq!(
            *frame_bytes(&canonical_bytes(&l).unwrap()).unwrap(),
            decode_bytes(e["plaintext_b64"].as_str().unwrap()).unwrap()
        );
        assert_eq!(
            decrypt_packet(&p, &c, &key(&v, &c), &c.event.actor, now).unwrap(),
            l
        );
        let fresh = encrypt_letter(&l, &c, now).unwrap();
        assert_ne!(fresh.enc, p.enc);
        assert_eq!(
            decrypt_packet(&fresh, &c, &key(&v, &c), &c.event.actor, now).unwrap(),
            l
        );
    }
    for f in v["framing_boundaries"].as_array().unwrap() {
        let bytes = vec![b'x'; f["json_byte_length"].as_u64().unwrap() as usize];
        let frame = frame_bytes(&bytes).unwrap();
        assert_eq!(frame.len() as u64, f["frame_byte_length"]);
        assert_eq!(frame[..4], hex(f["length_prefix_hex"].as_str().unwrap()));
        assert_eq!(hash_bytes(&frame), f["plaintext_sha3_256"]);
    }
    let generated = MailEncryptionKey::generate().unwrap();
    let restored = MailEncryptionKey::from_secret(&generated.export_secret()).unwrap();
    assert_eq!(generated.public_key(), restored.public_key());
}
#[test]
fn official_rfc9180_known_answer_with_production_primitive() {
    use hpke::{kem::X25519HkdfSha256 as K, Deserializable, Kem, Serializable};
    let v = vectors();
    let kat = &v["rfc9180_known_answer"];
    let sk = <K as Kem>::PrivateKey::from_bytes(&hex(kat["skRm"].as_str().unwrap())).unwrap();
    let enc = <K as Kem>::EncappedKey::from_bytes(&hex(kat["pkEm"].as_str().unwrap())).unwrap();
    assert_eq!(
        K::sk_to_pk(&sk).to_bytes().as_slice(),
        hex(kat["pkRm"].as_str().unwrap())
    );
    assert_eq!(
        K::decap(&sk, None, &enc).unwrap().0.as_slice(),
        hex(kat["shared_secret"].as_str().unwrap())
    );
    let pt = hpke::single_shot_open::<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha256, K>(
        &hpke::OpModeR::Base,
        &sk,
        &enc,
        &hex(kat["info"].as_str().unwrap()),
        &hex(kat["ct"].as_str().unwrap()),
        &hex(kat["aad"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(pt, hex(kat["pt"].as_str().unwrap()));
}
#[test]
fn every_shared_recipient_rejection() {
    let v = vectors();
    let now = v["now"].as_i64().unwrap();
    for case in v["recipient_rejections"].as_array().unwrap() {
        let c = if let Some(value) = case.get("card") {
            card(&v, value.as_str().unwrap())
        } else {
            card(&v, "card")
        };
        let secret = case["secret_hex"]
            .as_str()
            .unwrap_or(v["keys"]["recipient_secret_hex"].as_str().unwrap());
        let k = MailEncryptionKey::from_secret(&hex(secret)).unwrap();
        let owner = case
            .get("owner")
            .map(|s| serde_json::from_value(s.clone()).unwrap())
            .unwrap_or(c.event.actor.clone());
        let outcome = (|| {
            let p = validate_packet(&case["packet"])?;
            if let Some(id) = case["packet_id"].as_str() {
                if packet_id(&p)? != id {
                    return Err(agent_protocols::SdkError::protocol(
                        "invalid_packet",
                        "wrong id",
                    ));
                }
            }
            decrypt_packet(&p, &c, &k, &owner, now)
        })();
        assert!(
            outcome.is_err(),
            "accepted invalid recipient case {}",
            case["name"]
        );
    }
}
#[test]
fn shared_sender_discovery_and_authorization_cases() {
    let v = vectors();
    let c = card(&v, "card");
    let now = v["now"].as_i64().unwrap();
    for case in v["sender_card_cases"].as_array().unwrap() {
        assert!(
            validate_card_for_sending(&case["card"], &c.event.actor, case["now"].as_i64().unwrap())
                .is_err(),
            "{}",
            case["name"]
        );
    }
    for case in v["discovery_cases"].as_array().unwrap() {
        assert_eq!(
            validate_discovery(&case["value"], "https://relay.example", Some(&c)).is_ok(),
            case["expected"] == "valid",
            "{}",
            case["name"]
        );
    }
    for case in v["owner_jwt_cases"].as_array().unwrap() {
        let result = verify_owner_jwt(
            case["token"].as_str().unwrap(),
            &c.event.actor,
            "https://relay.example",
            now,
        );
        assert_eq!(
            result.is_ok(),
            case["expected"] == "valid",
            "{}",
            case["name"]
        );
        if let Err(e) = result {
            assert_eq!(e.code().unwrap(), case["expected"].as_str().unwrap());
        }
    }
    let jwt = v["owner_jwt_cases"][0]["token"].as_str().unwrap();
    assert_eq!(
        verify_owner_jwt(jwt, &c.event.actor, "https://relay.example", now + 300_000)
            .unwrap_err()
            .code(),
        Some("invalid_token")
    );
    let parts: Vec<_> = jwt.split('.').collect();
    let claims = String::from_utf8(decode_bytes(parts[1]).unwrap()).unwrap();
    let duplicate = claims.replacen("{", "{\"exp\":1790726700,", 1);
    let malicious = format!(
        "{}.{}.{}",
        parts[0],
        encode_bytes(duplicate.as_bytes()),
        parts[2]
    );
    assert!(verify_owner_jwt(&malicious, &c.event.actor, "https://relay.example", now).is_err());
}
#[test]
fn shared_card_cache_lifecycles_survive_snapshots() {
    let v = vectors();
    let c = card(&v, "card");
    let now = v["now"].as_i64().unwrap();
    for scenario in ["card_cache", "persistent_card_pin"] {
        let mut cache = CardCache::new();
        for step in v["lifecycle"][scenario].as_array().unwrap() {
            let result = cache.observe(
                &v["envelopes"][step["card"].as_str().unwrap()],
                &c.event.actor,
                step["now"].as_i64().unwrap_or(now),
            );
            let actual = match result {
                Ok(_) => "usable",
                Err(e) => match e.code() {
                    Some("card_equivocation") => "equivocation",
                    Some("mailbox_conflict") => "key_reuse",
                    Some("mailbox_unavailable") => "disabled",
                    Some("stale_card") => "rollback",
                    _ => panic!("unexpected cache error {e}"),
                },
            };
            assert_eq!(actual, step["expected"], "{}", step["card"]);
            cache = CardCache::from_snapshot(&cache.snapshot().unwrap()).unwrap();
        }
    }
}
fn recipient(v: &Value) -> MailRecipient {
    let c = card(v, "card");
    let mut r = MailRecipient::new(c.event.actor.clone());
    for name in ["card", "rotated_card"] {
        let c = card(v, name);
        r.add_key(&c, key(v, &c)).unwrap();
    }
    r
}
#[test]
fn shared_recipient_lifecycle_and_receipts() {
    let v = vectors();
    let mut r = recipient(&v);
    for step in v["lifecycle"]["recipient"].as_array().unwrap() {
        let p = packet(&v, step["packet"].as_str().unwrap());
        let out = r.receive(&p, None, step["now"].as_i64().unwrap()).unwrap();
        assert_eq!(
            matches!(out, RecipientAcceptance::Accepted(_)),
            step["expected"] == "accepted"
        );
        assert_eq!(r.letters().len() as u64, step["items"]);
        r = MailRecipient::from_snapshot(&r.snapshot().unwrap()).unwrap();
    }
    let history = &v["lifecycle"]["historical_card"];
    assert!(recipient(&v)
        .receive(
            &packet(&v, "original"),
            None,
            history["now"].as_i64().unwrap()
        )
        .is_ok());
    let expired = &v["lifecycle"]["expired_new_letter"];
    assert_eq!(
        recipient(&v)
            .receive(
                &packet(&v, "original"),
                None,
                expired["now"].as_i64().unwrap()
            )
            .unwrap_err()
            .code(),
        Some("packet_expired")
    );
    let original = validate_letter(&v["envelopes"]["letter"]).unwrap();
    let receipt = validate_letter(&v["envelopes"]["receipt"]).unwrap();
    validate_receipt(&receipt, &original).unwrap();
    assert!(validate_receipt(
        &receipt,
        &validate_letter(&v["envelopes"]["lower_nonce_letter"]).unwrap()
    )
    .is_err());
    let now = v["now"].as_i64().unwrap();
    let generated = sign_receipt(&owner_signer(&v), &original, now + 10000, now, 300).unwrap();
    validate_receipt(&generated, &original).unwrap();
    assert!(sign_receipt(&owner_signer(&v), &receipt, now + 10000, now, 301).is_err());
    let reply = sign_message(
        &owner_signer(&v),
        MessagePayload {
            to: original.event.actor.clone(),
            expires_at: now + 10000,
            thread_id: original.event.payload["thread_id"].as_str().unwrap().into(),
            parts: vec![MailPart::text("Answer")],
            subject: None,
            in_reply_to: Some(original.hash.clone()),
            reply_card: None,
            receipt_requested: None,
        },
        now,
        302,
    )
    .unwrap();
    validate_reply(&reply, &original).unwrap();
    let mut mutated = r.letters();
    mutated[0].event.payload["subject"] = json!("changed");
    assert_ne!(r.letters(), mutated);
}
#[test]
fn relay_shared_lifecycle_snapshots_and_owner_access() {
    let v = vectors();
    let now = v["now"].as_i64().unwrap();
    let owner = owner_signer(&v);
    let jwt = token(&owner, "https://relay.example", now);
    let c = card(&v, "card");
    let mailbox = &c.event.payload.mailbox_id;
    let mut relay = MailRelay::new("https://relay.example").unwrap();
    relay.publish(&v["envelopes"]["card"], now).unwrap();
    for step in v["lifecycle"]["relay"].as_array().unwrap() {
        match step["op"].as_str().unwrap() {
            "set_current" => {
                relay
                    .publish(&v["envelopes"][step["card"].as_str().unwrap()], now)
                    .unwrap();
            }
            "delete" => {
                relay
                    .delete(
                        mailbox,
                        &packet_id(&packet(&v, step["packet"].as_str().unwrap())).unwrap(),
                        &jwt,
                        now,
                    )
                    .unwrap();
            }
            "deliver" => {
                let result = relay.deliver(
                    mailbox,
                    &packet(&v, step["packet"].as_str().unwrap()),
                    step["now"].as_i64().unwrap(),
                );
                if let Some(seq) = step["seq"].as_u64() {
                    let result = result.unwrap();
                    assert_eq!(result.seq, seq);
                    assert_eq!(result.accepted_at, step["accepted_at"]);
                } else {
                    assert_eq!(
                        result.unwrap_err().code(),
                        Some(if step["expected"] == "disabled" {
                            "mailbox_unavailable"
                        } else {
                            "stale_card"
                        })
                    );
                }
            }
            _ => panic!("unknown lifecycle op"),
        }
        if let Some(stored) = step["stored"].as_u64() {
            assert_eq!(
                relay
                    .list(mailbox, &jwt, now, 100, None)
                    .unwrap()
                    .result
                    .len() as u64,
                stored
            );
        }
        relay = MailRelay::from_snapshot(&relay.snapshot().unwrap()).unwrap();
    }
    for case in v["owner_jwt_cases"].as_array().unwrap() {
        let t = case["token"].as_str().unwrap();
        assert_eq!(
            relay.list(mailbox, t, now, 100, None).is_ok(),
            case["expected"] == "valid"
        );
        if case["expected"] != "valid" {
            assert!(relay
                .delete(
                    mailbox,
                    &packet_id(&packet(&v, "original")).unwrap(),
                    t,
                    now
                )
                .is_err());
        }
    }
    let old = relay
        .publish(&v["envelopes"]["card"], now + MAX_TTL_MS)
        .unwrap();
    assert_eq!(old.envelope.hash, c.hash);
    assert_eq!(
        relay.card(mailbox).unwrap().envelope,
        card(&v, "reenabled_card")
    );
}
#[test]
fn live_control_nonces_quota_pagination_and_failure_atomicity() {
    let v = vectors();
    let now = v["now"].as_i64().unwrap();
    let original = card(&v, "card");
    let mailbox = original.event.payload.mailbox_id.clone();
    let signer = owner_signer(&v);
    let jwt = token(&signer, "https://relay.example", now);
    let mut relay = MailRelay::with_limits("https://relay.example", 2, 10000).unwrap();
    let mut shared = identity::MemoryNonceStore::new();
    relay
        .publish_with_nonce_store(&v["envelopes"]["card"], now, &mut shared)
        .unwrap();
    let mut p = original.event.payload.clone();
    p.routes = vec!["https://other.example".into()];
    let invalid = sign_card(&signer, p, now, 999).unwrap();
    assert!(relay
        .publish_with_nonce_store(&serde_json::to_value(invalid).unwrap(), now, &mut shared)
        .is_err());
    assert_eq!(shared.max_nonce(&signer.agent_id(), now), Some(100));
    shared
        .check_and_update(&signer.agent_id(), 200, now, 600000)
        .unwrap();
    assert!(relay
        .publish_with_nonce_store(&v["envelopes"]["rotated_card"], now, &mut shared)
        .is_err());
    assert_eq!(relay.card(&mailbox).unwrap().envelope, original);
    let a = relay
        .deliver(&mailbox, &packet(&v, "original"), now)
        .unwrap();
    let b = relay
        .deliver(&mailbox, &packet(&v, "reencrypted"), now)
        .unwrap();
    let before = relay.snapshot().unwrap();
    assert_eq!(
        relay
            .deliver(&mailbox, &packet(&v, "lower_nonce"), now)
            .unwrap_err()
            .code(),
        Some("quota_exceeded")
    );
    assert_eq!(relay.snapshot().unwrap(), before);
    let first = relay.list(&mailbox, &jwt, now, 1, None).unwrap();
    assert_eq!(first.result[0].seq, a.seq);
    relay.delete(&mailbox, &a.packet_id, &jwt, now).unwrap();
    let second = relay
        .list(&mailbox, &jwt, now, 1, first.next_cursor.as_deref())
        .unwrap();
    assert_eq!(second.result[0].seq, b.seq);
    assert!(second.next_cursor.is_none());
    let third = relay
        .deliver(&mailbox, &packet(&v, "lower_nonce"), now)
        .unwrap();
    assert_eq!(third.seq, 3);
    assert_eq!(
        relay
            .deliver(&mailbox, &packet(&v, "original"), now)
            .unwrap(),
        a
    );
    assert_eq!(
        relay
            .list(&mailbox, &jwt, now, 100, None)
            .unwrap()
            .result
            .len(),
        2
    );
    let mut second_payload = original.event.payload.clone();
    second_payload.mailbox_id = random_id().unwrap();
    let second_card = sign_card(&signer, second_payload, now, 201).unwrap();
    relay
        .publish(&serde_json::to_value(&second_card).unwrap(), now)
        .unwrap();
    assert!(relay
        .list(
            &second_card.event.payload.mailbox_id,
            &jwt,
            now,
            1,
            first.next_cursor.as_deref()
        )
        .is_err());
    let mut result = relay.card(&mailbox).unwrap();
    result.envelope.event.payload.enabled = false;
    assert!(relay.card(&mailbox).unwrap().envelope.event.payload.enabled);
}
#[test]
fn recipient_requires_registered_outgoing_before_accepting_receipt() {
    let v = vectors();
    let now = v["now"].as_i64().unwrap();
    let sender = AgentSigner::from_seed(
        hex(v["keys"]["sender_seed_hex"].as_str().unwrap())
            .try_into()
            .unwrap(),
    );
    let secret = MailEncryptionKey::generate().unwrap();
    let mut payload = card(&v, "card").event.payload;
    payload.public_key = secret.public_key();
    let sender_card = sign_card(&sender, payload, now, 400).unwrap();
    let receipt = validate_letter(&v["envelopes"]["receipt"]).unwrap();
    let packet = encrypt_letter(&receipt, &sender_card, now).unwrap();
    let mut recipient = MailRecipient::new(sender.agent_id());
    recipient.add_key(&sender_card, secret).unwrap();
    assert!(recipient.receive(&packet, None, now).is_err());
    assert!(recipient.letters().is_empty());
    let outgoing = validate_letter(&v["envelopes"]["letter"]).unwrap();
    recipient.remember_outgoing(&outgoing).unwrap();
    recipient = MailRecipient::from_snapshot(&recipient.snapshot().unwrap()).unwrap();
    assert!(matches!(
        recipient.receive(&packet, None, now).unwrap(),
        RecipientAcceptance::Accepted(_)
    ));
    let mut snapshot = recipient.snapshot().unwrap();
    snapshot["outgoing"] = json!([]);
    assert!(MailRecipient::from_snapshot(&snapshot).is_err());
    assert!(recipient.remember_outgoing(&receipt).is_err());
}
