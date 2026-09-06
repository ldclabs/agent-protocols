use agent_protocols::delegation::*;
use agent_protocols::identity::{AgentSigner, Envelope, Event};
use serde_json::{json, Value};

const ID: &str = "https://example.com/p";
const ORIGIN: &str = "https://dmsg.net";
fn signer() -> AgentSigner {
    AgentSigner::from_seed([61; 32])
}
fn root() -> AgentSigner {
    AgentSigner::from_seed([62; 32])
}
fn document() -> PrincipalDocument {
    serde_json::from_value(json!({"protocol":PROTOCOL,"id":ID,"updated_at":2000,"controllers":[
        {"id":signer().agent_id(),"source":ORIGIN,"valid_from":100,"delegation":{"scopes":["draft"],"audiences":[ORIGIN]}},
        {"id":root().agent_id(),"source":"local","valid_from":100,"delegation":"*"}
    ]})).unwrap()
}
fn grant(actor: &AgentSigner, scope: &str, audience: &str) -> Envelope<DelegationPayload> {
    let mut payload = DelegationGrantPayload::new(
        "del",
        PrincipalDescriptor::new(ID),
        root().agent_id(),
        vec![scope.into()],
        vec![audience.into()],
    );
    payload.expires_at = Some(1000);
    actor
        .sign_event(Event::new(
            PROTOCOL,
            DELEGATION_GRANT,
            actor.agent_id(),
            200,
            1,
            DelegationPayload::Grant(payload),
        ))
        .unwrap()
}
#[test]
fn shared_controller_conformance() {
    let cases: Vec<Value> = serde_json::from_str(include_str!("fixtures/delegation.json")).unwrap();
    for case in cases {
        let result = serde_json::from_value::<PrincipalDocument>(case["document"].clone())
            .map_err(|e| e.to_string())
            .and_then(|d| validate_principal_document(&d).map_err(|e| e.to_string()));
        assert_eq!(
            result.is_ok(),
            case["valid"].as_bool().unwrap(),
            "{}: {:?}",
            case["name"],
            result
        );
    }
}
#[test]
fn authority_ownership_and_materialization() {
    let doc = document();
    let envelope = grant(&signer(), "draft", ORIGIN);
    validate_delegation_acceptance(&envelope, &doc, ID, 250, None).unwrap();
    let credential =
        materialize_delegation_credential(&envelope, DelegationStatus::Active, 250, None).unwrap();
    assert_eq!(credential.accepted_at, 250);
    assert_eq!(credential.owner_controller, signer().agent_id());
    validate_delegation_use(&credential, ORIGIN, 300).unwrap();
    assert!(validate_delegation_use(&credential, "https://tokenlist.ing", 300).is_err());
    assert!(validate_delegation_use(&credential, ORIGIN, 1000).is_err());
    for bad in [
        grant(&signer(), "admin", ORIGIN),
        grant(&signer(), "draft", "https://tokenlist.ing"),
    ] {
        assert!(validate_delegation_acceptance(&bad, &doc, ID, 250, None).is_err());
    }
    assert!(
        validate_delegation_acceptance(&envelope, &doc, "https://impostor.example", 250, None)
            .is_err()
    );
    assert!(validate_delegation_acceptance(&envelope, &doc, ID, 1000, None).is_err());
    let mut only = doc.clone();
    only.controllers[0].delegation = None;
    validate_delegation_envelope(&envelope).unwrap();
    assert!(validate_delegation_acceptance(&envelope, &only, ID, 250, None).is_err());
    let other = materialize_delegation_credential(
        &grant(&root(), "draft", ORIGIN),
        DelegationStatus::Active,
        250,
        None,
    )
    .unwrap();
    assert!(validate_delegation_acceptance(&envelope, &doc, ID, 300, Some(&other)).is_err());
    assert!(
        validate_controller_enumeration(&doc, &signer().agent_id(), 300, &root().agent_id())
            .is_err()
    );
    validate_controller_enumeration(&doc, &root().agent_id(), 300, &signer().agent_id()).unwrap();
    let revoke = root()
        .sign_event(Event::new(
            PROTOCOL,
            DELEGATION_REVOKE,
            root().agent_id(),
            400,
            2,
            DelegationPayload::Revoke(DelegationRevokePayload {
                id: "del".into(),
                principal_id: ID.into(),
                reason: None,
            }),
        ))
        .unwrap();
    validate_delegation_acceptance(&revoke, &doc, ID, 450, Some(&credential)).unwrap();
    let revoked = materialize_delegation_credential(
        &revoke,
        DelegationStatus::Active,
        450,
        Some(&credential),
    )
    .unwrap();
    assert_eq!(revoked.status, DelegationStatus::Revoked);
    assert_eq!(revoked.controller, root().agent_id());
    assert_eq!(revoked.owner_controller, signer().agent_id());
    assert_eq!(revoked.grant_event_id, envelope.hash);
    assert_eq!(revoked.audiences, credential.audiences);
    assert!(validate_delegation_acceptance(&revoke, &doc, ID, 450, None).is_err());
    let replacement = grant(&root(), "draft", ORIGIN);
    validate_delegation_acceptance(&replacement, &doc, ID, 500, Some(&revoked)).unwrap();
    assert_eq!(
        materialize_delegation_credential(
            &replacement,
            DelegationStatus::Active,
            500,
            Some(&revoked)
        )
        .unwrap()
        .owner_controller,
        signer().agent_id()
    );
}
#[test]
fn retired_history_requires_hash_bound_acceptance() {
    let mut doc = document();
    let envelope = grant(&signer(), "draft", ORIGIN);
    let mut retired = doc.controllers.remove(0);
    retired.retired_at = Some(500);
    doc.retired_controllers.push(retired);
    assert!(validate_delegation_acceptance(&envelope, &doc, ID, 600, None).is_err());
    let mut acceptance = DelegationAcceptance {
        event_id: envelope.hash.clone(),
        accepted_at: 250,
    };
    validate_historical_delegation(&envelope, &acceptance, &doc, ID, None).unwrap();
    acceptance.event_id = "different".into();
    assert!(validate_historical_delegation(&envelope, &acceptance, &doc, ID, None).is_err());
    acceptance.event_id = envelope.hash.clone();
    acceptance.accepted_at = 500;
    assert!(validate_historical_delegation(&envelope, &acceptance, &doc, ID, None).is_err());
    acceptance.accepted_at = 250;
    doc.retired_controllers[0].invalid_from = Some(300);
    validate_historical_delegation(&envelope, &acceptance, &doc, ID, None).unwrap();
    doc.retired_controllers[0].invalid_from = Some(250);
    assert!(validate_historical_delegation(&envelope, &acceptance, &doc, ID, None).is_err());
}
