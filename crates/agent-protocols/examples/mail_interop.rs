//! Cross-language conformance adapter. Uses ONLY public deterministic fixture
//! keys; encryption itself uses the production SDK's fresh system randomness.
use agent_protocols::{identity::AgentSigner, mail::*};
use serde_json::Value;
use std::io::{self, Read};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let input: Value = serde_json::from_str(&input)?;
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../docs/protocols/agent-mail/1.0.vectors.json"
    ))?;
    let card = validate_card(&vectors["envelopes"]["card"])?;
    let letter = validate_letter(&vectors["messages"]["letter"])?;
    let seed = vectors["keys"]["sender_seed_hex"].as_str().unwrap();
    let seed: Vec<u8> = (0..seed.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&seed[i..i + 2], 16).unwrap())
        .collect();
    let signer = AgentSigner::from_seed(seed.try_into().unwrap());
    let now = vectors["now"].as_i64().unwrap();
    match input["op"].as_str() {
        Some("seal") => println!(
            "{}",
            serde_json::to_string(&encrypt_letter(
                &letter,
                &card,
                &signer,
                input["nonce"].as_u64().unwrap_or(700),
                now
            )?)?
        ),
        Some("open") => {
            let text = vectors["keys"]["recipient_secret_hex"].as_str().unwrap();
            let bytes: Vec<_> = (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                .collect();
            let key = MailEncryptionKey::from_secret(&bytes)?;
            let packet = validate_packet(&input["packet"])?;
            println!(
                "{}",
                serde_json::to_string(&decrypt_packet(
                    &packet,
                    &card,
                    &key,
                    &card.event.actor,
                    now
                )?)?
            );
        }
        _ => return Err("expected seal or open".into()),
    }
    Ok(())
}
