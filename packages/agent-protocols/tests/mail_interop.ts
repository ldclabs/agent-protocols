/** Cross-language harness: the production API always chooses fresh HPKE randomness. */
import { AgentSigner } from "../src/identity.js";
import { readFileSync } from "node:fs";
import {
  MailEncryptionKey,
  sealMailPacket,
  openMailPacket,
} from "../src/mail.js";
const v = JSON.parse(
  readFileSync(
    new URL(
      "../../../docs/protocols/agent-mail/1.0.vectors.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const req = JSON.parse(readFileSync(0, "utf8"));
if (req.op === "seal")
  console.log(
    JSON.stringify(
      await sealMailPacket(
        v.messages.letter,
        v.envelopes.card,
        AgentSigner.fromSeed(Buffer.from(v.keys.sender_seed_hex, "hex")),
        req.nonce ?? 700,
        v.now,
      ),
    ),
  );
else if (req.op === "open")
  console.log(
    JSON.stringify(
      await openMailPacket(
        req.packet,
        v.envelopes.card,
        MailEncryptionKey.fromBytes(
          Buffer.from(v.keys.recipient_secret_hex, "hex"),
        ),
        v.keys.recipient_agent_id,
        v.now,
      ),
    ),
  );
else throw new Error("unknown operation");
