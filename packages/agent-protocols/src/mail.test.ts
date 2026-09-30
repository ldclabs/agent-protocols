import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { sha3_256 } from "@noble/hashes/sha3.js";
import nacl from "tweetnacl";
import * as m from "./mail.js";
import {
  AgentSigner,
  MemoryNonceStore,
  parseStrictJson,
  canonicalEventBytes,
  createEvent,
} from "./identity.js";
import { base64UrlEncode } from "./encoding.js";
const v = JSON.parse(
  readFileSync(
    new URL(
      "../../../docs/protocols/agent-mail/1.0.vectors.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const schema = JSON.parse(
  readFileSync(
    new URL(
      "../../../docs/protocols/agent-mail/1.0.schema.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const e = v.envelopes,
  now = v.now,
  owner = v.keys.recipient_agent_id,
  service = "https://relay.example",
  mailbox = e.card.event.payload.mailbox_id;
const hex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
const secret = () =>
  m.MailEncryptionKey.fromBytes(hex(v.keys.recipient_secret_hex));
const recipient = () => {
  const k = new m.MailKeyring(owner);
  k.add(e.card, secret());
  k.add(
    e.rotated_card,
    m.MailEncryptionKey.fromBytes(hex(v.keys.rotated_recipient_secret_hex)),
  );
  return new m.MailRecipient(k);
};
const signer = AgentSigner.fromSeed(hex(v.keys.recipient_seed_hex));
const sender = AgentSigner.fromSeed(hex(v.keys.sender_seed_hex));
const packet = (name: string) => structuredClone(v.encryptions[name].packet);
const makeCard = (changes: any = {}, nonce = 400, at = now) =>
  signer.signEvent(
    m.mailboxPublishEvent(owner, at, nonce, {
      ...e.card.event.payload,
      ...changes,
    }),
  );
const makeLetter = (changes: any = {}, nonce = 500) =>
  sender.signEvent(
    m.mailMessageEvent(sender.agentId(), now, nonce, {
      ...e.letter.event.payload,
      ...changes,
    }),
  );
function jwt(who = signer, aud = service, at = now) {
  return who.signRequestJwt({
    iss: who.agentId(),
    sub: who.agentId(),
    aud,
    iat: Math.floor(at / 1000),
    exp: Math.floor(at / 1000) + 300,
  });
}
// Provider-level fixed material is confined to tests. Production sealMailPacket exposes no deterministic RNG override.
async function kat(
  pk: string,
  sk: string,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
) {
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  });
  const ek = hex(sk),
    ekm = {
      privateKey: await suite.kem.deserializePrivateKey(ek),
      publicKey: await suite.kem.deserializePublicKey(nacl.scalarMult.base(ek)),
    };
  const ctx = await suite.createSenderContext({
    recipientPublicKey: await suite.kem.deserializePublicKey(hex(pk)),
    info,
    ekm,
  });
  return {
    enc: new Uint8Array(ctx.enc),
    ct: new Uint8Array(await ctx.seal(plaintext, aad)),
  };
}

test("Mail bundled schema matches normative schema", () =>
  assert.deepEqual(m.MAIL_SCHEMA, schema));
for (const [name, c] of Object.entries(v.signing) as [string, any][])
  test(`Mail signing vector: ${name}`, () => {
    assert.equal(
      new TextDecoder().decode(canonicalEventBytes(e[name].event)),
      c.event_jcs,
    );
    assert.equal(
      new TextDecoder().decode(m.mailCanonicalBytes(e[name])),
      c.envelope_jcs,
    );
    assert.deepEqual(
      AgentSigner.fromSeed(hex(c.seed_hex)).signEvent(e[name].event),
      e[name],
    );
    if (e[name].event.type === "mailbox.publish")
      m.validateMailboxCard(e[name]);
    else m.validateMailLetter(e[name]);
  });
for (const c of v.schema_cases)
  test(`Mail schema vector: ${c.name}`, () => {
    if (c.valid) m.validateMailSchema(c.value, c.definition);
    else assert.throws(() => m.validateMailSchema(c.value, c.definition));
  });
for (const raw of v.strict_json_rejections)
  test(`Mail strict JSON vector: ${raw}`, () =>
    assert.throws(() => parseStrictJson(raw)));
for (const c of v.sender_card_cases)
  test(`Mail sender card vector: ${c.name}`, () =>
    assert.throws(() => m.validateMailSenderCard(c.card, owner, c.now)));
for (const c of v.discovery_cases)
  test(`Mail discovery vector: ${c.name}`, () => {
    if (c.expected === "valid")
      m.validateMailDiscovery(c.value, service, e.card);
    else assert.throws(() => m.validateMailDiscovery(c.value, service, e.card));
  });
for (const c of v.owner_jwt_cases)
  test(`Mail owner JWT vector: ${c.name}`, () => {
    if (c.expected === "valid")
      m.validateMailOwnerJwt(c.token, service, owner, now);
    else
      assert.throws(
        () => m.validateMailOwnerJwt(c.token, service, owner, now),
        { code: c.expected },
      );
  });
for (const c of v.framing_boundaries)
  test(`Mail framing boundary: ${c.json_byte_length}`, () => {
    const f = m.frameMailBytes(new Uint8Array(c.json_byte_length).fill(120));
    assert.equal(f.length, c.frame_byte_length);
    assert.equal(
      Buffer.from(f.subarray(0, 4)).toString("hex"),
      c.length_prefix_hex,
    );
    assert.equal(base64UrlEncode(sha3_256(f)), c.plaintext_sha3_256);
  });
test("Mail RFC9180 official known answer uses maintained HPKE suite", async () => {
  const k = v.rfc9180_known_answer;
  const out = await kat(k.pkRm, k.skEm, hex(k.info), hex(k.aad), hex(k.pt));
  assert.equal(Buffer.from(out.enc).toString("hex"), k.pkEm);
  assert.equal(Buffer.from(out.ct).toString("hex"), k.ct);
});
for (const [name, c] of Object.entries(v.encryptions) as [string, any][])
  test(`Mail encryption vector: ${name}`, async () => {
    const card = e[c.card],
      letter = e[c.letter];
    const frame = m.frameMailBytes(m.mailCanonicalBytes(letter));
    assert.equal(base64UrlEncode(frame), c.plaintext_b64);
    const out = await kat(
      Buffer.from(m.decodeMailBytes(card.event.payload.public_key)).toString(
        "hex",
      ),
      c.ephemeral_secret_hex,
      hex(c.info_hex),
      new TextEncoder().encode(c.aad_jcs),
      frame,
    );
    assert.deepEqual(
      {
        header: c.packet.header,
        enc: base64UrlEncode(out.enc),
        ciphertext: base64UrlEncode(out.ct),
      },
      c.packet,
    );
    assert.equal(m.mailPacketId(c.packet), c.packet_id);
    assert.equal(
      new TextDecoder().decode(m.mailCanonicalBytes(c.packet)),
      c.packet_jcs,
    );
    const key = m.MailEncryptionKey.fromBytes(
      hex(
        c.card === "rotated_card"
          ? v.keys.rotated_recipient_secret_hex
          : v.keys.recipient_secret_hex,
      ),
    );
    assert.deepEqual(
      await m.openMailPacket(c.packet, card, key, owner, now, c.packet_id),
      letter,
    );
  });
for (const c of v.recipient_rejections)
  test(`Mail recipient rejection: ${c.name}`, async () => {
    await assert.rejects(() =>
      m.openMailPacket(
        c.packet,
        e[c.card ?? "card"],
        m.MailEncryptionKey.fromBytes(
          hex(c.secret_hex ?? v.keys.recipient_secret_hex),
        ),
        c.owner ?? owner,
        c.now ?? now,
        c.packet_id,
      ),
    );
  });
for (const name of ["card_cache", "persistent_card_pin"])
  test(`Mail lifecycle vectors: ${name}`, () => {
    let cache = new m.MailCardCache();
    for (const c of v.lifecycle[name]) {
      if (c.expected === "usable")
        cache.observe(e[c.card], owner, c.now ?? now);
      else {
        const codes: Record<string, string> = {
          equivocation: "mailbox_conflict",
          rollback: "stale_card",
          disabled: "mailbox_unavailable",
          key_reuse: "mailbox_conflict",
        };
        assert.throws(() => cache.observe(e[c.card], owner, c.now ?? now), {
          code: codes[c.expected],
        });
      }
      cache = new m.MailCardCache(cache.snapshot());
    }
  });
test("Mail recipient lifecycle vectors include rotated duplicate, lower nonce and expired duplicate", async () => {
  let r = recipient();
  for (const c of v.lifecycle.recipient) {
    assert.equal((await r.accept(packet(c.packet), c.now)).kind, c.expected);
    assert.equal(r.letters().length, c.items);
    r = new m.MailRecipient(
      m.MailKeyring.restore(r.keyring.exportSnapshot()),
      r.snapshot(),
    );
  }
});
test("Mail historical card and expired-new-letter vectors", async () => {
  const c = v.lifecycle.historical_card;
  assert.equal(
    (await recipient().accept(packet(c.packet), c.now)).kind,
    c.expected,
  );
  const bad = v.lifecycle.expired_new_letter;
  await assert.rejects(() => recipient().accept(packet(bad.packet), bad.now), {
    code: "packet_expired",
  });
});
test("Mail receipt vector binds both participants and exact outgoing message", () => {
  m.validateMailReceipt(e.receipt, e.letter);
  assert.throws(() => m.validateMailReceipt(e.receipt, e.lower_nonce_letter));
});

test("Mail random production encryption roundtrips and concurrent acceptance is once", async () => {
  const [a, b] = await Promise.all([
    m.sealMailPacket(e.letter, e.card, now),
    m.sealMailPacket(e.letter, e.card, now),
  ]);
  assert.notEqual(a.enc, b.enc);
  assert.notEqual(a.ciphertext, b.ciphertext);
  const r = recipient();
  const results = await Promise.all([r.accept(a, now), r.accept(b, now)]);
  assert.deepEqual(results.map((x) => x.kind).sort(), [
    "accepted",
    "duplicate",
  ]);
  assert.equal(r.letters().length, 1);
  results[0].letter.event.payload.to = "bad";
  assert.equal(r.letters()[0].event.payload.to, owner);
});
test("Mail random independent keys, sender binding, keyring retention and key erasure", async () => {
  const key = m.MailEncryptionKey.generate(),
    other = m.MailEncryptionKey.generate();
  assert.notEqual(key.publicKey(), other.publicKey());
  const raw = key.exportSecret();
  raw.fill(0);
  assert.notEqual(
    key.publicKey(),
    m.MailEncryptionKey.fromBytes(raw).publicKey(),
  );
  assert.throws(() => new m.MailKeyring(owner).add(e.card, key));
  assert.throws(() => {
    key.destroy();
    key.exportSecret();
  });
  await assert.rejects(() =>
    m.sealMailPacket(makeLetter({ to: sender.agentId() }), e.card, now),
  );
  await assert.rejects(() =>
    m.sealMailPacket(makeLetter({ expires_at: now }), e.card, now),
  );
  const k = new m.MailKeyring(owner);
  k.add(e.card, secret());
  const sn = k.exportSnapshot();
  sn.entries[0].card.event.payload.enabled = false;
  assert.deepEqual(await k.open(packet("original"), now), e.letter);
  k.prune(e.card.event.payload.receive_until);
  await assert.rejects(() => k.open(packet("original"), now));
});
test("Mail pin refuses changed card while async encryption is in flight", async () => {
  const cache = new m.MailCardCache();
  const seal = cache.seal(e.letter, e.card, now);
  assert.throws(() => cache.observe(e.disabled_card, owner, now));
  await assert.rejects(() => seal, { code: "stale_card" });
});
test("Mail local JSON and signed reply bindings remain strict", () => {
  for (const bad of [
    { x: undefined },
    { x: NaN },
    { x: Infinity },
    { x: BigInt(1) },
    { x: new Date() },
  ])
    assert.throws(() => m.mailCanonicalBytes(bad));
  assert.throws(() => m.mailCanonicalBytes("\ud800"));
  const reply = signer.signEvent(
    m.mailMessageEvent(owner, now, 501, {
      to: sender.agentId(),
      expires_at: now + 1000,
      thread_id: e.letter.event.payload.thread_id,
      in_reply_to: e.letter.hash,
      parts: [m.mailTextPart("reply")],
    }),
  );
  m.validateMailReply(reply, e.letter);
  assert.throws(() =>
    m.validateMailReply(
      {
        ...reply,
        event: {
          ...reply.event,
          payload: { ...reply.event.payload, thread_id: m.newMailId() },
        },
      },
      e.letter,
    ),
  );
  assert.equal(m.mailPartText(m.mailTextPart("Hello 世界")), "Hello 世界");
});
test("Mail receiving receipt requires remembered outgoing original", async () => {
  const senderKey = m.MailEncryptionKey.generate();
  const senderCard = sender.signEvent(
    m.mailboxPublishEvent(sender.agentId(), now, 600, {
      ...e.card.event.payload,
      mailbox_id: m.newMailId(),
      key_id: m.newMailId(),
      public_key: senderKey.publicKey(),
    }),
  );
  const k = new m.MailKeyring(sender.agentId());
  k.add(senderCard, senderKey);
  const r = new m.MailRecipient(k);
  const p = await m.sealMailPacket(e.receipt, senderCard, now);
  await assert.rejects(() => r.accept(p, now));
  r.rememberOutgoing(e.letter);
  assert.equal((await r.accept(p, now)).kind, "accepted");
});
test("Mail relay live card validation is atomic, global-nonce-aware, and idempotent", () => {
  const ns = new MemoryNonceStore(),
    s = new m.MailRelayStore(service, { nonceStore: ns, clock: () => now });
  const first = s.publish(e.card);
  assert.equal(first.accepted_at, now);
  s.publish(e.rotated_card);
  assert.equal(s.publish(e.card, now + 999999999).accepted_at, now);
  assert.equal(s.card(mailbox).envelope.hash, e.rotated_card.hash);
  const before = s.snapshot();
  assert.throws(() => s.publish(e.key_reuse_card));
  assert.deepEqual(s.snapshot(), before);
  assert.equal(ns.maxNonce(owner, now), 101);
  const secondId = m.newMailId();
  assert.throws(() => s.publish(makeCard({ mailbox_id: secondId }, 101)));
  assert.throws(() =>
    s.publish(makeCard({ routes: ["https://other.example"] }, 999)),
  );
  assert.equal(ns.maxNonce(owner, now), 101);
  ns.checkAndUpdate(owner, 700, now, 600000);
  assert.throws(() => s.publish(makeCard({ mailbox_id: secondId }, 699)), {
    code: "nonce_not_greater",
  });
  const hijack = sender.signEvent(
    createEvent(
      "agent-mail/1.0",
      "mailbox.publish",
      sender.agentId(),
      now,
      800,
      e.card.event.payload,
    ),
  );
  assert.throws(() => s.publish(hijack), { code: "mailbox_conflict" });
});
test("Mail relay packet lifecycle, disabled retry, rotation, quotas, snapshot and authorization", async () => {
  let s = new m.MailRelayStore(service, { clock: () => now, maxPackets: 1 });
  s.publish(e.card);
  const result = s.deliver(mailbox, packet("original"));
  assert.equal(result.seq, 1);
  const token = jwt();
  assert.equal(s.list(mailbox, token).result.length, 1);
  assert.throws(() => s.list(mailbox, jwt(sender)), {
    code: "permission_denied",
  });
  assert.throws(() => s.delete(mailbox, result.packet_id, jwt(sender)), {
    code: "permission_denied",
  });
  assert.equal(s.list(mailbox, token).result.length, 1);
  assert.throws(() => s.deliver(mailbox, packet("reencrypted")), {
    code: "quota_exceeded",
  });
  s.delete(mailbox, result.packet_id, token);
  s.publish(e.disabled_card);
  assert.deepEqual(s.deliver(mailbox, packet("original"), now + 1), result);
  assert.equal(s.list(mailbox, token).result.length, 0);
  assert.throws(() => s.deliver(mailbox, packet("reencrypted")), {
    code: "mailbox_unavailable",
  });
  const enabled = makeCard(e.rotated_card.event.payload, 103);
  s.publish(enabled);
  const p = await m.sealMailPacket(e.letter, enabled, now);
  assert.equal(s.deliver(mailbox, p).seq, 2);
  assert.deepEqual(s.deliver(mailbox, packet("original"), now + 1), result);
  const snapshot = s.snapshot();
  snapshot.mailboxes[0].packets[0].packet.enc = "bad";
  assert.equal(s.list(mailbox, token).result.length, 1);
  s = new m.MailRelayStore(service, {
    snapshot: s.snapshot(),
    clock: () => now,
  });
  assert.deepEqual(s.deliver(mailbox, packet("original")), result);
  assert.equal(s.list(mailbox, token).result.length, 1);
  assert.throws(() => s.publish(e.rotated_card), { code: "nonce_not_greater" });
});
test("Mail relay normative lifecycle runs every step through real control writes", () => {
  const s = new m.MailRelayStore(service, { clock: () => now });
  s.publish(e.card);
  for (const c of v.lifecycle.relay) {
    if (c.op === "set_current") {
      s.publish(e[c.card]);
      continue;
    }
    if (c.op === "delete") {
      s.delete(mailbox, m.mailPacketId(packet(c.packet)), jwt());
    } else if (c.expected === "accepted" || c.expected === "idempotent") {
      const r = s.deliver(mailbox, packet(c.packet), c.now);
      assert.equal(r.seq, c.seq);
      assert.equal(r.accepted_at, c.accepted_at);
    } else
      assert.throws(() => s.deliver(mailbox, packet(c.packet), c.now), {
        code: c.expected === "disabled" ? "mailbox_unavailable" : c.expected,
      });
    assert.equal(s.list(mailbox, jwt()).result.length, c.stored);
  }
});
test("Mail pagination resumes past deletions and binds owner/mailbox/cursor", async () => {
  const s = new m.MailRelayStore(service, { clock: () => now });
  s.publish(e.card);
  const a = s.deliver(mailbox, packet("original")),
    b = s.deliver(mailbox, packet("reencrypted"));
  const token = jwt();
  const page = s.list(mailbox, token, { limit: 1 });
  assert.equal(page.result[0].packet_id, a.packet_id);
  s.delete(mailbox, a.packet_id, token);
  const restored = new m.MailRelayStore(service, {
    clock: () => now,
    snapshot: s.snapshot(),
  });
  assert.equal(
    restored.list(mailbox, token, { cursor: page.next_cursor }).result[0]
      .packet_id,
    b.packet_id,
  );
  const other = makeCard({ mailbox_id: m.newMailId() }, 401);
  restored.publish(other);
  assert.throws(
    () =>
      restored.list(other.event.payload.mailbox_id, token, {
        cursor: page.next_cursor,
      }),
    { code: "invalid_cursor" },
  );
  assert.throws(() => restored.list(mailbox, token, { limit: 0 }));
  assert.throws(() => restored.list(mailbox, token, { limit: 1001 }));
  restored.prune(e.letter.event.payload.expires_at);
  assert.throws(() =>
    restored.deliver(
      mailbox,
      packet("original"),
      e.letter.event.payload.expires_at,
    ),
  );
});
test("Mail owner JWT rejects duplicate JSON, string times and exact expiration", () => {
  const sign = (claimsText: string) => {
    const h = base64UrlEncode(
        new TextEncoder().encode(
          JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: owner }),
        ),
      ),
      p = base64UrlEncode(new TextEncoder().encode(claimsText));
    const key = nacl.sign.keyPair.fromSeed(hex(v.keys.recipient_seed_hex));
    return `${h}.${p}.${base64UrlEncode(nacl.sign.detached(new TextEncoder().encode(`${h}.${p}`), key.secretKey))}`;
  };
  const base = {
    iss: owner,
    sub: owner,
    aud: service,
    iat: now / 1000,
    exp: now / 1000 + 100,
  };
  for (const raw of [
    JSON.stringify({ ...base, iat: String(base.iat) }),
    JSON.stringify({ ...base, exp: base.iat }),
    JSON.stringify(base).replace('"exp":', `"iat":${base.iat},"exp":`),
  ])
    assert.throws(
      () => m.validateMailOwnerJwt(sign(raw), service, owner, now),
      { code: "invalid_token" },
    );
});

test("Mail relay restore requires the externally shared nonce store", () => {
  const nonces = new MemoryNonceStore();
  const relay = new m.MailRelayStore(service, {
    clock: () => now,
    nonceStore: nonces,
  });
  relay.publish(e.card);
  const snapshot = relay.snapshot();
  assert.throws(() => new m.MailRelayStore(service, { snapshot }), {
    code: "invalid_request",
  });
  nonces.checkAndUpdate(owner, 999, now, 600000);
  const restored = new m.MailRelayStore(service, {
    snapshot,
    nonceStore: nonces,
    clock: () => now,
  });
  assert.throws(
    () => restored.publish(makeCard({ mailbox_id: m.newMailId() }, 998)),
    { code: "nonce_not_greater" },
  );
});
