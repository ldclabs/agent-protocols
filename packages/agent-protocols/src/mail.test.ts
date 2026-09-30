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
const keyFor = (card: m.MailboxCard) =>
  m.MailEncryptionKey.fromBytes(
    hex(
      card.event.payload.public_key === e.card.event.payload.public_key
        ? v.keys.recipient_secret_hex
        : v.keys.rotated_recipient_secret_hex,
    ),
  );
const keyring = () => {
  const k = new m.MailKeyring(owner);
  for (const name of ["card", "rotated_card", "reopened_card"])
    k.add(e[name], keyFor(e[name]));
  return k;
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
const codeOf = (fn: () => unknown): string | undefined => {
  try {
    fn();
    return undefined;
  } catch (err) {
    return (err as { code?: string }).code;
  }
};

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
    if (c.expected === "valid") m.validateMailDiscovery(c.value, service);
    else assert.throws(() => m.validateMailDiscovery(c.value, service));
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
    assert.equal(
      Buffer.from(new TextEncoder().encode(m.MAIL_PROTOCOL)).toString("hex"),
      c.info_hex,
    );
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
    assert.deepEqual(
      await m.openMailPacket(
        c.packet,
        card,
        keyFor(card),
        owner,
        now,
        c.packet_id,
      ),
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
        now,
        c.packet_id,
      ),
    );
  });
const pinCodes: Record<string, string> = {
  rollback: "stale_card",
  closed: "mailbox_unavailable",
  card_expired: "stale_card",
};
for (const name of ["card_cache", "persistent_card_pin"])
  test(`Mail lifecycle vectors: ${name}`, () => {
    let cache = new m.MailCardCache();
    for (const c of v.lifecycle[name]) {
      if (c.prune !== undefined) cache.prune(c.prune);
      else if (c.expected === "usable")
        cache.observe(e[c.card], owner, c.now ?? now);
      else
        assert.throws(() => cache.observe(e[c.card], owner, c.now ?? now), {
          code: pinCodes[c.expected],
        });
      cache = new m.MailCardCache(JSON.parse(JSON.stringify(cache.snapshot())));
    }
  });
test("Mail recipient lifecycle vectors survive restarts", async () => {
  let inbox = new m.MailInbox(keyring());
  for (const c of v.lifecycle.recipient) {
    assert.equal(
      (await inbox.accept(packet(c.packet), c.now)).kind,
      c.expected,
    );
    assert.equal(inbox.snapshot().accepted.length, c.items);
    inbox = new m.MailInbox(
      m.MailKeyring.restore(inbox.keyring.exportSnapshot()),
      JSON.parse(JSON.stringify(inbox.snapshot())),
    );
  }
  const h = v.lifecycle.historical_card;
  assert.equal(
    (await new m.MailInbox(keyring()).accept(packet(h.packet), h.now)).kind,
    h.expected,
  );
  const x = v.lifecycle.expired_new_letter;
  await assert.rejects(
    () => new m.MailInbox(keyring()).accept(packet(x.packet), x.now),
    { code: "packet_expired" },
  );
});
test("Mail reply vector binds participants, parent and thread", () => {
  const r = v.lifecycle.reply;
  m.validateMailReply(e[r.valid], e[r.parent]);
  assert.throws(() => m.validateMailReply(e[r.valid], e[r.wrong_parent]));
});
test("Mail relay lifecycle vectors run through real control writes", () => {
  let s = new m.MailRelayStore(service, { clock: () => now });
  for (const c of v.lifecycle.relay) {
    if (c.op === "delete")
      s.delete(mailbox, m.mailPacketId(packet(c.packet)), jwt());
    else {
      const run = () =>
        c.op === "publish"
          ? s.publish(e[c.card], c.now)
          : s.deliver(mailbox, packet(c.packet), c.now);
      if (c.accepted_at !== undefined)
        assert.equal(run().accepted_at, c.accepted_at);
      else assert.equal(codeOf(run), c.expected);
    }
    const page = s.list(mailbox, jwt());
    if (c.stored !== undefined) assert.equal(page.result.length, c.stored);
    if (c.seqs !== undefined)
      assert.deepEqual(
        page.result.map((r) => r.seq),
        c.seqs,
      );
    s = new m.MailRelayStore(service, {
      clock: () => now,
      snapshot: JSON.parse(JSON.stringify(s.snapshot())),
    });
  }
  for (const c of v.lifecycle.relay_registration)
    assert.equal(
      codeOf(() => new m.MailRelayStore(service).publish(e[c.card], now)),
      c.expected,
    );
});

test("Mail random production encryption roundtrips and concurrent acceptance is once", async () => {
  const [a, b] = await Promise.all([
    m.sealMailPacket(e.letter, e.card, now),
    m.sealMailPacket(e.letter, e.card, now),
  ]);
  assert.notEqual(a.enc, b.enc);
  const inbox = new m.MailInbox(keyring());
  const results = await Promise.all([
    inbox.accept(a, now),
    inbox.accept(b, now),
  ]);
  assert.deepEqual(results.map((x) => x.kind).sort(), [
    "accepted",
    "duplicate",
  ]);
  assert.deepEqual(results[0].letter, e.letter);
  inbox.prune(e.letter.event.payload.expires_at);
  assert.equal(inbox.has(e.letter.hash), false);
});
test("Mail sealing checks recipient, lifetime, size and card usability first", async () => {
  await assert.rejects(
    () => m.sealMailPacket(makeLetter({ to: sender.agentId() }), e.card, now),
    { code: "invalid_actor" },
  );
  await assert.rejects(
    () =>
      m.sealMailPacket(makeLetter({ expires_at: now + 1 }), e.card, now + 1),
    { code: "packet_expired" },
  );
  await assert.rejects(
    () =>
      m.sealMailPacket(
        makeLetter({ expires_at: now + 3 * 86400000 }),
        e.card,
        now,
      ),
    { code: "invalid_packet" },
  );
  await assert.rejects(
    () =>
      m.sealMailPacket(
        makeLetter({
          parts: [
            {
              media_type: "application/octet-stream",
              data: base64UrlEncode(new Uint8Array(5000)),
            },
          ],
        }),
        e.small_limit_card,
        now,
      ),
    { code: "payload_too_large" },
  );
  await assert.rejects(() => m.sealMailPacket(e.letter, e.closed_card, now), {
    code: "mailbox_unavailable",
  });
  const cache = new m.MailCardCache();
  const sealed = await cache.seal(e.letter, e.card, now);
  assert.deepEqual(await keyring().open(sealed, now), e.letter);
  cache.observe(e.rotated_card, owner, now);
  await assert.rejects(() => cache.seal(e.letter, e.card, now), {
    code: "stale_card",
  });
});
test("Mail keys are independent, keyring retains old cards and prunes by receive_until", async () => {
  const key = m.MailEncryptionKey.generate(),
    other = m.MailEncryptionKey.generate();
  assert.notEqual(key.publicKey(), other.publicKey());
  assert.throws(() => new m.MailKeyring(owner).add(e.card, key), {
    code: "invalid_private_key",
  });
  assert.throws(() => {
    key.destroy();
    key.exportSecret();
  });
  const k = keyring();
  assert.deepEqual(await k.open(packet("original"), now), e.letter);
  const restored = m.MailKeyring.restore(k.exportSnapshot());
  restored.prune(e.card.event.payload.receive_until);
  await assert.rejects(() => restored.open(packet("original"), now), {
    code: "invalid_packet",
  });
});
test("Mail local JSON and text parts remain strict", () => {
  for (const bad of [
    { x: undefined },
    { x: NaN },
    { x: Infinity },
    { x: BigInt(1) },
    { x: new Date() },
    { "\ud800": 1 },
  ])
    assert.throws(() => m.mailCanonicalBytes(bad));
  assert.throws(() => m.mailCanonicalBytes("\ud800"));
  assert.throws(() => m.mailTextPart("\udc00"));
  assert.equal(m.mailPartText(m.mailTextPart("Hello 世界")), "Hello 世界");
  const reply = signer.signEvent(
    m.mailMessageEvent(owner, now, 501, {
      to: sender.agentId(),
      expires_at: now + 1000,
      thread_id: m.newMailId(),
      in_reply_to: e.letter.hash,
      parts: [m.mailTextPart("reply")],
    }),
  );
  assert.throws(() => m.validateMailReply(reply, e.letter));
});
test("Mail relay publication is atomic, nonce-aware and idempotent", () => {
  const ns = new MemoryNonceStore(),
    s = new m.MailRelayStore(service, { nonceStore: ns, clock: () => now });
  assert.equal(s.publish(e.card).accepted_at, now);
  s.publish(e.rotated_card);
  assert.equal(
    codeOf(() => s.publish(e.card, now + 1)),
    "nonce_not_greater",
  );
  assert.equal(s.card(mailbox).envelope.hash, e.rotated_card.hash);
  assert.equal(
    codeOf(() =>
      s.publish(makeCard({ mailbox_id: m.newMailId() }, 999, now - 400000)),
    ),
    "timestamp_out_of_window",
  );
  assert.equal(ns.maxNonce(owner, now), 101);
  ns.checkAndUpdate(owner, 700, now, 600000);
  assert.equal(
    codeOf(() => s.publish(makeCard({ mailbox_id: m.newMailId() }, 699))),
    "nonce_not_greater",
  );
  assert.equal(
    codeOf(() => s.card("bad")),
    "invalid_request",
  );
});
test("Mail relay quotas, tombstones, owner authorization and pruning", () => {
  const s = new m.MailRelayStore(service, { clock: () => now, maxPackets: 1 });
  s.publish(e.card);
  const result = s.deliver(mailbox, packet("original"));
  assert.deepEqual(Object.keys(result).sort(), ["accepted_at", "packet_id"]);
  assert.equal(
    codeOf(() => s.deliver(mailbox, packet("reencrypted"))),
    "rate_limited",
  );
  assert.equal(
    codeOf(() => s.list(mailbox, "bad")),
    "invalid_token",
  );
  assert.equal(
    codeOf(() => s.list(mailbox, jwt(sender))),
    "permission_denied",
  );
  assert.equal(
    codeOf(() => s.list(m.newMailId(), jwt())),
    "mailbox_unavailable",
  );
  assert.equal(
    codeOf(() => s.delete(mailbox, result.packet_id, jwt(sender))),
    "permission_denied",
  );
  s.delete(mailbox, result.packet_id, jwt());
  s.delete(mailbox, result.packet_id, jwt());
  assert.deepEqual(s.deliver(mailbox, packet("original"), now + 1), result);
  assert.equal(s.list(mailbox, jwt()).result.length, 0);
  assert.equal(s.deliver(mailbox, packet("reencrypted")).accepted_at, now);
  assert.equal(
    codeOf(() => s.deliver(m.newMailId(), packet("original"))),
    "invalid_packet",
  );
  const expires = e.letter.event.payload.expires_at;
  s.prune(expires);
  assert.equal(
    codeOf(() => s.deliver(mailbox, packet("original"), expires)),
    "stale_card",
  );
});
test("Mail pagination uses a plain seq cursor and resumes past deletions", () => {
  const s = new m.MailRelayStore(service, { clock: () => now });
  s.publish(e.card);
  const a = s.deliver(mailbox, packet("original")),
    b = s.deliver(mailbox, packet("reencrypted"));
  const token = jwt();
  const page = s.list(mailbox, token, { limit: 1 });
  assert.equal(page.result[0].packet_id, a.packet_id);
  assert.equal(page.next_cursor, "1");
  s.delete(mailbox, a.packet_id, token);
  const next = s.list(mailbox, token, { cursor: page.next_cursor });
  assert.equal(next.result[0].packet_id, b.packet_id);
  assert.equal(next.next_cursor, undefined);
  for (const cursor of ["", "-1", "01", "x"])
    assert.equal(
      codeOf(() => s.list(mailbox, token, { cursor })),
      "invalid_request",
    );
  for (const limit of [0, 1001, 1.5])
    assert.equal(
      codeOf(() => s.list(mailbox, token, { limit })),
      "invalid_request",
    );
});
test("Mail owner JWT verification is strict about claims JSON", () => {
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
  m.validateMailOwnerJwt(sign(JSON.stringify(base)), service, owner, now);
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
