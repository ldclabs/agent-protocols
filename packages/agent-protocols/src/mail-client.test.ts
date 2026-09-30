import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { AgentSigner } from "./identity.js";
import { HttpResponseError } from "./http-client.js";
import { MailClient } from "./mail-client.js";
import { mailPacketId, type MailDiscovery } from "./mail.js";
const v = JSON.parse(
  readFileSync(
    new URL(
      "../../../docs/protocols/agent-mail/1.0.vectors.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const service = "https://relay.example",
  now = v.now,
  card = v.envelopes.card,
  mailbox = card.event.payload.mailbox_id,
  owner = card.event.actor,
  packet = v.encryptions.original.packet;
const signer = AgentSigner.fromSeed(
  Buffer.from(v.keys.recipient_seed_hex, "hex"),
);
const jwt = () =>
  signer.signRequestJwt({
    iss: owner,
    sub: owner,
    aud: service,
    iat: now / 1000,
    exp: now / 1000 + 300,
  });
const record = {
  packet_id: mailPacketId(packet),
  packet,
  accepted_at: now,
  seq: 1,
};
const accepted = { envelope: card, accepted_at: now };
const delivery = { packet_id: record.packet_id, accepted_at: now, seq: 1 };
const response = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
const client = (fn: any, extra: any = {}) =>
  new MailClient(service, { fetch: fn, clock: () => now, ...extra });
test("Mail HTTP respects discovery base, anonymously delivers and owner-authenticates reads/deletes", async () => {
  const calls: { url: string; init: RequestInit }[] = [];
  const base = service + "/custom/mailboxes";
  const fetch = async (url: any, init: RequestInit) => {
    calls.push({ url: String(url), init });
    if (String(url).endsWith("/.well-known/agent-mail"))
      return response({
        protocol: "agent-mail/1.0",
        service,
        endpoints: { mailboxes: base },
      });
    if (init.method === "DELETE") return new Response(null, { status: 204 });
    if (init.method === "POST")
      return response(
        String(url) === base ? accepted : delivery,
        String(url) === base ? 200 : 202,
      );
    if (String(url).endsWith("/card")) return response(accepted);
    return response({ result: [record], extension: true });
  };
  const c = await MailClient.discover(
    service,
    { fetch, clock: () => now },
    card,
  );
  await c.card(mailbox, owner);
  await c.publish(card);
  await c.list(mailbox, owner, jwt());
  await c.deliver(packet, card);
  await c.delete(mailbox, record.packet_id, owner, jwt());
  assert.equal(calls.length, 6);
  for (const { init } of calls) {
    assert.equal(init.redirect, "error");
    assert.equal(init.credentials, "omit");
    assert.equal(init.referrerPolicy, "no-referrer");
  }
  const post = calls[4];
  assert.equal(post.url, `${base}/${mailbox}/packets`);
  assert.equal(new Headers(post.init.headers).has("authorization"), false);
  assert.equal(new Headers(post.init.headers).has("cookie"), false);
  assert.deepEqual(JSON.parse(String(post.init.body)), packet);
  assert.equal(new Headers(calls[2].init.headers).has("authorization"), false);
  for (const i of [3, 5])
    assert.equal(
      new Headers(calls[i].init.headers).get("authorization"),
      `Bearer ${jwt()}`,
    );
});
test("Mail HTTP rejects all discovery vectors with unsafe endpoints", async () => {
  for (const c of v.discovery_cases) {
    const api = client(async () => response(c.value));
    if (c.expected === "valid") await api.protocol(card);
    else await assert.rejects(() => api.protocol(card));
  }
});
test("Mail HTTP does not follow or trust redirects, even same-origin redirects", async () => {
  for (const mode of ["status", "redirected", "origin", "path"]) {
    const r = response(accepted, mode === "status" ? 302 : 200);
    if (mode === "redirected")
      Object.defineProperty(r, "redirected", { value: true });
    if (mode === "origin")
      Object.defineProperty(r, "url", { value: "https://evil.example/card" });
    if (mode === "path")
      Object.defineProperty(r, "url", { value: service + "/unexpected" });
    await assert.rejects(() => client(async () => r).card(mailbox, owner), {
      code: "invalid_response",
    });
  }
});
test("Mail HTTP rejects malformed signed cards and unexpected response bindings", async () => {
  const changed = structuredClone(accepted);
  changed.envelope.event.payload.routes = ["https://evil.example"];
  for (const x of [
    changed,
    { ...accepted, accepted_at: -1 },
    { ...accepted, extra: true },
    { ...accepted, envelope: v.envelopes.letter },
  ])
    await assert.rejects(() =>
      client(async () => response(x)).card(mailbox, owner),
    );
  await assert.rejects(() =>
    client(async () => response(accepted)).card(
      mailbox,
      v.keys.sender_agent_id,
    ),
  );
  await assert.rejects(() =>
    client(async () =>
      response({ ...delivery, packet_id: "A".repeat(43) }, 202),
    ).deliver(packet, card),
  );
  await assert.rejects(
    () => client(async () => response(delivery, 200)).deliver(packet, card),
    { code: "invalid_response" },
  );
  const latest = { envelope: v.envelopes.rotated_card, accepted_at: now };
  await assert.rejects(
    () => client(async () => response(latest)).publish(card),
    { code: "invalid_response" },
  );
});
test("Mail HTTP strict UTF-8/JSON, response media/status/size guards", async () => {
  const cases = [
    () =>
      new Response('{"envelope":0,"envelope":1}', {
        headers: { "content-type": "application/json" },
      }),
    () =>
      new Response(new Uint8Array([255]), {
        headers: { "content-type": "application/json" },
      }),
    () => new Response(JSON.stringify(accepted)),
    () => response(accepted, 201),
    () =>
      new Response(JSON.stringify(accepted), {
        headers: {
          "content-type": "application/json",
          "content-length": "99999",
        },
      }),
  ];
  for (const make of cases)
    await assert.rejects(() =>
      client(async () => make(), { maxResponseBytes: 5000 }).card(
        mailbox,
        owner,
      ),
    );
  await assert.rejects(
    () =>
      client(async () => response(accepted), { maxResponseBytes: 10 }).card(
        mailbox,
        owner,
      ),
    { code: "invalid_response" },
  );
});
test("Mail HTTP rejects bad owners/limits/URLs before network and honors local network policy", async () => {
  let calls = 0;
  const api = client(async () => {
    calls++;
    return response({});
  });
  await assert.rejects(() => api.list(mailbox, v.keys.sender_agent_id, jwt()), {
    code: "permission_denied",
  });
  await assert.rejects(
    () => api.delete(mailbox, record.packet_id, owner, "bad"),
    { code: "invalid_token" },
  );
  for (const limit of [0, -1, 1001, 1.5])
    await assert.rejects(() => api.list(mailbox, owner, jwt(), { limit }));
  await assert.rejects(() => api.deliver(packet, v.envelopes.rotated_card));
  assert.equal(calls, 0);
  await assert.rejects(
    () =>
      client(
        async () => {
          calls++;
          return response({});
        },
        { allowUrl: () => false },
      ).protocol(),
    { code: "permission_denied" },
  );
  assert.equal(calls, 0);
  for (const url of [
    "http://relay.example",
    "https://relay.example/",
    "https://user@relay.example",
  ])
    assert.throws(() => new MailClient(url));
});
test("Mail HTTP validates ordered lists, packet hashes and mailbox identity", async () => {
  const corrupted = structuredClone(record);
  corrupted.packet.ciphertext = "bad";
  for (const value of [
    { result: [record, record] },
    { result: [{ ...record, packet_id: "A".repeat(43) }] },
    { result: [corrupted] },
    { result: [], next_cursor: "x" },
    { result: [record], next_cursor: "" },
  ])
    await assert.rejects(() =>
      client(async () => response(value)).list(mailbox, owner, jwt()),
    );
  await assert.rejects(() =>
    client(async () => response({ result: [record, record] })).list(
      mailbox,
      owner,
      jwt(),
      { limit: 1 },
    ),
  );
});
test("Mail HTTP pages reject cursor cycles and cross-page sequence rewinds", async () => {
  const api = client(async () =>
    response({ result: [record], next_cursor: "same" }),
  );
  await assert.rejects(
    async () => {
      for await (const _ of api.pages(mailbox, owner, jwt, 1)) {
      }
    },
    { code: "invalid_response" },
  );
  let n = 0;
  const good = client(async () =>
    response(
      ++n === 1
        ? { result: [record], next_cursor: "next" }
        : {
            result: [
              {
                ...record,
                packet: v.encryptions.reencrypted.packet,
                packet_id: mailPacketId(v.encryptions.reencrypted.packet),
                seq: 2,
              },
            ],
          },
    ),
  );
  const rows = [];
  for await (const p of good.pages(mailbox, owner, jwt, 1))
    rows.push(...p.result);
  assert.equal(rows.length, 2);
});
test("Mail HTTP propagates structured server errors and nonce header", async () => {
  const api = client(
    async () =>
      new Response(
        JSON.stringify({
          error: {
            code: "nonce_not_greater",
            message: "advance",
            data: { max_nonce: 123 },
          },
        }),
        {
          status: 409,
          headers: {
            "content-type": "application/json",
            "Max-Seen-Nonce": "123",
          },
        },
      ),
  );
  await assert.rejects(
    () => api.publish(card),
    (e: any) => e instanceof HttpResponseError && e.status === 409,
  );
});

test("Mail HTTP rejects relay claims of first acceptance at/after expiration", async () => {
  const expiredResult = { ...delivery, accepted_at: packet.header.expires_at };
  await assert.rejects(
    () =>
      client(async () => response(expiredResult, 202)).deliver(packet, card),
    { code: "invalid_response" },
  );
  await assert.rejects(
    () =>
      client(async () =>
        response({
          result: [{ ...record, accepted_at: packet.header.expires_at }],
        }),
      ).list(mailbox, owner, jwt()),
    { code: "invalid_response" },
  );
});

test("Mail HTTP pins disabled cards before returning and rejects later rollback", async () => {
  let calls = 0;
  const api = client(async () =>
    response({
      envelope: ++calls === 1 ? v.envelopes.disabled_card : card,
      accepted_at: now,
    }),
  );
  assert.equal(
    (await api.card(mailbox, owner)).envelope.event.payload.enabled,
    false,
  );
  assert.equal(
    api.cardCache.snapshot().pins[0].hash,
    v.envelopes.disabled_card.hash,
  );
  await assert.rejects(() => api.card(mailbox, owner), { code: "stale_card" });
});
