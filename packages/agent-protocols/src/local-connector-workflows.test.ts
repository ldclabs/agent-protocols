import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { AgentSigner, type Envelope } from "./identity.js";
import {
  materializeProfile,
  type ProfileUpdatePayload,
  profileUpdateEvent,
} from "./profile.js";
import {
  buildServerRecord,
  discourseEvent,
  redactServerRecord,
  roomCreateEvent,
  type ServerRecord,
} from "./discourse.js";
import * as delegation from "./delegation.js";
import { MailEncryptionKey, mailboxPublishEvent, newMailId } from "./mail.js";
import {
  LocalConnector,
  standardToolDefinitions,
  validateToolInput,
} from "./local-connector.js";
import { CONNECTOR_CATALOG } from "./local-connector/catalog-data.js";

const HOST = "https://workflow.example.test";
const alice = AgentSigner.fromSeed(new Uint8Array(32).fill(11));
const bob = AgentSigner.fromSeed(new Uint8Array(32).fill(12));
const json = (value: unknown, status = 200) => Response.json(value, { status });
type Json = Record<string, any>;
const call = async (
  c: LocalConnector,
  tool: string,
  input: unknown = {},
): Promise<Json> =>
  JSON.parse(
    JSON.stringify(await c.callTool(`agent_protocols_${tool}`, input)),
  ) as Json;
function connector(fetchImpl: typeof fetch) {
  const c = new LocalConnector(alice, { fetchImpl });
  c.addHost({ host: HOST, allowed: true, profile_service: HOST });
  return c;
}

test("normative catalog, bundled schemas and shared input vectors remain equivalent", () => {
  const source = JSON.parse(
    readFileSync(
      new URL(
        "../../../docs/mcp/local-connector/1.0.tools.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  assert.deepEqual(CONNECTOR_CATALOG.tools, source);
  for (const [protocol, schema] of Object.entries(CONNECTOR_CATALOG.schemas))
    assert.deepEqual(
      schema,
      JSON.parse(
        readFileSync(
          new URL(
            `../../../docs/protocols/${protocol.split("/")[0]}/1.0.schema.json`,
            import.meta.url,
          ),
          "utf8",
        ),
      ),
    );
  const vectors = JSON.parse(
    readFileSync(
      new URL(
        "../../../docs/mcp/local-connector/1.0.vectors.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  for (const v of vectors.cases) {
    if (v.valid)
      assert.doesNotThrow(() => validateToolInput(v.tool, v.input), v.name);
    else
      assert.throws(
        () => validateToolInput(v.tool, v.input),
        undefined,
        v.name,
      );
  }
  for (const tool of standardToolDefinitions())
    assert.ok(
      Object.keys(tool.output_schema.properties as object).length > 0,
      tool.name,
    );
});

test("service discovery and complete profile read/edit/read-back preserve optional fields", async () => {
  let profiles: Envelope<ProfileUpdatePayload>[] = [
    alice.signEvent(
      profileUpdateEvent(alice.agentId(), 100, 1, {
        id: alice.agentId(),
        name: "Before",
        links: [{ name: "Home", url: HOST, rel: "homepage" }],
        capabilities: ["research"],
      }),
    ),
  ];
  const c = connector((async (url, init) => {
    const u = new URL(String(url));
    if (u.pathname === "/.well-known/agent-profile")
      return json({
        protocol: "agent-profile/1.0",
        service: HOST,
        endpoints: { profiles: `${HOST}/profiles` },
        features: ["event-history"],
      });
    if (u.pathname === "/.well-known/agent-knowledge")
      return json({
        protocol: "agent-knowledge/1.0",
        service: HOST,
        features: ["ranked-search"],
        search_modes: ["lexical"],
        limits: { max_envelope_bytes: 262144 },
      });
    if (u.pathname === `/profiles/${alice.agentId()}/events`)
      return json({
        result: profiles.slice(0, Number(u.searchParams.get("limit") ?? 1)),
      });
    if (u.pathname === "/profiles" && init?.method === "POST") {
      const e = JSON.parse(String(init.body));
      profiles.unshift(e);
      return json(materializeProfile(e));
    }
    return json({ error: { code: "not_found", message: "unknown" } }, 404);
  }) as typeof fetch);
  assert.deepEqual((await call(c, "identity_current")).profiles, [HOST]);
  const services = await call(c, "services_list");
  assert.equal(services.services.length, 2);
  assert.deepEqual(services.errors, []);
  const old = (await call(c, "profiles_get", { profile_service: HOST }))
    .profiles[0];
  const { updated_at: _, event_id: __, ...payload } = old;
  await call(c, "profile_update", {
    profile_service: HOST,
    profile: { ...payload, name: "After" },
  });
  const current = (await call(c, "profiles_get", { profile_service: HOST }))
    .profiles[0];
  assert.equal(current.name, "After");
  assert.deepEqual(current.links, old.links);
  assert.deepEqual(current.capabilities, ["research"]);
  assert.equal(
    (await call(c, "profile_history", { profile_service: HOST })).envelopes
      .length,
    2,
  );
  assert.deepEqual(
    (
      await call(c, "profiles_get", {
        profile_service: HOST,
        ids: [bob.agentId()],
      })
    ).missing,
    [bob.agentId()],
  );
  await assert.rejects(
    () =>
      call(c, "profile_history", {
        profile_service: HOST,
        agent_id: "not-an-agent",
      }),
    (e) => (e as any).code === "invalid_agent_id",
  );
  await assert.rejects(
    () =>
      call(c, "profile_update", { profile_service: HOST, profile: current }),
    (e) => Boolean((e as any).data?.errors.length),
  );
});

test("delegation pages and controller enumeration preserve authority and completeness", async () => {
  const principalId = `${HOST}/principal`;
  const principal: delegation.PrincipalDocument = {
    protocol: "agent-delegation/1.0",
    updated_at: 100,
    id: principalId,
    type: "organization",
    controllers: [
      {
        id: alice.agentId(),
        source: "local",
        valid_from: 0,
        delegation: { scopes: ["read"], audiences: [HOST] },
      },
    ],
    delegation_service: HOST,
  };
  const envelope = alice.signEvent(
    delegation.delegationGrantEvent(alice.agentId(), 100, 1, {
      id: "del",
      principal_id: principalId,
      subject: bob.agentId(),
      scopes: ["read"],
      audiences: [HOST],
    }),
  );
  const credential = delegation.materializeDelegationCredential(envelope, {
    acceptedAt: 101,
  });
  let overreach = false;
  let credentialId = "del";
  const c = connector((async (url, init) => {
    const u = new URL(String(url));
    if (u.pathname === "/principal") return json(principal);
    if (u.pathname === "/.well-known/agent-delegation")
      return json({ protocol: "agent-delegation/1.0", service: HOST });
    if (u.pathname === "/v1/delegations/query") {
      const q = JSON.parse(String(init?.body));
      if (q.subject === undefined) {
        assert.equal(q.principal_id, principalId);
        assert.ok(new Headers(init?.headers).get("authorization"));
        return json({
          result: [
            overreach ? { ...credential, scopes: ["admin"] } : credential,
          ],
        });
      }
      return q.cursor
        ? json({ result: [credential] })
        : json({ result: [], next_cursor: "second" });
    }
    if (u.pathname === "/v1/delegations/del/events")
      return json({ result: [{ envelope, accepted_at: 101 }] });
    if (u.pathname === "/v1/delegations/del")
      return json({ ...credential, id: credentialId });
    return json({}, 404);
  }) as typeof fetch);
  const input = {
    principal_id: principalId,
    subject: bob.agentId(),
    audience: HOST,
  };
  const first = await call(c, "delegation_check", input);
  assert.equal(first.complete, false);
  assert.equal(first.next_cursor, "second");
  const second = await call(c, "delegation_check", {
    ...input,
    cursor: first.next_cursor,
  });
  assert.equal(second.complete, true);
  assert.equal(second.delegations[0].usable, true);
  assert.equal(
    (await call(c, "delegations_list", { principal_id: principalId }))
      .delegations[0].subject,
    bob.agentId(),
  );
  assert.equal(
    (
      await call(c, "delegation_history", {
        principal_id: principalId,
        id: "del",
      })
    ).signatures_verified,
    true,
  );
  credentialId = "other";
  await assert.rejects(
    () =>
      call(c, "delegation_history", {
        principal_id: principalId,
        id: "del",
      }),
    { code: "invalid_payload" },
  );
  credentialId = "del";
  overreach = true;
  await assert.rejects(
    () => call(c, "delegations_list", { principal_id: principalId }),
    { code: "permission_denied" },
  );
});

function roomFixture() {
  const id = "room1";
  const type = {
    type: "review.signal",
    kind: "signal" as const,
    title: "Review",
    schema: {
      type: "object",
      required: ["note"],
      properties: { note: { type: "string" } },
    },
  };
  const envelope = alice.signEvent(
    roomCreateEvent(alice.agentId(), 100, 1, {
      host: HOST,
      topic: "Review",
      visibility: "private",
      start_time: 1,
      end_time: 10000,
      types: [type],
    }),
  );
  const records: ServerRecord[] = [
    buildServerRecord(id, 1, null, 100, envelope),
  ];
  for (const [event, payload] of [
    ["review.signal", { note: "first" }],
    ["room.close", { reason: "done" }],
  ] as const) {
    const previous = records.at(-1)!;
    records.push(
      buildServerRecord(
        id,
        previous.seq + 1,
        previous.hash,
        100 + previous.seq,
        alice.signEvent(
          discourseEvent(
            event,
            alice.agentId(),
            100 + previous.seq,
            previous.seq + 1,
            id,
            1,
            records[0].hash,
            payload,
          ),
        ),
      ),
    );
  }
  const last = records.at(-1)!;
  const room = {
    id,
    status: "ended" as const,
    url: `${HOST}/v1/rooms/${id}`,
    creator: alice.agentId(),
    types: [type],
    seq: last.seq,
    hash: last.hash,
    pre_hash: last.pre_hash,
    accepted_at: last.accepted_at,
    head: { seq: last.seq, hash: last.hash },
    envelope,
  };
  const manifest = {
    protocol: "agent-discourse/1.0",
    type: "room.archive",
    room_id: id,
    url: room.url,
    generated_at: 200,
    last_seq: last.seq,
    last_hash: last.hash,
    formats: { jsonl: `${room.url}/archive.jsonl` },
  };
  return { id, records, room, manifest };
}

test("private invitations, old history, archive verification and watches survive restart", async () => {
  const f = roomFixture();
  let redacted = false;
  let corrupt = false;
  const fetchImpl = (async (url, init) => {
    const u = new URL(String(url));
    if (u.pathname === "/.well-known/agent-discourse")
      return json({
        protocol: "agent-discourse/1.0",
        service: HOST,
        endpoints: {
          rooms: `${HOST}/v1/rooms`,
          my_rooms: `${HOST}/v1/me/rooms`,
        },
      });
    assert.ok(
      new Headers(init?.headers).get("authorization"),
      "private reads carry a JWT",
    );
    if (u.pathname === "/v1/me/rooms")
      return json({
        result: [{ ...f.room, membership: "invited", role: "observer" }],
      });
    if (u.pathname === `/v1/rooms/${f.id}/events`)
      return json({ result: f.records });
    if (u.pathname === `/v1/rooms/${f.id}/archive`)
      return json(corrupt ? { ...f.manifest, last_hash: "bad" } : f.manifest);
    if (u.pathname.endsWith("/archive.jsonl"))
      return new Response(
        f.records
          .map((r, i) =>
            JSON.stringify(redacted && i === 1 ? redactServerRecord(r) : r),
          )
          .join("\n"),
      );
    return json(f.room);
  }) as typeof fetch;
  const c = connector(fetchImpl);
  const mine = await call(c, "rooms_list", {
    scope: "mine",
    host: HOST,
    membership: "invited",
  });
  assert.equal(mine.rooms[0].membership, "invited");
  await call(c, "room_state", { host: HOST, room_id: f.id });
  await call(c, "room_watch", { room_id: f.id, types: ["review.signal"] });
  const snapshot = c.snapshot();
  snapshot.rooms[0].records = snapshot.rooms[0].records.slice(-1);
  snapshot.rooms[0].timeline = snapshot.rooms[0].timeline.slice(-1);
  const restored = LocalConnector.fromSnapshot(alice, snapshot, { fetchImpl });
  assert.deepEqual(
    (await call(restored, "room_watch", { room_id: f.id })).types,
    ["review.signal"],
  );
  assert.equal(
    (await call(restored, "room_timeline", { room_id: f.id })).history
      .truncated,
    true,
  );
  const before = restored.snapshot();
  const remote = await call(restored, "room_timeline", {
    room_id: f.id,
    source: "remote",
    before_seq: 3,
  });
  assert.deepEqual(
    remote.items.map((i: any) => i.seq),
    [1, 2],
  );
  assert.deepEqual(restored.snapshot(), before);
  const archive = await call(restored, "room_archive", { room_id: f.id });
  assert.equal(archive.state_verified, true);
  assert.equal(archive.verified, true);
  redacted = true;
  const incomplete = await call(restored, "room_archive", { room_id: f.id });
  assert.equal(incomplete.state_verified, false);
  assert.deepEqual(incomplete.redacted, [2]);
  corrupt = true;
  await assert.rejects(() => call(restored, "room_archive", { room_id: f.id }));
  const live = connector(fetchImpl);
  live.observeRoom(HOST, f.room);
  await call(live, "room_watch", { room_id: f.id, types: ["review.signal"] });
  for (const record of f.records) live.applyHostRecord(HOST, record);
  assert.equal(
    (await call(live, "inbox_next", { kinds: ["room.event.custom"] })).items
      .length,
    1,
  );
  const schema = await call(live, "schema_get", {
    protocol: "agent-discourse/1.0",
    room_id: f.id,
    type: "review.signal",
  });
  assert.deepEqual(schema.schemas[0].schema.required, ["note"]);
});

test("archive pack metadata cannot replace the signed import digest", async () => {
  const pack = `${HOST}/pack.json`,
    digest = "A".repeat(43);
  const envelope = alice.signEvent(
    roomCreateEvent(alice.agentId(), 100, 1, {
      host: HOST,
      topic: "Pack",
      visibility: "public",
      start_time: 1,
      end_time: 10000,
      types: [{ pack, digest }],
    }),
  );
  const first = buildServerRecord("room1", 1, null, 100, envelope);
  const last = buildServerRecord(
    "room1",
    2,
    first.hash,
    101,
    alice.signEvent(
      discourseEvent(
        "room.close",
        alice.agentId(),
        101,
        2,
        "room1",
        1,
        first.hash,
        {},
      ),
    ),
  );
  const c = connector((async (url) => {
    const path = new URL(String(url)).pathname;
    if (path === "/.well-known/agent-discourse") return json({}, 404);
    if (path.endsWith("/archive"))
      return json({
        protocol: "agent-discourse/1.0",
        type: "room.archive",
        room_id: "room1",
        url: `${HOST}/v1/rooms/room1`,
        generated_at: 102,
        last_seq: 2,
        last_hash: last.hash,
        formats: { jsonl: `${HOST}/log` },
        packs: [{ pack, digest: "B".repeat(43), url: `${HOST}/forged-pack` }],
      });
    if (path === "/log")
      return new Response(
        [first, last].map((r) => JSON.stringify(r)).join("\n"),
      );
    assert.fail("a mismatched pack must be rejected before fetching it");
  }) as typeof fetch);
  await assert.rejects(
    () => call(c, "room_archive", { room_id: "room1", host: HOST }),
    /signed import/,
  );
});

test("mail resolve projects the final pin once and isolates malformed Profile endpoints", async () => {
  const mirror = "https://mirror.example.test",
    now = Date.now(),
    id = newMailId();
  const payload = {
    mailbox_id: id,
    public_key: MailEncryptionKey.generate().publicKey(),
    routes: [HOST, mirror],
    expires_at: now + 60000,
    receive_until: now + 120000,
    max_packet_bytes: 65536,
  };
  const old = bob.signEvent(
    mailboxPublishEvent(bob.agentId(), now, 1, payload),
  );
  const closed = bob.signEvent(
    mailboxPublishEvent(bob.agentId(), now, 2, { ...payload, routes: [] }),
  );
  const profile = bob.signEvent(
    profileUpdateEvent(bob.agentId(), now, 3, {
      id: bob.agentId(),
      name: "Bob",
      service_endpoints: [
        { type: "agent-mail", url: `${HOST}/bad` },
        { type: "agent-mail", url: `${HOST}/v1/mailboxes/${id}/card` },
        { type: "agent-mail", url: `${mirror}/v1/mailboxes/${id}/card` },
      ],
    }),
  );
  const c = connector((async (url) => {
    const u = new URL(String(url));
    if (u.pathname === "/.well-known/agent-profile")
      return json({
        protocol: "agent-profile/1.0",
        service: HOST,
        endpoints: { profiles: `${HOST}/profiles` },
      });
    if (u.pathname.endsWith("/events")) return json({ result: [profile] });
    return json({
      envelope: u.origin === mirror ? closed : old,
      accepted_at: now,
    });
  }) as typeof fetch);
  c.addHost({ host: mirror, allowed: true });
  const result = await call(c, "mail_resolve", {
    agent_id: bob.agentId(),
    profile_service: HOST,
  });
  assert.equal(result.errors.length, 1);
  assert.equal(result.mailboxes.length, 1);
  assert.equal(result.mailboxes[0].card.hash, closed.hash);
  assert.equal(result.mailboxes[0].usable, false);
});
