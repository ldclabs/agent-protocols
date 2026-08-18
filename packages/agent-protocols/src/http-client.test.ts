import assert from "node:assert/strict";
import test from "node:test";

import { AgentSigner } from "./identity.js";
import {
  DelegationClient,
  DiscourseClient,
  ProfileClient,
  sseEventsUrl,
} from "./http-client.js";

interface QueuedResponse {
  ok?: boolean;
  status?: number;
  body?: unknown;
}

interface RecordedCall {
  url: string;
  init?: RequestInit;
}

function makeFetch(responses: QueuedResponse[] = []) {
  const calls: RecordedCall[] = [];
  let index = 0;
  const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
    calls.push({ url: String(url), init });
    const queued = responses[index++] ?? { ok: true, status: 200, body: null };
    return {
      ok: queued.ok ?? true,
      status: queued.status ?? 200,
      url: String(url),
      json: async () => queued.body,
      text: async () =>
        typeof queued.body === "string"
          ? queued.body
          : JSON.stringify(queued.body),
    } as Response;
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const AGENT_ID = AgentSigner.fromSeed(new Uint8Array(32).fill(1)).agentId();
const PRINCIPAL_ID = "https://api.al.ink/d9c6a99cne5g00a6scn0";

test("ProfileClient calls every endpoint with the right method and path", async () => {
  const { fetchImpl, calls } = makeFetch([
    { body: { id: AGENT_ID, name: "A", updated_at: 1, event_id: "e" } },
    { body: { result: [] } },
    { body: { result: [] } },
    { body: { id: AGENT_ID, name: "A", updated_at: 1, event_id: "e" } },
  ]);
  // base url carries a trailing slash to exercise normalization
  const client = new ProfileClient("https://api.example.com/", fetchImpl);

  const profile = await client.getProfile(AGENT_ID);
  assert.equal(profile.name, "A");
  await client.getProfiles([AGENT_ID]);
  await client.profileEvents(AGENT_ID);
  await client.submitProfileUpdate({
    hash: "h",
    event: {
      protocol: "agent-profile/1.0",
      type: "profile.update",
      actor: AGENT_ID,
      created_at: 1,
      nonce: 1,
      payload: { id: AGENT_ID, name: "A" },
    },
    signature: "s",
  });

  assert.equal(calls[0].url, `https://api.example.com/v1/profiles/${AGENT_ID}`);
  assert.equal(calls[0].init, undefined);
  assert.equal(calls[1].url, "https://api.example.com/v1/profiles/batch");
  assert.equal(calls[1].init?.method, "POST");
  assert.match(String(calls[1].init?.body), /ids/);
  assert.equal(
    calls[2].url,
    `https://api.example.com/v1/profiles/${AGENT_ID}/events?limit=1`,
  );
  assert.equal(calls[3].url, "https://api.example.com/v1/profiles");
  assert.equal(calls[3].init?.method, "POST");
});

test("ProfileClient.profileEvents accepts an explicit limit", async () => {
  const { fetchImpl, calls } = makeFetch([{ body: { result: [] } }]);
  const client = new ProfileClient("https://api.example.com", fetchImpl);
  await client.profileEvents(AGENT_ID, 5);
  assert.match(calls[0].url, /\/events\?limit=5$/);
});

test("DiscourseClient calls every endpoint and forwards bearer tokens", async () => {
  const { fetchImpl, calls } = makeFetch([
    { body: { protocol: "agent-discourse/1.0", host: "h" } },
    { body: { id: "room1" } },
    { body: { id: "room1" } },
    { body: { status: "pending" } },
    { body: { status: "pending" } },
    { body: [] },
    { body: { room_id: "room1" } },
    { body: { room_id: "room1" } },
    { body: { room_id: "room1" } },
    { body: [] },
    { body: [] },
    { body: { manifest: true } },
  ]);
  const client = new DiscourseClient("https://api.example.com", fetchImpl);
  const envelope = {
    hash: "h",
    event: {
      protocol: "agent-discourse/1.0",
      type: "x",
      actor: AGENT_ID,
      created_at: 1,
      nonce: 1,
      payload: {},
    },
    signature: "s",
  };

  await client.protocol();
  await client.createRoom(envelope as never);
  await client.room("room1");
  await client.requestJoin("room1", "jwt-a", { role: "speaker" });
  await client.joinRequest("room1", "req1", "jwt-b");
  await client.joinRequests("room1", "jwt-c");
  await client.joinRoom("room1", envelope as never);
  await client.leaveRoom("room1", envelope as never);
  await client.submitEvent("room1", envelope as never);
  await client.events("room1");
  await client.events("room1", {
    afterSeq: 7,
    limit: 10,
    cursor: "a b",
    jwt: "jwt-d",
  });
  const archive = await client.archive("room1");
  assert.deepEqual(archive, { manifest: true });

  assert.equal(calls[0].url, "https://api.example.com/.well-known/agent-discourse");
  assert.equal(calls[1].url, "https://api.example.com/v1/rooms");
  assert.equal(calls[1].init?.method, "POST");
  assert.equal(calls[2].url, "https://api.example.com/v1/rooms/room1");
  assert.equal(
    (calls[3].init?.headers as Record<string, string>).authorization,
    "Bearer jwt-a",
  );
  assert.equal(
    calls[4].url,
    "https://api.example.com/v1/rooms/room1/join-requests/req1",
  );
  assert.equal(
    (calls[4].init?.headers as Record<string, string>).authorization,
    "Bearer jwt-b",
  );
  assert.equal(
    (calls[5].init?.headers as Record<string, string>).authorization,
    "Bearer jwt-c",
  );
  assert.equal(calls[9].url, "https://api.example.com/v1/rooms/room1/events");
  assert.equal(calls[9].init?.headers, undefined);
  assert.equal(
    calls[10].url,
    "https://api.example.com/v1/rooms/room1/events?after_seq=7&limit=10&cursor=a%20b",
  );
  assert.equal(
    (calls[10].init?.headers as Record<string, string>).authorization,
    "Bearer jwt-d",
  );
  assert.equal(calls[11].url, "https://api.example.com/v1/rooms/room1/archive");
});

test("DiscourseClient.sseEventsUrl matches the helper", () => {
  const { fetchImpl } = makeFetch();
  const client = new DiscourseClient("https://api.example.com", fetchImpl);
  assert.equal(
    client.sseEventsUrl("room1"),
    sseEventsUrl("https://api.example.com", "room1"),
  );
});

test("DelegationClient calls delegation discovery, read, submit, and query endpoints", async () => {
  const { fetchImpl, calls } = makeFetch([
    {
      body: {
        protocol: "agent-delegation/1.0",
        service: "https://api.al.ink",
        endpoints: { delegations: "https://api.al.ink/v1/delegations" },
      },
    },
    { body: { id: PRINCIPAL_ID, controllers: [AGENT_ID] } },
    {
      body: {
        id: "del_1",
        protocol: "agent-delegation/1.0",
        principal: { id: PRINCIPAL_ID },
        controller: AGENT_ID,
        subject: AGENT_ID,
        scopes: ["inbox.screen"],
        status: "active",
        updated_at: 1,
        event_id: "e",
      },
    },
    { body: { id: "del_1", status: "active", checked_at: 2, event_id: "e" } },
    { body: { result: [] } },
    { body: { id: "del_1", status: "revoked", checked_at: 3, event_id: "e2" } },
    { body: { result: [] } },
  ]);
  const client = new DelegationClient("https://api.al.ink/", fetchImpl);

  await client.protocol();
  await client.principal(PRINCIPAL_ID);
  await client.delegation("del_1");
  await client.delegationStatus("del_1");
  await client.delegationEvents("del_1");
  await client.submitDelegationEvent({
    hash: "h",
    event: {
      protocol: "agent-delegation/1.0",
      type: "delegation.revoke",
      actor: AGENT_ID,
      created_at: 1,
      nonce: 1,
      payload: { id: "del_1", principal_id: PRINCIPAL_ID },
    },
    signature: "s",
  });
  await client.queryDelegations({
    subject: AGENT_ID,
    principal_id: PRINCIPAL_ID,
    status: "active",
    limit: 20,
  });

  assert.equal(calls[0].url, "https://api.al.ink/.well-known/agent-delegation");
  assert.equal(calls[1].url, PRINCIPAL_ID);
  assert.deepEqual(calls[1].init?.headers, { accept: "application/json" });
  assert.equal(calls[2].url, "https://api.al.ink/v1/delegations/del_1");
  assert.equal(calls[3].url, "https://api.al.ink/v1/delegations/del_1/status");
  assert.equal(calls[4].url, "https://api.al.ink/v1/delegations/del_1/events");
  assert.equal(calls[5].url, "https://api.al.ink/v1/delegations");
  assert.equal(calls[5].init?.method, "POST");
  assert.equal(calls[6].url, "https://api.al.ink/v1/delegations/query");
  assert.match(String(calls[6].init?.body), /inbox|active|limit/);
});

test("DelegationClient re-resolves a principal document served away from its id", async () => {
  const document = { id: PRINCIPAL_ID, controllers: [AGENT_ID], aliases: ["https://al.ink/yan"] };
  const { fetchImpl, calls } = makeFetch([{ body: document }, { body: document }]);
  const client = new DelegationClient("https://api.al.ink/", fetchImpl);

  // The alias hosts a copy instead of redirecting, so the canonical id is read.
  const resolved = await client.principal("https://al.ink/yan");

  assert.equal(resolved.id, PRINCIPAL_ID);
  assert.equal(calls[0].url, "https://al.ink/yan");
  assert.equal(calls[1].url, PRINCIPAL_ID);

  // A copy that never leads to an authoritative read is rejected.
  const impostor = makeFetch([
    { body: { id: PRINCIPAL_ID, controllers: [AGENT_ID] } },
    { body: { id: "https://impostor.example.com/yan", controllers: [AGENT_ID] } },
  ]);
  await assert.rejects(
    () =>
      new DelegationClient("https://api.al.ink/", impostor.fetchImpl).principal(
        "https://al.ink/yan",
      ),
    /was served at/,
  );
});

test("DiscourseClient supports public rooms, my rooms, and agent status endpoints", async () => {
  const { fetchImpl, calls } = makeFetch([
    { body: [] },
    { body: [] },
    { body: { statuses: [] } },
    {
      body: {
        status: {
          room_id: "room1",
          agent_id: AGENT_ID,
          state: "idle",
          expires_at: 2,
          updated_at: 1,
        },
      },
    },
    {
      body: {
        room_id: "room1",
        agent_id: AGENT_ID,
        state: "idle",
        expires_at: 2,
        updated_at: 1,
      },
    },
  ]);
  const client = new DiscourseClient("https://api.example.com/", fetchImpl);

  await client.publicRooms({
    status: "active",
    tag: "code review",
    startsAfter: 10,
    endsBefore: 20,
    limit: 5,
    cursor: "next page",
  });
  await client.myRooms("jwt-me");
  await client.agentStatuses("room1", "jwt-statuses");
  await client.agentStatus("room1", AGENT_ID, "jwt-status");
  await client.setAgentStatus("room1", "jwt-set", {
    state: "idle",
    expires_at: 2,
  });

  assert.equal(
    calls[0].url,
    "https://api.example.com/v1/rooms/public?status=active&tag=code%20review&starts_after=10&ends_before=20&limit=5&cursor=next%20page",
  );
  assert.equal(calls[1].url, "https://api.example.com/v1/me/rooms");
  assert.equal(
    (calls[1].init?.headers as Record<string, string>).authorization,
    "Bearer jwt-me",
  );
  assert.equal(calls[2].url, "https://api.example.com/v1/rooms/room1/agent-status");
  assert.equal(
    (calls[2].init?.headers as Record<string, string>).authorization,
    "Bearer jwt-statuses",
  );
  assert.equal(
    calls[3].url,
    `https://api.example.com/v1/rooms/room1/agent-status/${AGENT_ID}`,
  );
  assert.equal(calls[4].init?.method, "PUT");
  assert.equal(
    (calls[4].init?.headers as Record<string, string>).authorization,
    "Bearer jwt-set",
  );
  assert.match(String(calls[4].init?.body), /idle/);
});

test("readJson throws on non-2xx responses", async () => {
  const { fetchImpl } = makeFetch([{ ok: false, status: 500, body: "boom" }]);
  const client = new ProfileClient("https://api.example.com", fetchImpl);
  await assert.rejects(() => client.getProfile(AGENT_ID), /HTTP 500: boom/);
});

test("sseEventsUrl preserves HTTP schemes and encodes room ids", () => {
  assert.equal(
    sseEventsUrl("https://api.example.com", "room123"),
    "https://api.example.com/v1/rooms/room123/events/live",
  );
  assert.equal(
    sseEventsUrl("http://api.example.com/", "room 1"),
    "http://api.example.com/v1/rooms/room%201/events/live",
  );
  assert.equal(
    sseEventsUrl("ftp://api.example.com", "r"),
    "ftp://api.example.com/v1/rooms/r/events/live",
  );
});
