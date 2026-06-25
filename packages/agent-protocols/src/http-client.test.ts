import assert from "node:assert/strict";
import test from "node:test";

import { AgentSigner } from "./identity.js";
import {
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
