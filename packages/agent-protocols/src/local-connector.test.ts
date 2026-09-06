import assert from "node:assert/strict";
import test from "node:test";

import {
  RoomResponse,
  buildServerRecord,
  discourseEvent,
  eventType,
  roomCreateEvent,
} from "./discourse.js";
import { AgentSigner, withMention } from "./identity.js";
import {
  HeldDraft,
  InboxItem,
  InboxKind,
  LocalConnector,
  RoomMemberStatus,
  RoomMemberView,
  RoomStateView,
  RoomWriteResult,
  SyncState,
  TOOL_DELEGATIONS_LIST,
  TOOL_DELEGATION_CHECK,
  TOOL_DELEGATION_GRANT,
  TOOL_DELEGATION_REVOKE,
  TOOL_DRAFTS_LIST,
  TOOL_DRAFT_DROP,
  TOOL_DRAFT_GET,
  TOOL_INBOX_NEXT,
  TOOL_PRINCIPAL_RESOLVE,
  TOOL_ROOM_JOIN,
  TOOL_ROOM_MEMBERS_LIST,
  TOOL_ROOM_SEND_MESSAGE,
  TOOL_ROOM_STATE,
  TimelineItem,
  roomSummaryFromResponse,
  standardToolDefinitions,
  syncStateFromRoomResponse,
  timelineItemFromRecord,
} from "./local-connector.js";

function signer(byte: number): AgentSigner {
  return AgentSigner.fromSeed(new Uint8Array(32).fill(byte));
}

function roomResponse(roomId: string, creator: AgentSigner): RoomResponse {
  const envelope = creator.signEvent(
    roomCreateEvent(creator.agentId(), 100, 1, {
      topic: "Room",
      visibility: "public",
      start_time: 1,
      end_time: 2,
    }),
  );
  return {
    id: roomId,
    status: "active",
    url: `https://api.example.test/v1/rooms/${roomId}`,
    topic: "Room",
    visibility: "public",
    start_time: 1,
    end_time: 2,
    tags: [],
    types: [],
    seq: 1,
    pre_hash: null,
    hash: "room-create-head",
    received_at: 100,
    head: { seq: 1, hash: "room-create-head" },
    envelope,
  };
}

test("standardToolDefinitions includes local connector tools and annotations", () => {
  const tools = standardToolDefinitions();
  const names = tools.map((tool) => tool.name);

  assert.ok(names.includes(TOOL_ROOM_MEMBERS_LIST));
  assert.ok(names.includes(TOOL_INBOX_NEXT));
  assert.ok(names.includes(TOOL_ROOM_JOIN));
  assert.ok(names.includes(TOOL_ROOM_SEND_MESSAGE));
  assert.equal(
    tools.find((tool) => tool.name === TOOL_ROOM_MEMBERS_LIST)?.annotations
      .readOnlyHint,
    true,
  );
  assert.equal(
    tools.find((tool) => tool.name === TOOL_ROOM_SEND_MESSAGE)?.annotations
      .openWorldHint,
    true,
  );
});

test("standardToolDefinitions covers the delegation surface", () => {
  const tools = standardToolDefinitions();
  const find = (name: string) => {
    const tool = tools.find((candidate) => candidate.name === name);
    assert.ok(tool, `missing tool ${name}`);
    return tool;
  };

  // Reads reach other origins, so they are open-world but never writes.
  for (const name of [
    TOOL_PRINCIPAL_RESOLVE,
    TOOL_DELEGATION_CHECK,
    TOOL_DELEGATIONS_LIST,
  ]) {
    assert.equal(find(name).annotations.readOnlyHint, true, name);
    assert.equal(find(name).annotations.openWorldHint, true, name);
  }

  // Grant and revoke sign envelopes, so they are neither read-only nor
  // idempotent.
  for (const name of [TOOL_DELEGATION_GRANT, TOOL_DELEGATION_REVOKE]) {
    assert.equal(find(name).annotations.readOnlyHint, false, name);
    assert.equal(find(name).annotations.idempotentHint, false, name);
    assert.equal(find(name).annotations.openWorldHint, true, name);
  }
});

test("syncStateFromRoomResponse and roomSummaryFromResponse derive room views", () => {
  const creator = AgentSigner.fromSeed(new Uint8Array(32).fill(8));
  const envelope = creator.signEvent(
    roomCreateEvent(creator.agentId(), 100, 1, {
      topic: "Room",
      visibility: "public",
      start_time: 1,
      end_time: 2,
      tags: ["review"],
      language: "en",
    }),
  );
  const room = {
    id: "room1",
    status: "active" as const,
    url: "https://api.example.com/v1/rooms/room1",
    seq: 1,
    pre_hash: null,
    hash: "room-create-head",
    received_at: 101,
    head: { seq: 1, hash: "room-create-head" },
    envelope,
  };

  assert.deepEqual(syncStateFromRoomResponse("https://api.example.com/", room), {
    host: "https://api.example.com",
    room_id: "room1",
    head_seq: 1,
    head_hash: "room-create-head",
    synced_seq: 1,
    remote_seq: 1,
    subscribed: false,
    unread_count: 0,
    pending_inbox_count: 0,
  });
  assert.deepEqual(roomSummaryFromResponse("https://api.example.com/", room), {
    room_id: "room1",
    host: "https://api.example.com",
    topic: "Room",
    status: "active",
    visibility: "public",
    start_time: 1,
    end_time: 2,
    tags: ["review"],
    language: "en",
    role: undefined,
    unread_count: 0,
    pending_inbox_count: 0,
  });
});

test("timelineItemFromRecord exposes message fields and event-level mentions", () => {
  const speaker = AgentSigner.fromSeed(new Uint8Array(32).fill(9));
  const target = AgentSigner.fromSeed(new Uint8Array(32).fill(10));
  const event = withMention(
    discourseEvent(
      eventType.MESSAGE_CREATE,
      speaker.agentId(),
      120,
      2,
      "room1",
      1,
      "room-create-head",
      {
        content_type: "text/plain",
        content: "please review this",
        references: ["abc"],
      },
    ),
    target.agentId(),
  );
  const envelope = speaker.signEvent(event);
  const record = buildServerRecord("room1", 2, "room-create-head", 121, envelope);
  const item = timelineItemFromRecord(record);

  assert.equal(item.type, eventType.MESSAGE_CREATE);
  assert.equal(item.kind, "message");
  assert.equal(item.content_type, "text/plain");
  assert.equal(item.content, "please review this");
  assert.deepEqual(item.references, ["abc"]);
  assert.deepEqual(item.mentions, [target.agentId()]);
  assert.equal(item.summary, "please review this");
});

test("connector surface reflects the 2026-07-04 revision", () => {
  const tools = standardToolDefinitions();
  const names = tools.map((tool) => tool.name);

  // The host allowlist is operator configuration; no agent-reachable mutation.
  assert.ok(!names.some((name) => name === "agent_protocols_host_add"));

  // Static annotations: mark_read-capable timeline reads declare readOnly false.
  const timeline = tools.find(
    (tool) => tool.name === "agent_protocols_room_timeline",
  );
  assert.equal(timeline?.annotations.readOnlyHint, false);
  assert.equal(timeline?.annotations.idempotentHint, true);
  const inboxNext = tools.find((tool) => tool.name === TOOL_INBOX_NEXT);
  assert.equal(inboxNext?.annotations.readOnlyHint, false);

  // Member status and inbox kinds cover removal and bans.
  const banned: RoomMemberStatus = "banned";
  const removedKind: InboxKind = "room.member.removed";
  assert.equal(banned, "banned");
  assert.equal(removedKind, "room.member.removed");
});

test("observed hosts do not bypass the allowlist for signing", () => {
  const connector = new LocalConnector(signer(1));
  connector.acceptRoomResponse(
    "https://untrusted.example.test",
    roomResponse("room1", signer(5)),
  );
  assert.equal(
    connector.state.hosts.get("https://untrusted.example.test")?.allowed,
    false,
  );
  assert.throws(
    () =>
      connector.signRoomEvent(
        eventType.MESSAGE_CREATE,
        { host: "https://untrusted.example.test", roomId: "room1" },
        undefined,
        undefined,
        [],
        { content_type: "text/plain", content: "hi" },
      ),
    /permission denied/,
  );
});

test("room views fall back to room.create payload metadata", async () => {
  const connector = new LocalConnector(signer(1));
  const room = roomResponse("room1", signer(5));
  const payload = room.envelope!.event.payload;
  payload.agenda = "Review the proposal";
  payload.guidance = "Stay concise";
  payload.tags = ["review"];
  payload.language = "en";
  room.topic = undefined;
  room.agenda = undefined;
  room.guidance = undefined;
  room.visibility = undefined;
  room.start_time = undefined;
  room.end_time = undefined;
  room.tags = [];
  room.language = undefined;
  connector.observeRoom("https://api.example.test", room);

  const state = (await connector.callTool(TOOL_ROOM_STATE, {
    room_id: "room1",
    host: "https://api.example.test",
  })) as { room: RoomStateView };
  assert.equal(state.room.topic, "Room");
  assert.equal(state.room.agenda, "Review the proposal");
  assert.equal(state.room.guidance, "Stay concise");
  assert.equal(state.room.visibility, "public");
  assert.equal(state.room.start_time, 1);
  assert.equal(state.room.end_time, 2);
  assert.deepEqual(state.room.tags, ["review"]);
  assert.equal(state.room.language, "en");
});

test("applyRecord materializes members, timeline, and inbox", async () => {
  const active = signer(1);
  const speaker = signer(2);
  const connector = new LocalConnector(active);
  connector.addHost({
    host: "https://api.example.test",
    allowed: true,
    features: [],
  });
  connector.acceptRoomResponse(
    "https://api.example.test",
    roomResponse("room1", signer(5)),
  );

  const joinEnvelope = speaker.signEvent(
    discourseEvent(
      eventType.ROOM_JOIN,
      speaker.agentId(),
      110,
      1,
      "room1",
      1,
      "room-create-head",
      { request_id: "jr1", role: "speaker" },
    ),
  );
  const join = buildServerRecord(
    "room1",
    2,
    "room-create-head",
    111,
    joinEnvelope,
  );
  connector.applyRecord(join);

  // room.join is a membership signal: it does not advance the room head.
  const afterJoin = (await connector.callTool(TOOL_ROOM_STATE, {
    room_id: "room1",
    host: "https://api.example.test",
  })) as { sync: SyncState };
  assert.equal(afterJoin.sync.head_seq, 1);

  const messageEnvelope = speaker.signEvent(
    withMention(
      discourseEvent(
        eventType.MESSAGE_CREATE,
        speaker.agentId(),
        120,
        2,
        "room1",
        1,
        "room-create-head",
        { content_type: "text/plain", content: "please review this" },
      ),
      active.agentId(),
    ),
  );
  const message = buildServerRecord("room1", 3, join.hash, 121, messageEnvelope);
  connector.applyRecord(message);

  const members = (await connector.callTool(TOOL_ROOM_MEMBERS_LIST, {
    room_id: "room1",
    host: "https://api.example.test",
    status: "active",
  })) as { members: RoomMemberView[] };
  assert.equal(members.members.length, 2);

  const inbox = (await connector.callTool(TOOL_INBOX_NEXT, {
    room_id: "room1",
    kinds: ["room.mention"],
    claim: true,
  })) as { items: InboxItem[]; pending_count: number };
  assert.equal(inbox.items.length, 1);
  assert.equal(inbox.items[0].kind, "room.mention");
  assert.equal(inbox.pending_count, 0);
});

test("room.send_message holds a draft on head mismatch before submit", async () => {
  const active = signer(1);
  const speaker = signer(2);
  const connector = new LocalConnector(active);
  connector.acceptRoomResponse(
    "https://api.example.test",
    roomResponse("room1", signer(5)),
  );

  const messageEnvelope = speaker.signEvent(
    discourseEvent(
      eventType.MESSAGE_CREATE,
      speaker.agentId(),
      120,
      1,
      "room1",
      1,
      "room-create-head",
      { content_type: "text/plain", content: "new context" },
    ),
  );
  const message = buildServerRecord(
    "room1",
    2,
    "room-create-head",
    121,
    messageEnvelope,
  );
  connector.applyRecord(message);

  const result = (await connector.callTool(TOOL_ROOM_SEND_MESSAGE, {
    room_id: "room1",
    content: "answer based on old context",
    base_seq: 1,
    base_hash: "room-create-head",
    on_head_mismatch: "hold",
  })) as RoomWriteResult;
  assert.equal(result.status, "held");
  assert.equal(result.draft?.kind, "message");
  assert.equal(result.draft?.base_seq, 1);
  assert.equal(result.changes?.length, 1);
  assert.equal(connector.state.drafts.size, 1);

  const draftId = result.draft!.id;
  const drafts = (await connector.callTool(TOOL_DRAFTS_LIST, {
    room_id: "room1",
  })) as { drafts: HeldDraft[] };
  assert.equal(drafts.drafts.length, 1);

  const draft = (await connector.callTool(TOOL_DRAFT_GET, {
    draft_id: draftId,
  })) as { changes: TimelineItem[] };
  assert.equal(draft.changes.length, 1);

  const dropped = (await connector.callTool(TOOL_DRAFT_DROP, {
    draft_id: draftId,
  })) as { status: string };
  assert.equal(dropped.status, "dropped");
  assert.equal(connector.state.drafts.size, 0);
});

test("signal records do not advance the room head", async () => {
  const connector = new LocalConnector(signer(1));
  const speaker = signer(2);
  const room = roomResponse("room1", signer(5));
  room.types = [
    {
      type: "reaction.create",
      kind: "signal",
      title: "Reaction",
      schema: { type: "object" },
    },
  ];
  connector.acceptRoomResponse("https://api.example.test", room);

  const signalEnvelope = speaker.signEvent(
    discourseEvent(
      "reaction.create",
      speaker.agentId(),
      120,
      1,
      "room1",
      1,
      "room-create-head",
      { emoji: "+1" },
    ),
  );
  const signal = buildServerRecord(
    "room1",
    2,
    "room-create-head",
    121,
    signalEnvelope,
  );
  connector.applyRecord(signal);

  const state = (await connector.callTool(TOOL_ROOM_STATE, {
    room_id: "room1",
    host: "https://api.example.test",
  })) as { sync: SyncState };
  assert.equal(state.sync.head_seq, 1);
  assert.equal(state.sync.head_hash, "room-create-head");
  assert.equal(state.sync.synced_seq, 2);
  assert.equal(state.sync.remote_seq, 2);
});

test("rejects non-signal records not based on the room head", () => {
  const connector = new LocalConnector(signer(1));
  const speaker = signer(2);
  const room = roomResponse("room1", signer(5));
  room.types = [
    {
      type: "reaction.create",
      kind: "signal",
      title: "Reaction",
      schema: { type: "object" },
    },
  ];
  connector.acceptRoomResponse("https://api.example.test", room);

  const signalEnvelope = speaker.signEvent(
    discourseEvent(
      "reaction.create",
      speaker.agentId(),
      120,
      1,
      "room1",
      1,
      "room-create-head",
      { emoji: "+1" },
    ),
  );
  const signal = buildServerRecord(
    "room1",
    2,
    "room-create-head",
    121,
    signalEnvelope,
  );
  const signalHash = signal.hash;
  connector.applyRecord(signal);

  const staleEnvelope = speaker.signEvent(
    discourseEvent(
      eventType.MESSAGE_CREATE,
      speaker.agentId(),
      122,
      2,
      "room1",
      2,
      signalHash,
      { content_type: "text/plain", content: "based on signal, not room head" },
    ),
  );
  const stale = buildServerRecord("room1", 3, signalHash, 123, staleEnvelope);
  assert.throws(
    () => connector.applyRecord(stale),
    /must match current room head/,
  );
});

test("member.remove records project removal, bans, and inbox", async () => {
  const active = signer(1);
  const moderator = signer(5);
  const connector = new LocalConnector(active);
  const room = roomResponse("room1", moderator);
  room.creator = moderator.agentId();
  connector.acceptRoomResponse("https://api.example.test", room);

  const activeId = connector.agentId();
  const joinEnvelope = active.signEvent(
    discourseEvent(
      eventType.ROOM_JOIN,
      activeId,
      110,
      1,
      "room1",
      1,
      "room-create-head",
      { role: "speaker" },
    ),
  );
  const join = buildServerRecord(
    "room1",
    2,
    "room-create-head",
    111,
    joinEnvelope,
  );
  connector.applyHostRecord("https://api.example.test", join);

  const removeEnvelope = moderator.signEvent(
    discourseEvent(
      eventType.ROOM_MEMBER_REMOVE,
      moderator.agentId(),
      120,
      2,
      "room1",
      1,
      "room-create-head",
      { member: activeId, ban: true, reason: "spam" },
    ),
  );
  const remove = buildServerRecord("room1", 3, join.hash, 121, removeEnvelope);
  connector.applyHostRecord("https://api.example.test", remove);

  const members = (await connector.callTool(TOOL_ROOM_MEMBERS_LIST, {
    room_id: "room1",
    host: "https://api.example.test",
    status: "banned",
  })) as { members: RoomMemberView[] };
  assert.equal(members.members.length, 1);
  assert.equal(members.members[0].left_seq, 3);

  const inbox = (await connector.callTool(TOOL_INBOX_NEXT, {
    room_id: "room1",
    kinds: ["room.member.removed"],
  })) as { items: InboxItem[] };
  assert.equal(inbox.items.length, 1);
  assert.equal(inbox.items[0].kind, "room.member.removed");
  assert.equal(inbox.items[0].reason, "member_banned");
});

test("room.update records advance the head and revise the contract", async () => {
  const connector = new LocalConnector(signer(1));
  const moderator = signer(5);
  connector.acceptRoomResponse(
    "https://api.example.test",
    roomResponse("room1", moderator),
  );

  const updateEnvelope = moderator.signEvent(
    discourseEvent(
      eventType.ROOM_UPDATE,
      moderator.agentId(),
      120,
      2,
      "room1",
      1,
      "room-create-head",
      {
        topic: "Sharper topic",
        guidance: "",
        end_time: 5000,
        // An all-default policy is still an explicit revision, stored verbatim.
        policy: {},
      },
    ),
  );
  const update = buildServerRecord(
    "room1",
    2,
    "room-create-head",
    121,
    updateEnvelope,
  );
  connector.applyHostRecord("https://api.example.test", update);

  const state = (await connector.callTool(TOOL_ROOM_STATE, {
    room_id: "room1",
    host: "https://api.example.test",
  })) as { room: RoomStateView; sync: SyncState };
  assert.equal(state.sync.head_seq, 2);
  assert.equal(state.room.topic, "Sharper topic");
  assert.equal(state.room.guidance, undefined);
  assert.equal(state.room.end_time, 5000);
  assert.deepEqual(state.room.policy, {});
  assert.equal(state.sync.pending_inbox_count, 1);
});

test("duplicate room ids across hosts require a host input", async () => {
  const creator = signer(5);
  const connector = new LocalConnector(signer(1));
  connector.acceptRoomResponse(
    "https://a.example.test",
    roomResponse("room1", creator),
  );
  connector.acceptRoomResponse(
    "https://b.example.test",
    roomResponse("room1", creator),
  );

  await assert.rejects(
    connector.callTool(TOOL_ROOM_MEMBERS_LIST, { room_id: "room1" }),
    /more than one host/,
  );
  const listed = (await connector.callTool(TOOL_ROOM_MEMBERS_LIST, {
    room_id: "room1",
    host: "https://b.example.test",
  })) as { sync: SyncState };
  assert.equal(listed.sync.host, "https://b.example.test");
});

test("delegation connector checks policy, ownership and service before signing or posting", async () => {
  const active = signer(61), other = signer(62);
  const host = "https://api.example.test", principalId = `${host}/p`;
  let policy: unknown = { scopes: ["draft"], audiences: ["https://dmsg.net"] };
  let previous: unknown;
  let readStatus = 404;
  const posts: unknown[] = [];
  let credentialReads = 0;
  const credentialReadUrls: string[] = [];
  let signatures = 0;
  let requestJwtSignatures = 0;
  const signEvent = active.signEvent.bind(active);
  active.signEvent = ((event) => { signatures++; return signEvent(event); }) as typeof active.signEvent;
  const signRequestJwt = active.signRequestJwt.bind(active);
  active.signRequestJwt = ((claims) => { requestJwtSignatures++; return signRequestJwt(claims); }) as typeof active.signRequestJwt;
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    if (url === principalId) return new Response(JSON.stringify({
      id: principalId, protocol: "agent-delegation/1.0", updated_at: Date.now(),
      delegation_query_url: `${host}/v1/delegations/query`,
      controllers: [{ id: active.agentId(), source: "local", valid_from: 0, ...(policy === undefined ? {} : { delegation: policy }) }],
    }));
    if (init?.method === "POST") { posts.push(JSON.parse(init.body as string)); return new Response("{}"); }
    credentialReads++;
    credentialReadUrls.push(url);
    return new Response(JSON.stringify(previous ?? {}), { status: readStatus });
  }) as typeof fetch;
  const connector = new LocalConnector(active, { fetchImpl });
  const input = { delegation_service: `${host}/`, principal_id: principalId, id: "del/opaque", subject: other.agentId(), scopes: ["draft"], audiences: ["https://dmsg.net"] };
  await assert.rejects(() => connector.callTool(TOOL_DELEGATION_GRANT, input), /permission denied/);
  await assert.rejects(() => connector.callTool(TOOL_DELEGATIONS_LIST, { delegation_service: host }), /permission denied/);
  assert.equal(credentialReads, 0, "unapproved services were never read");
  assert.equal(posts.length, 0, "unapproved services were never posted to");
  assert.equal(signatures, 0, "unapproved services received no event signatures");
  assert.equal(requestJwtSignatures, 0, "unapproved services received no request JWT signatures");
  connector.addHost({ host, allowed: true, features: [] });
  await connector.callTool(TOOL_DELEGATION_GRANT, input);
  assert.equal(credentialReadUrls[0], `${host}/v1/delegations/del%2Fopaque`);
  assert.equal(posts.length, 1);
  assert.deepEqual((posts[0] as { event: { payload: unknown } }).event.payload, {
    id: "del/opaque", principal: { id: principalId }, subject: other.agentId(), scopes: ["draft"], audiences: ["https://dmsg.net"],
  });
  await assert.rejects(() => connector.callTool(TOOL_DELEGATION_GRANT, { ...input, audiences: ["https://tokenlist.ing"] }));
  policy = undefined;
  await assert.rejects(() => connector.callTool(TOOL_DELEGATION_GRANT, input));
  policy = { scopes: ["draft"], audiences: ["https://dmsg.net"] };
  readStatus = 200;
  previous = { id: "del/opaque", principal: { id: principalId }, protocol: "agent-delegation/1.0", accepted_at: 1, owner_controller: other.agentId() };
  await assert.rejects(() => connector.callTool(TOOL_DELEGATION_GRANT, input));
  await assert.rejects(() => connector.callTool(TOOL_DELEGATION_REVOKE, input));
  readStatus = 503;
  await assert.rejects(() => connector.callTool(TOOL_DELEGATION_GRANT, input));
  await assert.rejects(() => connector.callTool(TOOL_DELEGATION_GRANT, { ...input, delegation_service: `${host}/untrusted` }));
  assert.equal(posts.length, 1, "denied writes were never submitted");
  assert.equal(signatures, 1, "denied writes were never signed");
  const tool = standardToolDefinitions().find(t => t.name === TOOL_DELEGATION_GRANT)!;
  assert.ok((tool.input_schema.required as string[]).includes("audiences"));
});
