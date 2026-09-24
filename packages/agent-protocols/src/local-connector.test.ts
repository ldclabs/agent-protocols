import assert from "node:assert/strict";
import test from "node:test";

import {
  ArchiveRecord,
  RoomJoinRequest,
  RoomResponse,
  ServerRecord,
  buildServerRecord,
  discourseEvent,
  eventAdvancesRoomHead,
  eventType,
  redactServerRecord,
  roomCreateEvent,
  validateRoomBase,
} from "./discourse.js";
import * as delegation from "./delegation.js";
import { AgentSigner, Envelope, withMention } from "./identity.js";
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
  TOOL_DRAFT_COMMIT,
  TOOL_INBOX_NEXT,
  TOOL_JOIN_REQUEST_REVIEW,
  TOOL_PRINCIPAL_RESOLVE,
  TOOL_ROOM_JOIN,
  TOOL_ROOM_CREATE,
  TOOL_ROOM_MEMBERS_LIST,
  TOOL_ROOM_SEND_MESSAGE,
  TOOL_ROOM_STATE,
  TOOL_ROOM_SUBMIT_EVENT,
  TOOL_ROOM_TIMELINE,
  TimelineItem,
  roomSummaryFromResponse,
  standardToolDefinitions,
  syncStateFromRoomResponse,
  timelineItemFromRecord,
} from "./local-connector.js";

const HOST = "https://api.example.test";

function signer(byte: number): AgentSigner {
  return AgentSigner.fromSeed(new Uint8Array(32).fill(byte));
}

function roomResponse(roomId: string, creator: AgentSigner): RoomResponse {
  const envelope = creator.signEvent(
    roomCreateEvent(creator.agentId(), 100, 1, {
      host: HOST,
      topic: "Room",
      visibility: "public",
      start_time: 1,
      end_time: 2,
    }),
  );
  return {
    id: roomId,
    status: "active",
    url: `${HOST}/v1/rooms/${roomId}`,
    topic: "Room",
    visibility: "public",
    start_time: 1,
    end_time: 2,
    tags: [],
    types: [],
    seq: 1,
    pre_hash: null,
    hash: "room-create-head",
    accepted_at: 100,
    head: { seq: 1, hash: "room-create-head" },
    envelope,
  };
}

const REACTION_TYPE = { type: "reaction.create", kind: "signal" as const, title: "Reaction", schema: { type: "object" } };
const PLAN_TYPE = { type: "plan.update", kind: "control" as const, title: "Plan", schema: { type: "object" } };

/**
 * A minimal in-memory ADP host: it assigns records, enforces the Section 5.1
 * base checks, and serves history, the room resource, and join requests.
 */
class MockHost {
  records: ServerRecord[] = [];
  room: RoomResponse;
  joinRequests = new Map<string, RoomJoinRequest>();
  headBoundRejections = 0;
  failNextWrite = false;
  banned = new Set<string>();

  constructor(readonly roomId: string, readonly creator: AgentSigner, visibility: "public" | "private" = "public", policy = {}) {
    const envelope = creator.signEvent(roomCreateEvent(creator.agentId(), 100, 1, {
      host: HOST, topic: "Room", visibility, start_time: 1, end_time: 10 ** 13, policy,
    }));
    const record = buildServerRecord(roomId, 1, null, 100, envelope);
    this.records.push(record);
    this.room = {
      id: roomId, status: "active", url: `${HOST}/v1/rooms/${roomId}`, creator: creator.agentId(),
      topic: "Room", visibility, policy, types: [REACTION_TYPE, PLAN_TYPE],
      seq: 1, pre_hash: null, hash: record.hash, accepted_at: 100, head: { seq: 1, hash: record.hash }, envelope,
    };
  }

  head(): { seq: number; hash: string } {
    return this.room.head!;
  }

  append(envelope: Envelope<unknown>): ServerRecord {
    const previous = this.records[this.records.length - 1];
    const record = buildServerRecord(this.roomId, previous.seq + 1, previous.hash, 1000 + previous.seq, envelope);
    this.records.push(record);
    this.room.seq = record.seq;
    this.room.hash = record.hash;
    this.room.pre_hash = record.pre_hash;
    if (eventAdvancesRoomHead(envelope.event.type, this.room.types)) this.room.head = { seq: record.seq, hash: record.hash };
    return record;
  }

  fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    const path = url.pathname;
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
    const base = `/v1/rooms/${this.roomId}`;
    if (init?.method === "POST" && path === "/v1/rooms") {
      const envelope = JSON.parse(init.body as string) as Envelope<never>;
      const record = buildServerRecord(this.roomId, 1, null, 100, envelope);
      this.records = [record];
      Object.assign(this.room, record, { envelope, head: { seq: 1, hash: record.hash } });
      return json(this.room);
    }
    if (init?.method === "POST" && path === `${base}/join-requests`) {
      const envelope = JSON.parse(init.body as string) as Envelope<never>;
      const request: RoomJoinRequest = { id: envelope.hash, request: envelope, status: "pending", expires_at: 10 ** 13 };
      this.joinRequests.set(request.id, request);
      return json(request);
    }
    if (init?.method === "POST" && path === base) {
      if (this.failNextWrite) {
        this.failNextWrite = false;
        throw new Error("network unavailable");
      }
      const envelope = JSON.parse(init.body as string) as Envelope<unknown>;
      if (envelope.event.type === eventType.ROOM_JOIN && this.banned.has(envelope.event.actor)) {
        return json({ error: { code: "member_banned", message: "request review to rejoin" } }, 403);
      }
      if (envelope.event.base_seq !== undefined) {
        const anchor = this.records.find((record) => record.seq === envelope.event.base_seq);
        try {
          validateRoomBase(envelope.event.type, this.room.types, envelope.event.base_seq, envelope.event.base_hash!, anchor?.hash, this.head().seq);
        } catch (error) {
          const code = (error as { code: string }).code;
          if (code === "room_head_mismatch") this.headBoundRejections += 1;
          return json({ error: { code, message: "stale" } }, 409);
        }
      }
      if (envelope.event.type === eventType.ROOM_JOIN_REVIEW) {
        const payload = envelope.event.payload as { request: Envelope<unknown>; decision: string };
        const request = this.joinRequests.get(payload.request.hash)!;
        request.status = payload.decision === "approve" ? "approved" : "rejected";
        if (request.status === "approved") this.banned.delete(payload.request.event.actor);
      }
      return json(this.append(envelope));
    }
    if (path.startsWith(`${base}/join-requests/`)) {
      const request = this.joinRequests.get(path.slice(`${base}/join-requests/`.length));
      return request ? json(request) : json({ error: { code: "join_request_not_found", message: "no" } }, 404);
    }
    if (path === `${base}/events`) {
      const after = Number(url.searchParams.get("after_seq") ?? 0);
      return json({ result: this.records.filter((record) => record.seq > after) });
    }
    if (path === base) return json(this.room);
    return json({ error: { code: "not_found", message: path } }, 404);
  }) as typeof fetch;
}

function connectorFor(active: AgentSigner, host: MockHost): LocalConnector {
  const connector = new LocalConnector(active, { fetchImpl: host.fetch });
  connector.addHost({ host: HOST, allowed: true, features: [] });
  return connector;
}

function message(author: AgentSigner, host: MockHost, text: string, nonce: number): Envelope<unknown> {
  const head = host.head();
  return author.signEvent(discourseEvent(eventType.MESSAGE_CREATE, author.agentId(), 120, nonce, host.roomId, head.seq, head.hash, { content_type: "text/plain", content: text }));
}

/** A control record: it moves the coordination head that message and control writes are checked against. */
function plan(author: AgentSigner, host: MockHost, step: string, nonce: number): Envelope<unknown> {
  const head = host.head();
  return author.signEvent(discourseEvent(PLAN_TYPE.type, author.agentId(), 120, nonce, host.roomId, head.seq, head.hash, { step }));
}

test("the tool catalog is the consolidated 23-tool surface", () => {
  const names = standardToolDefinitions().map((tool) => tool.name);
  assert.equal(names.length, 23);
  assert.equal(new Set(names).size, 23);
  for (const removed of [
    "agent_protocols_rooms_search", "agent_protocols_room_leave",
    "agent_protocols_hosts_list", "agent_protocols_room_open", "agent_protocols_room_member_get",
    "agent_protocols_agent_status_get", "agent_protocols_agent_status_clear", "agent_protocols_room_unread",
    "agent_protocols_room_mark_read", "agent_protocols_draft_get", "agent_protocols_draft_drop",
    "agent_protocols_room_join_request", "agent_protocols_room_join_when_approved", "agent_protocols_host_add",
  ]) {
    assert.ok(!names.includes(removed as never), removed);
  }
  const tools = standardToolDefinitions();
  const find = (name: string) => tools.find((tool) => tool.name === name)!;
  assert.equal(find(TOOL_ROOM_MEMBERS_LIST).annotations.readOnlyHint, true);
  assert.equal(find(TOOL_ROOM_SEND_MESSAGE).annotations.openWorldHint, true);
  assert.equal(find(TOOL_ROOM_STATE).annotations.readOnlyHint, false);
  assert.equal(find(TOOL_ROOM_TIMELINE).annotations.readOnlyHint, false);
  assert.equal(find(TOOL_INBOX_NEXT).annotations.readOnlyHint, false);
  for (const name of [TOOL_PRINCIPAL_RESOLVE, TOOL_DELEGATION_CHECK, TOOL_DELEGATIONS_LIST]) {
    assert.equal(find(name).annotations.readOnlyHint, true, name);
    assert.equal(find(name).annotations.openWorldHint, true, name);
  }
  for (const name of [TOOL_DELEGATION_GRANT, TOOL_DELEGATION_REVOKE]) {
    assert.equal(find(name).annotations.readOnlyHint, false, name);
    assert.equal(find(name).annotations.idempotentHint, false, name);
  }
  const grant = find(TOOL_DELEGATION_GRANT).input_schema as { required: string[]; properties: Record<string, unknown> };
  assert.ok(grant.required.includes("audiences"));
  assert.ok(!("delegation_service" in grant.properties));
  assert.ok((find(TOOL_DELEGATION_CHECK).input_schema.required as string[]).includes("audience"));
  const banned: RoomMemberStatus = "banned";
  const removedKind: InboxKind = "room.member.removed";
  assert.deepEqual([banned, removedKind], ["banned", "room.member.removed"]);
});

test("syncStateFromRoomResponse and roomSummaryFromResponse derive room views", () => {
  const room = roomResponse("room1", signer(8));
  room.envelope!.event.payload.tags = ["review"];
  room.envelope!.event.payload.language = "en";
  room.tags = undefined;
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
  const summary = roomSummaryFromResponse("https://api.example.com/", room);
  assert.deepEqual([summary.topic, summary.language, summary.tags], ["Room", "en", ["review"]]);
});

test("timelineItemFromRecord exposes message fields, classes, and redaction", () => {
  const speaker = signer(9);
  const target = signer(10);
  const event = withMention(
    discourseEvent(eventType.MESSAGE_CREATE, speaker.agentId(), 120, 2, "room1", 1, "room-create-head", {
      content_type: "text/plain",
      content: "please review this",
      references: ["abc"],
    }),
    target.agentId(),
  );
  const record = buildServerRecord("room1", 2, "room-create-head", 121, speaker.signEvent(event));
  const item = timelineItemFromRecord(record);
  assert.equal(item.kind, "message");
  assert.equal(item.accepted_at, 121);
  assert.equal(item.content, "please review this");
  assert.deepEqual(item.references, ["abc"]);
  assert.deepEqual(item.mentions, [target.agentId()]);
  assert.equal(item.summary, "please review this");

  const redacted = timelineItemFromRecord(redactServerRecord(record));
  assert.deepEqual([redacted.redacted, redacted.kind, redacted.actor, redacted.payload], [true, "message", undefined, undefined]);

  const long = "界".repeat(200);
  const longItem = timelineItemFromRecord(buildServerRecord("room1", 2, "h", 1, speaker.signEvent(
    discourseEvent(eventType.MESSAGE_CREATE, speaker.agentId(), 1, 3, "room1", 1, "h", { content_type: "text/plain", content: long }),
  )));
  assert.equal([...longItem.summary].length, 160);
  assert.ok(longItem.summary.endsWith("…"));
  const update = timelineItemFromRecord(buildServerRecord("room1", 2, "h", 1, speaker.signEvent(
    discourseEvent(eventType.ROOM_UPDATE, speaker.agentId(), 1, 4, "room1", 1, "h", { topic: "t" }),
  )));
  assert.equal(update.kind, "contract");
});

test("observed hosts do not bypass the allowlist for signing", () => {
  const connector = new LocalConnector(signer(1));
  connector.acceptRoomResponse("https://untrusted.example.test", roomResponse("room1", signer(5)));
  assert.equal(connector.state.hosts.get("https://untrusted.example.test")?.allowed, false);
  assert.throws(
    () => connector.signRoomEvent(eventType.MESSAGE_CREATE, { host: "https://untrusted.example.test", roomId: "room1" }, undefined, undefined, [], { content_type: "text/plain", content: "hi" }),
    /permission denied/,
  );
});

test("room views fall back to room.create payload metadata", async () => {
  const connector = new LocalConnector(signer(1));
  connector.addHost({ host: HOST, allowed: true });
  const room = roomResponse("room1", signer(5));
  const payload = room.envelope!.event.payload;
  payload.agenda = "Review the proposal";
  payload.guidance = "Stay concise";
  payload.tags = ["review"];
  payload.language = "en";
  room.topic = undefined;
  room.visibility = undefined;
  room.start_time = undefined;
  room.end_time = undefined;
  room.tags = [];
  connector.acceptRoomResponse(HOST, room);

  const state = (await connector.callTool(TOOL_ROOM_STATE, { room_id: "room1", host: HOST })) as { room: RoomStateView };
  assert.equal(state.room.topic, "Room");
  assert.equal(state.room.agenda, "Review the proposal");
  assert.equal(state.room.guidance, "Stay concise");
  assert.equal(state.room.visibility, "public");
  assert.deepEqual(state.room.tags, ["review"]);
  assert.equal(state.room.language, "en");
});

test("room_state opens and syncs, and the presented head follows what the agent read", async () => {
  const creator = signer(5), active = signer(1), other = signer(2);
  const host = new MockHost("room1", creator);
  host.append(plan(other, host, "first", 1));
  const connector = connectorFor(active, host);

  const opened = (await connector.callTool(TOOL_ROOM_STATE, { room_id: "room1", host: HOST, subscribe: true })) as { sync: SyncState };
  assert.equal(opened.sync.head_seq, 2);
  assert.equal(opened.sync.presented_seq, 2, "the first state read is the starting view");
  assert.equal(opened.sync.subscribed, true);

  // New coordination arrives; a status-only read does not present it.
  host.append(plan(other, host, "second", 2));
  await connector.callTool(TOOL_ROOM_TIMELINE, { room_id: "room1", refresh: true, types: [PLAN_TYPE.type] });
  let sync = ((await connector.callTool(TOOL_ROOM_MEMBERS_LIST, { room_id: "room1" })) as { sync: SyncState }).sync;
  assert.deepEqual([sync.head_seq, sync.presented_seq], [3, 2], "a filtered read presents nothing");

  // A gap-free timeline read from the presented head presents the new head.
  const timeline = (await connector.callTool(TOOL_ROOM_TIMELINE, { room_id: "room1", unread_only: true, mark_read: true })) as { items: TimelineItem[]; sync: SyncState; unread_count: number };
  assert.equal(timeline.sync.presented_seq, 3);
  assert.equal(timeline.unread_count, 0);

  // A reply without an explicit base is signed against the presented head;
  // messages never advance the head.
  const sent = (await connector.callTool(TOOL_ROOM_SEND_MESSAGE, { room_id: "room1", content: "reply" })) as RoomWriteResult;
  assert.equal(sent.status, "sent");
  assert.equal(sent.record?.envelope.event.base_seq, 3);
  assert.deepEqual([sent.sync.head_seq, sent.sync.presented_seq], [3, 3]);
  // The agent's own control write extends the presented head.
  const planned = (await connector.callTool(TOOL_ROOM_SUBMIT_EVENT, { room_id: "room1", type: PLAN_TYPE.type, payload: { step: "mine" } })) as RoomWriteResult;
  assert.equal(planned.status, "sent");
  assert.equal(planned.sync.presented_seq, planned.record?.seq);
});

test("consecutive own messages share the head, and own control writes advance the presented head", async () => {
  const creator = signer(5);
  const host = new MockHost("room1", creator);
  const connector = connectorFor(creator, host);
  await connector.callTool(TOOL_ROOM_CREATE, {
    host: HOST, topic: "Room", visibility: "public", start_time: 1, end_time: 10 ** 13,
  });
  for (const content of ["first", "second"]) {
    const sent = await connector.callTool(TOOL_ROOM_SEND_MESSAGE, { room_id: "room1", content }) as RoomWriteResult;
    assert.equal(sent.status, "sent");
    assert.equal(sent.record?.envelope.event.base_seq, 1);
    assert.deepEqual([sent.sync.head_seq, sent.sync.presented_seq], [1, 1]);
  }
  for (const step of ["one", "two"]) {
    const sent = await connector.callTool(TOOL_ROOM_SUBMIT_EVENT, { room_id: "room1", type: PLAN_TYPE.type, payload: { step } }) as RoomWriteResult;
    assert.equal(sent.status, "sent");
    assert.equal(sent.sync.presented_seq, sent.record?.seq);
  }
  assert.equal(connector.state.drafts.size, 0);
});

test("failed and rejected draft commits keep the draft for retry", async () => {
  const creator = signer(5), other = signer(2);
  const host = new MockHost("room1", creator);
  const connector = connectorFor(creator, host);
  await connector.callTool(TOOL_ROOM_STATE, { room_id: "room1", host: HOST });
  host.append(plan(other, host, "new context", 1));
  const held = await connector.callTool(TOOL_ROOM_SEND_MESSAGE, { room_id: "room1", content: "draft" }) as RoomWriteResult;
  const draftId = held.draft!.id;
  host.failNextWrite = true;
  await assert.rejects(connector.callTool(TOOL_DRAFT_COMMIT, { draft_id: draftId, action: "send" }), /network unavailable/);
  assert.ok(connector.state.drafts.has(draftId));
  host.append(plan(other, host, "more context", 2));
  const rejected = await connector.callTool(TOOL_DRAFT_COMMIT, { draft_id: draftId, action: "send", on_head_mismatch: "reject" }) as RoomWriteResult;
  assert.equal(rejected.status, "rejected");
  assert.ok(connector.state.drafts.has(draftId));
  const sent = await connector.callTool(TOOL_DRAFT_COMMIT, { draft_id: draftId, action: "send" }) as RoomWriteResult;
  assert.equal(sent.status, "sent");
  assert.equal(connector.state.drafts.size, 0);
});

test("banned members request review with both known and newly reported bans", async () => {
  for (const known of [true, false]) {
    const creator = signer(5), applicant = signer(6);
    const host = new MockHost("room1", creator);
    const connector = connectorFor(applicant, host);
    await connector.callTool(TOOL_ROOM_STATE, { room_id: "room1", host: HOST });
    host.banned.add(applicant.agentId());
    const head = host.head();
    const ban = host.append(creator.signEvent(discourseEvent(eventType.ROOM_MEMBER_REMOVE,
      creator.agentId(), 120, 2, host.roomId, head.seq, head.hash,
      { member: applicant.agentId(), ban: true })));
    if (known) connector.applyHostRecord(HOST, ban);
    const joined = await connector.callTool(TOOL_ROOM_JOIN, { room_id: "room1", role: "speaker" }) as { status: string; join_request: RoomJoinRequest };
    assert.equal(joined.status, "approval_required");
    assert.equal(joined.join_request.request.event.type, eventType.ROOM_JOIN_REQUEST);
    assert.equal(host.joinRequests.size, 1);
    const moderator = connectorFor(creator, host);
    await moderator.callTool(TOOL_ROOM_STATE, { host: HOST, room_id: "room1" });
    await moderator.callTool(TOOL_JOIN_REQUEST_REVIEW, {
      room_id: "room1", request_id: joined.join_request.id, decision: "approve", role: "speaker",
    });
    const approved = await connector.callTool(TOOL_ROOM_JOIN, { room_id: "room1", role: "speaker" }) as { status: string };
    assert.equal(approved.status, "joined");
    assert.equal(host.banned.has(applicant.agentId()), false);
  }
});

test("a message against an unread coordination change is held, then committed with send or dropped", async () => {
  const creator = signer(5), active = signer(1), other = signer(2);
  const host = new MockHost("room1", creator);
  const connector = connectorFor(active, host);
  await connector.callTool(TOOL_ROOM_STATE, { room_id: "room1", host: HOST });
  // Another agent's message does not conflict with the draft.
  host.append(message(other, host, "chatter", 1));
  // A coordination change while the agent composes; the connector has not synced it.
  host.append(plan(other, host, "new context", 2));

  const held = (await connector.callTool(TOOL_ROOM_SEND_MESSAGE, { room_id: "room1", content: "answer based on old context" })) as RoomWriteResult;
  assert.equal(held.status, "held");
  assert.equal(host.headBoundRejections, 1, "the host enforced the head check");
  assert.deepEqual(held.draft?.options, ["revise", "send", "drop"]);
  assert.equal(held.changes?.length, 2);
  assert.equal(held.sync.presented_seq, 3, "the held result presents the head its changes reach");

  const read = (await connector.callTool(TOOL_DRAFTS_LIST, { draft_id: held.draft!.id })) as { drafts: HeldDraft[]; changes: TimelineItem[] };
  assert.equal(read.changes.length, 2);

  const sent = (await connector.callTool(TOOL_DRAFT_COMMIT, { draft_id: held.draft!.id, action: "revise", content: "revised answer" })) as RoomWriteResult;
  assert.equal(sent.status, "sent");
  assert.equal(sent.record?.envelope.event.base_seq, 3);
  assert.equal(connector.state.drafts.size, 0);

  host.append(plan(other, host, "more", 3));
  const again = (await connector.callTool(TOOL_ROOM_SEND_MESSAGE, { room_id: "room1", content: "x", on_head_mismatch: "hold" })) as RoomWriteResult;
  assert.equal(again.status, "held");
  const dropped = (await connector.callTool(TOOL_DRAFT_COMMIT, { draft_id: again.draft!.id, action: "drop" })) as { status: string };
  assert.equal(dropped.status, "dropped");
  await assert.rejects(() => connector.callTool(TOOL_DRAFT_COMMIT, { draft_id: again.draft!.id, action: "send" }), /draft not found/);

  host.append(plan(other, host, "even more", 4));
  const forced = (await connector.callTool(TOOL_ROOM_SEND_MESSAGE, { room_id: "room1", content: "y", on_head_mismatch: "send_anyway" })) as RoomWriteResult;
  assert.equal(forced.status, "sent");
  assert.equal(forced.record?.envelope.event.base_seq, 6, "send_anyway re-signed against the latest head");
  assert.equal(forced.sync.presented_seq, 5, "an automatic rebase does not present records the agent never saw");
});

test("contract writes only anchor, so a busy room cannot hold a moderator's update", async () => {
  const creator = signer(5), other = signer(2);
  const host = new MockHost("room1", creator);
  const connector = connectorFor(creator, host);
  await connector.callTool(TOOL_ROOM_STATE, { room_id: "room1", host: HOST });
  host.append(plan(other, host, "busy", 1));
  const result = (await connector.callTool(TOOL_ROOM_SUBMIT_EVENT, {
    room_id: "room1", type: eventType.ROOM_UPDATE, payload: { end_time: 10 ** 13 + 1 },
  })) as RoomWriteResult;
  assert.equal(result.status, "sent");
  assert.equal(result.record?.envelope.event.base_seq, 1, "anchored on the presented head, not the current one");
  assert.equal(result.sync.head_seq, 3, "and it still advances the head");
});

test("join: direct for open roles and invitees, reviewed and approved otherwise", async () => {
  const creator = signer(5), applicant = signer(6), invitee = signer(7);
  const publicRoom = new MockHost("pub1", creator, "public", { open_roles: ["observer"] });
  const observer = connectorFor(applicant, publicRoom);
  const joined = (await observer.callTool(TOOL_ROOM_JOIN, { room_id: "pub1", host: HOST, role: "observer", perspective: "watcher" })) as { status: string; member: RoomMemberView };
  assert.equal(joined.status, "joined");
  assert.equal(joined.member.perspective, "watcher");

  const privateRoom = new MockHost("priv1", creator, "private", { invites: { [invitee.agentId()]: "speaker" } });
  const invited = (await connectorFor(invitee, privateRoom).callTool(TOOL_ROOM_JOIN, { room_id: "priv1", host: HOST, role: "speaker" })) as { status: string };
  assert.equal(invited.status, "joined");

  const outsider = connectorFor(applicant, privateRoom);
  const pending = (await outsider.callTool(TOOL_ROOM_JOIN, { room_id: "priv1", host: HOST, role: "speaker", perspective: "reviewer", reason: "please" })) as { status: string; join_request: RoomJoinRequest };
  assert.equal(pending.status, "approval_required");
  assert.equal(pending.join_request.request.event.type, eventType.ROOM_JOIN_REQUEST);
  assert.equal(pending.join_request.request.event.base_seq, undefined, "a join request carries no base");
  const stillPending = (await outsider.callTool(TOOL_ROOM_JOIN, { room_id: "priv1", host: HOST, role: "speaker" })) as { status: string };
  assert.equal(stillPending.status, "approval_required");
  assert.equal(privateRoom.joinRequests.size, 1, "a pending request is not re-submitted");

  const moderator = connectorFor(creator, privateRoom);
  await moderator.callTool(TOOL_ROOM_STATE, { room_id: "priv1", host: HOST });
  await assert.rejects(() => moderator.callTool(TOOL_JOIN_REQUEST_REVIEW, { room_id: "priv1", request_id: pending.join_request.id, decision: "approve" }), /requires a role/);
  const review = (await moderator.callTool(TOOL_JOIN_REQUEST_REVIEW, { room_id: "priv1", request_id: pending.join_request.id, decision: "approve", role: "speaker" })) as { record: ServerRecord };
  assert.equal((review.record.envelope.event.payload as { request: Envelope<unknown> }).request.hash, pending.join_request.id);

  const approved = (await outsider.callTool(TOOL_ROOM_JOIN, { room_id: "priv1", host: HOST, role: "speaker" })) as { status: string; member: RoomMemberView };
  assert.equal(approved.status, "joined");
  assert.deepEqual([approved.member.role, approved.member.perspective], ["speaker", "reviewer"]);
  const inbox = (await outsider.callTool(TOOL_INBOX_NEXT, { kinds: ["room.join.approved"] })) as { items: InboxItem[] };
  assert.equal(inbox.items.length, 1);
});

test("signal and message records keep the head, contract and control records advance it", async () => {
  const connector = new LocalConnector(signer(1));
  connector.addHost({ host: HOST, allowed: true });
  const speaker = signer(2);
  const room = roomResponse("room1", signer(5));
  room.types = [REACTION_TYPE, PLAN_TYPE];
  connector.acceptRoomResponse(HOST, room);

  const signal = buildServerRecord("room1", 2, "room-create-head", 121, speaker.signEvent(
    discourseEvent("reaction.create", speaker.agentId(), 120, 1, "room1", 1, "room-create-head", { emoji: "+1" }),
  ));
  connector.applyRecord(signal);
  const redactedMessage = redactServerRecord(buildServerRecord("room1", 3, signal.hash, 122, speaker.signEvent(
    discourseEvent(eventType.MESSAGE_CREATE, speaker.agentId(), 121, 2, "room1", 1, "room-create-head", { content_type: "text/plain", content: "gone" }),
  )));
  connector.applyRecord(redactedMessage as ArchiveRecord);
  let state = (await connector.callTool(TOOL_ROOM_STATE, { room_id: "room1" })) as { sync: SyncState };
  assert.deepEqual([state.sync.head_seq, state.sync.synced_seq], [1, 3], "messages, redacted or not, keep the head");

  // A control record based on the latest record advances the head.
  const control = buildServerRecord("room1", 4, redactedMessage.hash, 123, speaker.signEvent(
    discourseEvent(PLAN_TYPE.type, speaker.agentId(), 122, 3, "room1", 3, redactedMessage.hash, { step: "next" }),
  ));
  connector.applyRecord(control);
  // A message based before the head is rejected by the local chain check.
  const stale = buildServerRecord("room1", 5, control.hash, 124, speaker.signEvent(
    discourseEvent(eventType.MESSAGE_CREATE, speaker.agentId(), 123, 4, "room1", 2, signal.hash, { content_type: "text/plain", content: "stale" }),
  ));
  assert.throws(() => connector.applyRecord(stale), /at or after the room head/);
  // A contract record anchored on an older record is accepted and advances the head.
  const contract = buildServerRecord("room1", 5, control.hash, 125, signer(5).signEvent(
    discourseEvent(eventType.ROOM_UPDATE, signer(5).agentId(), 124, 2, "room1", 1, "room-create-head", { topic: "Sharper topic", guidance: "", policy: {} }),
  ));
  connector.applyRecord(contract);
  state = (await connector.callTool(TOOL_ROOM_STATE, { room_id: "room1" })) as { sync: SyncState; room: RoomStateView };
  assert.equal(state.sync.head_seq, 5);
  assert.equal((state as { room: RoomStateView }).room.topic, "Sharper topic");
  assert.deepEqual((state as { room: RoomStateView }).room.policy, {});
});

test("member.remove records project removal, bans, and inbox", async () => {
  const active = signer(1);
  const moderator = signer(5);
  const connector = new LocalConnector(active);
  const room = roomResponse("room1", moderator);
  room.creator = moderator.agentId();
  connector.acceptRoomResponse(HOST, room);

  const join = buildServerRecord("room1", 2, "room-create-head", 111, active.signEvent(
    discourseEvent(eventType.ROOM_JOIN, active.agentId(), 110, 1, "room1", 1, "room-create-head", { role: "speaker" }),
  ));
  connector.applyHostRecord(HOST, join);
  const remove = buildServerRecord("room1", 3, join.hash, 121, moderator.signEvent(
    discourseEvent(eventType.ROOM_MEMBER_REMOVE, moderator.agentId(), 120, 2, "room1", 1, "room-create-head", { member: active.agentId(), ban: true, reason: "spam" }),
  ));
  connector.applyHostRecord(HOST, remove);

  const members = (await connector.callTool(TOOL_ROOM_MEMBERS_LIST, { room_id: "room1", host: HOST, status: "banned" })) as { members: RoomMemberView[] };
  assert.equal(members.members.length, 1);
  assert.equal(members.members[0].left_seq, 3);
  const one = (await connector.callTool(TOOL_ROOM_MEMBERS_LIST, { room_id: "room1", agent_id: active.agentId(), include_recent_activity: true })) as { members: RoomMemberView[]; recent: TimelineItem[] };
  assert.equal(one.members.length, 1);
  assert.equal(one.recent.length, 1);

  const inbox = (await connector.callTool(TOOL_INBOX_NEXT, { room_id: "room1", kinds: ["room.member.removed"], claim: true })) as { items: InboxItem[]; pending_count: number };
  assert.equal(inbox.items[0].reason, "member_banned");
  assert.equal(inbox.pending_count, 0, "a claimed item is leased");
});

test("duplicate room ids across hosts require a host input", async () => {
  const creator = signer(5);
  const connector = new LocalConnector(signer(1));
  connector.acceptRoomResponse("https://a.example.test", roomResponse("room1", creator));
  connector.acceptRoomResponse("https://b.example.test", roomResponse("room1", creator));
  await assert.rejects(connector.callTool(TOOL_ROOM_MEMBERS_LIST, { room_id: "room1" }), /more than one host/);
  const listed = (await connector.callTool(TOOL_ROOM_MEMBERS_LIST, { room_id: "room1", host: "https://b.example.test" })) as { sync: SyncState };
  assert.equal(listed.sync.host, "https://b.example.test");
});

test("delegation writes derive the service from the principal and check policy and ownership first", async () => {
  const active = signer(61), other = signer(62);
  const principalId = `${HOST}/p`;
  let policy: unknown = { scopes: ["draft"], audiences: ["https://dmsg.net"] };
  let previous: unknown;
  let readStatus = 404;
  const posts: unknown[] = [];
  const reads: string[] = [];
  let signatures = 0;
  const signEvent = active.signEvent.bind(active);
  active.signEvent = ((event) => { signatures++; return signEvent(event); }) as typeof active.signEvent;
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    if (url === principalId) return new Response(JSON.stringify({
      id: principalId, protocol: "agent-delegation/1.0", updated_at: Date.now(),
      delegation_query_url: `${HOST}/v1/delegations/query`,
      controllers: [{ id: active.agentId(), source: "local", valid_from: 0, ...(policy === undefined ? {} : { delegation: policy }) }],
    }));
    if (url.endsWith("/.well-known/agent-delegation")) return new Response("{}", { status: 404 });
    if (init?.method === "POST") { posts.push(JSON.parse(init.body as string)); return new Response("{}"); }
    reads.push(url);
    return new Response(JSON.stringify(previous ?? {}), { status: readStatus });
  }) as typeof fetch;
  const connector = new LocalConnector(active, { fetchImpl });
  const input = { principal_id: principalId, id: "del.opaque", subject: other.agentId(), scopes: ["draft"], audiences: ["https://dmsg.net"] };
  await assert.rejects(() => connector.callTool(TOOL_DELEGATION_GRANT, input), /permission denied/);
  await assert.rejects(() => connector.callTool(TOOL_DELEGATIONS_LIST, { delegation_service: HOST }), /permission denied/);
  assert.deepEqual([reads.length, posts.length, signatures], [0, 0, 0], "unapproved services were never read, posted to, or signed for");
  connector.addHost({ host: HOST, allowed: true, features: [] });
  await connector.callTool(TOOL_DELEGATION_GRANT, input);
  assert.equal(reads[0], `${HOST}/v1/delegations/del.opaque`);
  assert.equal(posts.length, 1);
  assert.deepEqual((posts[0] as { event: { payload: unknown } }).event.payload, {
    id: "del.opaque", principal_id: principalId, subject: other.agentId(), scopes: ["draft"], audiences: ["https://dmsg.net"],
  });
  await assert.rejects(() => connector.callTool(TOOL_DELEGATION_GRANT, { ...input, audiences: ["https://tokenlist.ing"] }));
  policy = undefined;
  await assert.rejects(() => connector.callTool(TOOL_DELEGATION_GRANT, input));
  policy = { scopes: ["draft"], audiences: ["https://dmsg.net"] };
  readStatus = 200;
  previous = { id: "del.opaque", principal_id: principalId, subject: other.agentId(), protocol: "agent-delegation/1.0", accepted_at: 1, owner_controller: other.agentId() };
  await assert.rejects(() => connector.callTool(TOOL_DELEGATION_GRANT, input), /own/);
  await assert.rejects(() => connector.callTool(TOOL_DELEGATION_REVOKE, input), /own/);
  readStatus = 503;
  await assert.rejects(() => connector.callTool(TOOL_DELEGATION_GRANT, input));
  assert.equal(posts.length, 1, "denied writes were never submitted");
  assert.equal(signatures, 1, "denied writes were never signed");
});

test("delegation_check verifies each candidate for the requested audience", async () => {
  const controller = signer(71), subject = signer(72);
  const principalId = `${HOST}/p`;
  const document: delegation.PrincipalDocument = {
    id: principalId, protocol: delegation.DELEGATION_PROTOCOL, updated_at: 1000, delegation_query_url: `${HOST}/v1/delegations/query`,
    controllers: [{ id: controller.agentId(), source: "local", valid_from: 0, delegation: { scopes: ["draft"], audiences: ["https://dmsg.net"] } }],
  };
  const envelope = controller.signEvent(delegation.delegationGrantEvent(controller.agentId(), 500, 1, {
    id: "del", principal_id: principalId, subject: subject.agentId(), scopes: ["draft"], audiences: ["https://dmsg.net"],
  }));
  const credential = delegation.materializeDelegationCredential(envelope, { acceptedAt: 600 });
  const forged = { ...credential, id: "forged", scopes: ["draft"], grant_event_id: "x" };
  const fetchImpl = (async (input: string | URL | Request) => {
    const url = String(input);
    if (url === principalId) return new Response(JSON.stringify(document));
    if (url.endsWith("/.well-known/agent-delegation")) return new Response("{}", { status: 404 });
    if (url === `${HOST}/v1/delegations/query`) return new Response(JSON.stringify({ result: [credential, forged] }));
    if (url === `${HOST}/v1/delegations/del/events`) return new Response(JSON.stringify({ result: [{ envelope, accepted_at: 600 }] }));
    if (url === `${HOST}/v1/delegations/forged/events`) return new Response(JSON.stringify({ result: [{ envelope, accepted_at: 600 }] }));
    return new Response("{}", { status: 404 });
  }) as typeof fetch;
  const connector = new LocalConnector(subject, { fetchImpl });
  connector.addHost({ host: HOST, allowed: true });
  const result = (await connector.callTool(TOOL_DELEGATION_CHECK, { principal_id: principalId, audience: "https://dmsg.net" })) as { delegations: delegation.DelegationVerdict[] };
  assert.deepEqual(result.delegations.map((v) => [v.credential.id, v.verified, v.usable]), [["del", true, true], ["forged", false, false]]);
  const other = (await connector.callTool(TOOL_DELEGATION_CHECK, { principal_id: principalId, audience: "https://tokenlist.ing" })) as { delegations: delegation.DelegationVerdict[] };
  assert.deepEqual([other.delegations[0].verified, other.delegations[0].usable], [true, false]);
  await assert.rejects(() => connector.callTool(TOOL_DELEGATION_CHECK, { principal_id: principalId }), /audience is required/);
});
