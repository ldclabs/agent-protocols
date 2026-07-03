import assert from "node:assert/strict";
import test from "node:test";

import { buildServerRecord, discourseEvent, eventType, roomCreateEvent } from "./discourse.js";
import { AgentSigner, withMention } from "./identity.js";
import {
  TOOL_INBOX_NEXT,
  TOOL_ROOM_JOIN,
  TOOL_ROOM_MEMBERS_LIST,
  TOOL_ROOM_SEND_MESSAGE,
  roomSummaryFromResponse,
  standardToolDefinitions,
  syncStateFromRoomResponse,
  timelineItemFromRecord,
} from "./local-connector.js";

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
