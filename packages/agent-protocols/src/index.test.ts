import assert from "node:assert/strict";
import test from "node:test";

import * as sdk from "./index.js";

test("index re-exports the public surface of every module", () => {
  // errors
  assert.equal(typeof sdk.protocolError, "function");
  assert.equal(typeof sdk.AgentProtocolError, "function");
  // identity
  assert.equal(typeof sdk.AgentSigner, "function");
  assert.equal(sdk.AGENT_ID_PREFIX, "did:agent:");
  // profile
  assert.equal(sdk.PROFILE_PROTOCOL, "agent-profile/1.0");
  assert.equal(typeof sdk.materializeProfile, "function");
  // discourse
  assert.equal(sdk.DISCOURSE_PROTOCOL, "agent-discourse/1.0");
  assert.equal(typeof sdk.TypeRegistry, "function");
  // http-client
  assert.equal(typeof sdk.ProfileClient, "function");
  assert.equal(typeof sdk.DiscourseClient, "function");
  assert.equal(typeof sdk.sseEventsUrl, "function");
  // local-connector
  assert.equal(typeof sdk.standardToolDefinitions, "function");
  assert.equal(
    sdk.TOOL_ROOM_SEND_MESSAGE,
    "agent_protocols_room_send_message",
  );
});
