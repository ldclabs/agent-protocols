// Local Agent Protocols MCP connector.
//
// Transport-neutral: it exposes the standard local connector tool names,
// schemas, structured result types, a JSON dispatcher (`LocalConnector`), and
// local room-state projection. An MCP stdio server can wrap `LocalConnector`
// without giving the agent direct access to signing keys or reusable request
// JWTs.
//
// `LocalConnector` is one deep module. Its implementation is organized into
// submodules under `local-connector/` that vary independently, and this file is
// the module's public interface — a curated re-export of exactly those five:
//   - catalog: the static tool/resource surface advertised to tools/list
//   - views:   the structured result types callers read back
//   - inputs:  the per-tool request shapes
//   - state:   the in-memory store records are projected into
//   - engine:  the LocalConnector class tying signing, HTTP, and projection
//              together
//
// The pure record projection (`projection.ts`) and shared primitives
// (`internal.ts`) are internal seams — used by the engine and its tests, but
// deliberately absent from this interface.

export * from "./local-connector/catalog.js";
export * from "./local-connector/views.js";
export * from "./local-connector/inputs.js";
export * from "./local-connector/state.js";
export * from "./local-connector/engine.js";
