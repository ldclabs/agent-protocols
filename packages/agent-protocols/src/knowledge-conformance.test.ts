import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { AgentProtocolError } from "./errors.js";
import {
  AgentSigner,
  canonicalEventBytes,
  parseStrictJson,
  verifyEnvelope,
} from "./identity.js";
import * as k from "./knowledge.js";

const vectors = JSON.parse(
  readFileSync(
    new URL(
      "../../../docs/protocols/agent-knowledge/1.0.vectors.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const schema = JSON.parse(
  readFileSync(
    new URL(
      "../../../docs/protocols/agent-knowledge/1.0.schema.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const service = "https://knowledge.example.com";
const env = (name: string): k.KnowledgeEnvelope =>
  structuredClone(vectors.fixtures[name].envelope);
function mutate(value: any, changes: any[] = []): any {
  const copy = structuredClone(value);
  for (const change of changes) {
    const keys = change.path.slice(1).split("/");
    let parent = copy;
    for (const key of keys.slice(0, -1)) parent = parent[key];
    const key = keys.at(-1);
    if (change.op === "remove") {
      if (Array.isArray(parent)) parent.splice(Number(key), 1);
      else delete parent[key];
    } else parent[key] = structuredClone(change.value);
  }
  return copy;
}
function outcome(fn: () => void): string {
  try {
    fn();
    return "valid";
  } catch (error) {
    if (error instanceof AgentProtocolError) return error.code;
    throw error;
  }
}
function model(accepted: string[] = [], hidden: string[] = []) {
  let clock = vectors.now;
  const store = new k.KnowledgeStore({ service, clock: () => clock });
  for (const name of accepted) store.submit(env(name));
  for (const name of hidden) store.hide(env(name).hash);
  return {
    store,
    advance: (ms: number) => {
      clock += ms;
    },
  };
}
function state(store: k.KnowledgeStore) {
  return { checkpoint: store.checkpoint, known: store.knownEnvelopes() };
}

test("Knowledge bundled schema is identical to normative schema", () =>
  assert.deepEqual(k.KNOWLEDGE_SCHEMA, schema));
for (const [name, fixture] of Object.entries(vectors.fixtures) as [
  string,
  any,
][])
  test(`Knowledge signed fixture: ${name}`, () => {
    verifyEnvelope(fixture.envelope);
    assert.equal(
      Buffer.from(canonicalEventBytes(fixture.envelope.event)).toString(),
      fixture.canonical_event_utf8,
    );
    const signer = AgentSigner.fromSeed(
      Buffer.from(vectors.seeds[fixture.signer], "hex"),
    );
    assert.equal(signer.agentId(), fixture.envelope.event.actor);
    assert.deepEqual(
      signer.signEvent(fixture.envelope.event),
      fixture.envelope,
    );
  });
for (const c of vectors.schema_cases)
  test(`Knowledge schema: ${c.name}`, () =>
    assert.equal(
      outcome(() =>
        k.validateKnowledgeSchema(
          c.value ?? mutate(env(c.fixture), c.changes),
          c.definition,
        ),
      ) === "valid",
      c.valid,
    ));
for (const c of vectors.identity_cases)
  test(`Knowledge identity: ${c.name}`, () =>
    assert.equal(
      outcome(() => {
        if (c.raw_json !== undefined) parseStrictJson(c.raw_json);
        else k.validateKnowledgeEnvelope(mutate(env(c.fixture), c.changes));
      }),
      c.expected,
    ));
for (const c of vectors.object_cases)
  test(`Knowledge object: ${c.name}`, () => {
    const known = new Map<string, k.KnowledgeEnvelope>();
    for (const name of c.accepted) {
      const item = env(name);
      k.validateKnowledgeEnvelope(item);
      k.validateKnowledgeDependencies(item, known);
      known.set(item.hash, item);
    }
    assert.equal(
      outcome(() => {
        const item = env(c.fixture);
        k.validateKnowledgeEnvelope(item);
        try {
          k.validateKnowledgeDependencies(item, known);
        } catch (error) {
          if (
            error instanceof AgentProtocolError &&
            error.code === "missing_dependency"
          )
            assert.deepEqual(error.data, { missing: c.missing });
          throw error;
        }
      }),
      c.expected,
    );
  });
for (const c of vectors.view_cases)
  test(`Knowledge view: ${c.name}`, () => {
    for (const order of c.arrival_orders) {
      const { store } = model();
      const pending: string[] = [];
      for (const name of order) {
        pending.push(name);
        let progress = true;
        while (progress) {
          progress = false;
          for (const candidate of [...pending]) {
            const before = state(store);
            const result = outcome(() => {
              store.submit(env(candidate));
            });
            if (result === "missing_dependency") {
              assert.deepEqual(state(store), before);
              continue;
            }
            assert.equal(result, "valid");
            pending.splice(pending.indexOf(candidate), 1);
            progress = true;
          }
        }
      }
      assert.equal(pending.length, 0);
      assert.deepEqual(
        k.materializeKnowledge(store.knownEnvelopes()),
        c.expected,
      );
      for (const [name, links] of Object.entries(c.expected_relations ?? {}))
        assert.deepEqual(
          (
            store.event(env(name).hash).envelope.event
              .payload as k.KnowledgePublishPayload
          ).relations,
          links,
        );
    }
  });
for (const c of vectors.acceptance_cases)
  test(`Knowledge acceptance: ${c.name}`, () => {
    const { store } = model();
    const receipts = new Map<string, k.KnowledgeRecord>();
    for (const step of c.steps) {
      if (step.withhold) {
        store.hide(env(step.withhold).hash);
        continue;
      }
      const item = env(step.fixture),
        before = state(store);
      let actual = "";
      try {
        const record = store.submit(item, step.now);
        actual = receipts.has(item.hash) ? "resubmission" : "accepted";
        if (actual === "resubmission")
          assert.deepEqual(record, receipts.get(item.hash));
        else {
          assert.equal(record.accepted_at, step.now);
          receipts.set(item.hash, record);
        }
      } catch (error) {
        if (!(error instanceof AgentProtocolError)) throw error;
        actual = error.code;
      }
      assert.equal(actual, step.expected, `${c.name}/${step.fixture}`);
      assert.equal(store.checkpoint, step.seq, `${c.name}/${step.fixture}`);
      if (actual !== "accepted") assert.deepEqual(state(store), before);
    }
  });
for (const c of vectors.evidence_cases)
  test(`Knowledge evidence: ${c.name}`, () =>
    assert.equal(
      k.verifyKnowledgeEvidence(
        c.digest,
        c.representation_hex == null
          ? null
          : Buffer.from(c.representation_hex, "hex"),
      ),
      c.expected,
    ));
for (const c of vectors.query_cases)
  test(`Knowledge query: ${c.name}`, () => {
    assert.equal(
      outcome(() => {
        const request = k.parseKnowledgeQuery(c.parameters);
        assert.deepEqual(
          c.accepted.filter((name: string) =>
            k.knowledgeQueryMatches(env(name), request),
          ),
          c.matches,
        );
      }),
      c.expected,
    );
  });
for (const c of vectors.text_cases)
  test(`Knowledge text: ${c.name}`, () =>
    assert.equal(
      outcome(() => {
        assert.deepEqual(
          k.knowledgeTextTerms(c.text, c.lexical ?? true),
          c.terms,
        );
        if (c.fixture)
          assert.equal(
            k.knowledgeTextMatches(env(c.fixture), c.text),
            c.matches,
          );
      }),
      c.expected,
    ));
for (const c of vectors.batch_cases)
  test(`Knowledge batch: ${c.name}`, () => {
    const { store } = model(c.accepted, c.hidden),
      before = state(store);
    assert.equal(
      outcome(() => {
        const request =
          c.raw_json === undefined
            ? c.request
            : k.parseKnowledgeReadJson(c.raw_json);
        const response = mutate(store.batch(request), c.response_changes);
        k.validateKnowledgeBatchResponse(response, request.hashes, service);
        assert.deepEqual(
          response.result.map((r: k.KnowledgeRecord) => r.envelope.hash),
          c.result,
        );
        assert.deepEqual(response.missing, c.missing);
        assert.equal(response.checkpoint, store.checkpoint);
        assert.equal(response.as_of, vectors.now);
      }),
      c.expected,
    );
    assert.deepEqual(state(store), before);
  });
for (const c of vectors.search_cases)
  test(`Knowledge search: ${c.name}`, () => {
    const { store } = model(c.accepted, c.hidden),
      before = state(store);
    assert.equal(
      outcome(() => {
        const request =
          c.raw_json === undefined
            ? c.request
            : k.parseKnowledgeReadJson(c.raw_json);
        k.validateKnowledgeSearchRequest(request, c.modes);
        const response = mutate(
          store.search(
            request,
            {
              candidates: (c.candidates ?? []).map(
                (name: string) => env(name).hash,
              ),
              ranking: c.ranking ?? { mode: request.mode, id: "fixture-v1" },
              coverage: c.coverage ?? { exhaustive: true, reasons: [] },
            },
            c.modes,
          ),
          c.response_changes,
        );
        k.validateKnowledgeSearchResponse(response, request, service);
        assert.deepEqual(
          response.result.map(
            (r: k.KnowledgeSearchHit) => r.record.envelope.hash,
          ),
          c.result ?? [],
        );
      }),
      c.expected,
    );
    assert.deepEqual(state(store), before);
  });
for (const c of vectors.pagination_cases)
  test(`Knowledge pagination: ${c.name}`, () => {
    const { store, advance } = model(c.accepted, c.hidden);
    let previous: any;
    let tracker: k.KnowledgePageTracker;
    for (const step of c.steps) {
      for (const name of step.add ?? []) store.submit(env(name));
      for (const name of step.hide ?? []) store.hide(env(name).hash);
      advance(step.advance_ms ?? 0);
      assert.equal(
        outcome(() => {
          const request = k.parseKnowledgeQuery(step.parameters);
          if (step.continue) request.cursor = previous.next_cursor;
          else tracker = new k.KnowledgePageTracker(service);
          const response = mutate(store.query(request), step.response_changes);
          tracker.accept(request, response);
          assert.deepEqual(
            response.result.map((r: k.KnowledgeRecord) => r.envelope.hash),
            step.matches.map((name: string) => env(name).hash),
          );
          assert.equal(response.next_cursor !== undefined, step.more);
          previous = response;
        }),
        step.expected,
        `${c.name}: ${JSON.stringify(step)}`,
      );
    }
  });
for (const c of vectors.discovery_cases)
  test(`Knowledge discovery: ${c.name}`, () =>
    assert.equal(
      outcome(() =>
        k.validateKnowledgeDiscovery(c.document, c.origin ?? service),
      ),
      c.expected,
    ));
