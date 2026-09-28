/**
 * Agent Knowledge 1.0. Signatures establish attribution, never scientific truth.
 * Knowledge events are immutable, portable objects: acceptance never consults a
 * live-write nonce cache, and nothing is fetched or executed implicitly.
 */
import { createHash } from "node:crypto";
import canonicalize from "canonicalize";
import { Validator, type Schema } from "@cfworker/json-schema";
import { protocolError } from "./errors.js";
import {
  AgentId,
  Envelope,
  Event,
  createEvent,
  parseStrictJson,
  validateOrigin,
  verifyEnvelope,
} from "./identity.js";
import { KNOWLEDGE_SCHEMA } from "./knowledge-schema.js";

export { KNOWLEDGE_SCHEMA } from "./knowledge-schema.js";
export const KNOWLEDGE_PROTOCOL = "agent-knowledge/1.0";
export const KNOWLEDGE_ERROR_CODES = [
  "missing_dependency",
  "invalid_target",
  "invalid_cursor",
  "query_too_broad",
  "query_unavailable",
  "unsupported_search_mode",
] as const;
export const KNOWLEDGE_EVENT_TYPES = [
  "knowledge.publish",
  "knowledge.assess",
  "knowledge.retract",
] as const;
export const KNOWLEDGE_KINDS = [
  "question",
  "hypothesis",
  "definition",
  "observation",
  "inference",
  "procedure",
  "resource",
  "negative_result",
  "synthesis",
  "collection",
] as const;
export const KNOWLEDGE_RELATIONS = [
  "derived_from",
  "addresses",
  "tests",
  "extends",
  "supports",
  "contradicts",
  "supersedes",
  "contains",
] as const;
export const KNOWLEDGE_VERDICTS = [
  "supports",
  "challenges",
  "reproduced",
  "not_reproduced",
  "applied",
  "inconclusive",
] as const;
export const KNOWLEDGE_SEARCH_MODES = [
  "lexical",
  "semantic",
  "hybrid",
] as const;
/** Default allowance for `created_at` ahead of the receiver clock. */
export const DEFAULT_FUTURE_SKEW_MS = 300_000;
export const DEFAULT_MAX_ENVELOPE_BYTES = 262_144;
/** Relationships that may point at an assessment as well as a publication. */
const ASSESSMENT_RELATIONS: readonly string[] = [
  "derived_from",
  "supports",
  "contradicts",
];

export type KnowledgeKind = (typeof KNOWLEDGE_KINDS)[number];
export type KnowledgeRelationType = (typeof KNOWLEDGE_RELATIONS)[number];
export type KnowledgeVerdict = (typeof KNOWLEDGE_VERDICTS)[number];
export type KnowledgeSearchMode = (typeof KNOWLEDGE_SEARCH_MODES)[number];
export interface KnowledgeContext {
  scope: string;
  conditions: string[];
  limitations: string[];
}
export interface KnowledgeReproduction {
  environment: string;
  steps: string[];
  expected: string;
  observed?: string;
}
export interface KnowledgeEvidence {
  url: string;
  description: string;
  digest?: string;
  media_type?: string;
  role?: "source" | "input" | "output" | "environment" | "validation";
}
export interface KnowledgeProfileBinding {
  profile: { url: string; digest: string };
  data: Record<string, unknown>;
}
export interface KnowledgeRelation {
  relation: KnowledgeRelationType;
  target: string;
}
interface KnowledgeLicensedPayload {
  license: string;
  extra?: Record<string, unknown>;
}
interface KnowledgeResearchPayload extends KnowledgeLicensedPayload {
  context: KnowledgeContext;
  basis: string;
  evidence?: KnowledgeEvidence[];
  reproduction?: KnowledgeReproduction;
  profiles?: KnowledgeProfileBinding[];
}
export interface KnowledgePublishPayload extends KnowledgeResearchPayload {
  kind: KnowledgeKind;
  title: string;
  statement: string;
  language: string;
  relations?: KnowledgeRelation[];
  tags?: string[];
}
export interface KnowledgeAssessPayload extends KnowledgeResearchPayload {
  target: string;
  verdict: KnowledgeVerdict;
  summary: string;
}
export interface KnowledgeRetractPayload extends KnowledgeLicensedPayload {
  target: string;
  reason: string;
}
export type KnowledgePayload =
  KnowledgePublishPayload | KnowledgeAssessPayload | KnowledgeRetractPayload;
export type KnowledgeEnvelope = Envelope<KnowledgePayload>;
export interface KnowledgeRecord {
  envelope: KnowledgeEnvelope;
  accepted_at: number;
  seq: number;
  [key: string]: unknown;
}
export interface KnowledgeFilters {
  actor?: AgentId;
  type?: (typeof KNOWLEDGE_EVENT_TYPES)[number];
  kind?: KnowledgeKind;
  target?: string;
  relation?: KnowledgeRelationType;
  tag?: string;
  profile?: string;
  language?: string;
  verdict?: KnowledgeVerdict;
  created_from?: number;
  created_before?: number;
}
export interface KnowledgeQuery extends KnowledgeFilters {
  q?: string;
  after_seq?: number;
  limit?: number;
  cursor?: string;
}
export interface KnowledgeScope {
  service: string;
  checkpoint: number;
  as_of: number;
}
export interface KnowledgeQueryResponse extends KnowledgeScope {
  result: KnowledgeRecord[];
  next_cursor?: string;
  [key: string]: unknown;
}
export interface KnowledgeBatchRequest {
  hashes: string[];
}
export interface KnowledgeBatchResponse extends KnowledgeScope {
  result: KnowledgeRecord[];
  missing: string[];
  [key: string]: unknown;
}
export interface KnowledgeSearchRequest {
  text: string;
  mode: KnowledgeSearchMode;
  filters?: KnowledgeFilters;
  limit?: number;
}
export interface KnowledgeRanking {
  mode: KnowledgeSearchMode;
  id: string;
  [key: string]: unknown;
}
export interface KnowledgeCoverage {
  exhaustive: boolean;
  reasons: ("candidate_limit" | "index_lag" | "approximate" | "timeout")[];
  [key: string]: unknown;
}
export interface KnowledgeSearchHit {
  record: KnowledgeRecord;
  explanation: string;
  [key: string]: unknown;
}
export interface KnowledgeSearchResponse extends KnowledgeScope {
  result: KnowledgeSearchHit[];
  ranking: KnowledgeRanking;
  coverage: KnowledgeCoverage;
  [key: string]: unknown;
}
export interface KnowledgeEndpoints {
  events: string;
  query: string;
  batch: string;
  search?: string;
}
export interface KnowledgeDiscovery {
  protocol: typeof KNOWLEDGE_PROTOCOL;
  service: string;
  endpoints?: Partial<KnowledgeEndpoints>;
  features?: string[];
  search_modes?: string[];
  peers?: string[];
  limits?: Record<string, number>;
  [key: string]: unknown;
}

export function knowledgePublishEvent(
  actor: AgentId,
  createdAt: number,
  nonce: number,
  payload: KnowledgePublishPayload,
): Event<KnowledgePublishPayload> {
  return createEvent(
    KNOWLEDGE_PROTOCOL,
    "knowledge.publish",
    actor,
    createdAt,
    nonce,
    payload,
  );
}
export function knowledgeAssessEvent(
  actor: AgentId,
  createdAt: number,
  nonce: number,
  payload: KnowledgeAssessPayload,
): Event<KnowledgeAssessPayload> {
  return createEvent(
    KNOWLEDGE_PROTOCOL,
    "knowledge.assess",
    actor,
    createdAt,
    nonce,
    payload,
  );
}
export function knowledgeRetractEvent(
  actor: AgentId,
  createdAt: number,
  nonce: number,
  payload: KnowledgeRetractPayload,
): Event<KnowledgeRetractPayload> {
  return createEvent(
    KNOWLEDGE_PROTOCOL,
    "knowledge.retract",
    actor,
    createdAt,
    nonce,
    payload,
  );
}
const validators = new Map<string, Validator>();
/** Structure only. Signatures, canonical encodings and references are separate checks. */
export function validateKnowledgeSchema(
  value: unknown,
  definition = "signedEnvelope",
  code = "invalid_event",
): void {
  let validator = validators.get(definition);
  if (!validator) {
    if (!Object.hasOwn(KNOWLEDGE_SCHEMA.$defs, definition))
      throw protocolError(code, "unknown schema definition");
    validator = new Validator(
      {
        $ref: `#/$defs/${definition}`,
        $defs: KNOWLEDGE_SCHEMA.$defs,
      } as Schema,
      "2020-12",
      true,
    );
    validators.set(definition, validator);
  }
  jsonCheck(value, code);
  if (!validator.validate(value).valid)
    throw protocolError(code, `invalid ${definition} structure`);
}
function jsonCheck(value: unknown, code = "invalid_event"): void {
  try {
    const visited = new Set<object>();
    const inspect = (input: unknown, depth: number): void => {
      if (depth > 256) throw new Error("nesting limit");
      if (
        input === null ||
        typeof input === "boolean" ||
        typeof input === "string"
      )
        return;
      if (typeof input === "number") {
        if (
          !Number.isFinite(input) ||
          (Number.isInteger(input) && !Number.isSafeInteger(input))
        )
          throw new Error("invalid number");
        return;
      }
      if (typeof input !== "object" || visited.has(input))
        throw new Error("non-JSON value");
      const prototype = Object.getPrototypeOf(input);
      if (
        !Array.isArray(input) &&
        prototype !== null &&
        prototype !== Object.prototype
      )
        throw new Error("non-JSON object");
      visited.add(input);
      if (Array.isArray(input))
        for (let i = 0; i < input.length; i++) inspect(input[i], depth + 1);
      else
        for (const key of Reflect.ownKeys(input)) {
          const descriptor = Object.getOwnPropertyDescriptor(input, key)!;
          if (
            typeof key !== "string" ||
            !descriptor.enumerable ||
            !("value" in descriptor)
          )
            throw new Error("non-JSON member");
          inspect(descriptor.value, depth + 1);
        }
      visited.delete(input);
    };
    inspect(value, 0);
    const text = JSON.stringify(value);
    if (text === undefined) throw new Error();
    parseStrictJson(text);
  } catch {
    throw protocolError(code, "value violates strict I-JSON");
  }
}
export function validateKnowledgeId(
  value: unknown,
  code = "invalid_event",
): asserts value is string {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(value) ||
    Buffer.from(value, "base64url").toString("base64url") !== value
  )
    throw protocolError(code, "ID must canonically encode 32 bytes");
}
function https(value: string, code = "invalid_event"): URL {
  try {
    const u = new URL(value);
    if (
      u.protocol !== "https:" ||
      !u.hostname ||
      u.username ||
      u.password ||
      /[\\\x00-\x20]/.test(value)
    )
      throw new Error();
    return u;
  } catch {
    throw protocolError(
      code,
      "URL requires absolute HTTPS, a host and no userinfo",
    );
  }
}
const sha3 = (bytes: Uint8Array | string): string =>
  createHash("sha3-256").update(bytes).digest("base64url");
/** Sorted, distinct direct dependencies. */
export function knowledgeDependencies(item: KnowledgeEnvelope): string[] {
  return item.event.type === "knowledge.publish"
    ? [
        ...new Set(
          (item.event.payload as KnowledgePublishPayload).relations?.map(
            (link) => link.target,
          ) ?? [],
        ),
      ].sort()
    : [
        (item.event.payload as KnowledgeAssessPayload | KnowledgeRetractPayload)
          .target,
      ];
}
/** Structure, Identity hash/signature, URLs, canonical IDs and profile uniqueness. Dependencies are separate. */
export function validateKnowledgeEnvelope(
  value: unknown,
): asserts value is KnowledgeEnvelope {
  validateKnowledgeSchema(value);
  const item = value as KnowledgeEnvelope;
  verifyEnvelope(item);
  validateKnowledgeId(item.hash);
  const payload = item.event.payload;
  https(payload.license);
  if ("evidence" in payload)
    for (const ref of payload.evidence ?? []) {
      https(ref.url);
      if (ref.digest !== undefined) validateKnowledgeId(ref.digest);
    }
  if ("profiles" in payload) {
    const seen = new Set<string>();
    for (const binding of payload.profiles ?? []) {
      https(binding.profile.url);
      validateKnowledgeId(binding.profile.digest);
      if (seen.has(binding.profile.digest))
        throw protocolError("invalid_event", "duplicate profile digest");
      seen.add(binding.profile.digest);
    }
  }
  for (const target of knowledgeDependencies(item)) validateKnowledgeId(target);
}
export function parseKnowledgeEnvelope(text: string): KnowledgeEnvelope {
  const value = parseStrictJson(text);
  validateKnowledgeEnvelope(value);
  return value;
}
export type KnowledgeKnownSet =
  | ReadonlyMap<string, KnowledgeEnvelope>
  | Readonly<Record<string, KnowledgeEnvelope>>;
function knownMap(
  known: KnowledgeKnownSet,
): ReadonlyMap<string, KnowledgeEnvelope> {
  return known instanceof Map ? known : new Map(Object.entries(known));
}
/** Check target rules against retained envelopes that already passed validation. */
export function validateKnowledgeDependencies(
  item: KnowledgeEnvelope,
  known: KnowledgeKnownSet,
): void {
  const retained = knownMap(known);
  checkDependencies(item, (id) => retained.get(id));
}
function checkDependencies(
  item: KnowledgeEnvelope,
  lookup: (id: string) => KnowledgeEnvelope | undefined,
): void {
  const missing = knowledgeDependencies(item).filter(
    (id) => lookup(id) === undefined,
  );
  if (missing.length)
    throw protocolError("missing_dependency", "unresolved dependencies", {
      missing,
    });
  const links =
    item.event.type === "knowledge.publish"
      ? ((item.event.payload as KnowledgePublishPayload).relations ?? [])
      : [
          {
            relation: item.event.type,
            target: (
              item.event.payload as
                KnowledgeAssessPayload | KnowledgeRetractPayload
            ).target,
          },
        ];
  for (const link of links) {
    const target = lookup(link.target)!.event;
    const allowed =
      link.relation === "knowledge.retract" ||
      ASSESSMENT_RELATIONS.includes(link.relation)
        ? ["knowledge.publish", "knowledge.assess"]
        : ["knowledge.publish"];
    if (!allowed.includes(target.type))
      throw protocolError("invalid_target", "wrong target type");
    const kind =
      link.relation === "addresses"
        ? "question"
        : link.relation === "tests"
          ? "hypothesis"
          : undefined;
    if (kind && (target.payload as KnowledgePublishPayload).kind !== kind)
      throw protocolError("invalid_target", "wrong target contribution kind");
    if (
      ["supersedes", "knowledge.retract"].includes(link.relation) &&
      (target.actor !== item.event.actor || target.nonce >= item.event.nonce)
    )
      throw protocolError(
        "invalid_target",
        "target requires same actor and smaller nonce",
      );
  }
}
export interface KnowledgeView {
  status: "active" | "retracted";
  successors?: string[];
  assessments?: string[];
  active_assessments?: string[];
}
/** Validates a dependency-closed dataset, then derives order-independent local facts. */
export function materializeKnowledge(
  known: KnowledgeKnownSet,
): Record<string, KnowledgeView> {
  const retained = knownMap(known);
  for (const [id, item] of retained) {
    validateKnowledgeEnvelope(item);
    if (id !== item.hash)
      throw protocolError("invalid_event", "dataset ID mismatch");
  }
  for (const item of retained.values())
    validateKnowledgeDependencies(item, retained);
  const withdrawn = new Set<string>();
  const successors = new Map<string, Set<string>>();
  const assessments = new Map<string, Set<string>>();
  const append = (
    index: Map<string, Set<string>>,
    target: string,
    id: string,
  ): void => {
    let ids = index.get(target);
    if (!ids) {
      ids = new Set();
      index.set(target, ids);
    }
    ids.add(id);
  };
  for (const [id, item] of retained) {
    if (item.event.type === "knowledge.retract")
      withdrawn.add((item.event.payload as KnowledgeRetractPayload).target);
    else if (item.event.type === "knowledge.assess")
      append(
        assessments,
        (item.event.payload as KnowledgeAssessPayload).target,
        id,
      );
    else
      for (const link of (item.event.payload as KnowledgePublishPayload)
        .relations ?? [])
        if (link.relation === "supersedes") append(successors, link.target, id);
  }
  const result: Record<string, KnowledgeView> = {};
  for (const [id, item] of [...retained.entries()].sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  )) {
    if (item.event.type === "knowledge.retract") continue;
    const view: KnowledgeView = {
      status: withdrawn.has(id) ? "retracted" : "active",
    };
    if (item.event.type === "knowledge.publish") {
      view.successors = [...(successors.get(id) ?? [])].sort();
      view.assessments = [...(assessments.get(id) ?? [])].sort();
      view.active_assessments = view.assessments.filter(
        (key) => !withdrawn.has(key),
      );
    }
    result[id] = view;
  }
  return result;
}
export type KnowledgeEvidenceStatus =
  "unchecked" | "matched" | "mismatched" | "unavailable";
/**
 * Compare a digest with complete representation bytes (after transfer/content
 * decoding, before text conversion). Pass `null` or `undefined` bytes when the
 * complete representation could not be obtained. No fetching occurs.
 */
export function verifyKnowledgeEvidence(
  digest: string | undefined,
  bytes?: Uint8Array | null,
): KnowledgeEvidenceStatus {
  if (digest === undefined) return "unchecked";
  validateKnowledgeId(digest);
  if (bytes == null) return "unavailable";
  return sha3(bytes) === digest ? "matched" : "mismatched";
}
const fold = (value: string) =>
  value.replace(/[A-Z]/g, (char) => char.toLowerCase());
export function knowledgeTextTerms(value: unknown, lexical = true): string[] {
  if (
    typeof value !== "string" ||
    [...value].length < 1 ||
    [...value].length > 1024 ||
    /[\uD800-\uDFFF]/u.test(value)
  )
    throw protocolError(
      "invalid_request",
      "text requires 1..1024 Unicode scalars",
    );
  const terms = value.split(/[\x09-\x0d\x20]+/).filter(Boolean);
  if (!terms.length || (lexical && terms.length > 16))
    throw protocolError(
      "invalid_request",
      "empty text or too many lexical terms",
    );
  return terms.map(fold);
}
export function knowledgeTextMatches(
  item: KnowledgeEnvelope,
  text: string,
): boolean {
  const p = item.event.payload;
  let fields: string[];
  if (item.event.type === "knowledge.retract")
    fields = [(p as KnowledgeRetractPayload).reason];
  else {
    const r = p as KnowledgeResearchPayload;
    fields =
      item.event.type === "knowledge.publish"
        ? [
            (p as KnowledgePublishPayload).title,
            (p as KnowledgePublishPayload).statement,
            r.basis,
          ]
        : [(p as KnowledgeAssessPayload).summary, r.basis];
    fields.push(
      r.context.scope,
      ...r.context.conditions,
      ...r.context.limitations,
    );
  }
  const folded = fields.map(fold);
  return knowledgeTextTerms(text).every((term) =>
    folded.some((field) => field.includes(term)),
  );
}
function filterCheck(filters: KnowledgeFilters): void {
  validateKnowledgeSchema(filters, "searchFilters", "invalid_request");
  for (const key of ["actor", "target", "profile"] as const)
    if (filters[key] !== undefined)
      validateKnowledgeId(
        key === "actor" ? filters[key]!.slice(10) : filters[key],
        "invalid_request",
      );
  if (
    filters.created_from !== undefined &&
    filters.created_before !== undefined &&
    filters.created_from >= filters.created_before
  )
    throw protocolError("invalid_request", "time range must be nonempty");
}
export function validateKnowledgeQuery(
  value: unknown,
): asserts value is KnowledgeQuery {
  validateKnowledgeSchema(value, "queryRequest", "invalid_request");
  const {
    q,
    limit: _l,
    cursor: _c,
    after_seq: _a,
    ...filters
  } = value as KnowledgeQuery;
  filterCheck(filters);
  if (q !== undefined) knowledgeTextTerms(q);
}
const INTEGER_PARAMETERS = [
  "created_from",
  "created_before",
  "after_seq",
  "limit",
];
/** Parse decoded HTTP pairs without discarding duplicate parameter names. */
export function parseKnowledgeQuery(
  parameters: Iterable<readonly [string, string]> | URLSearchParams,
): KnowledgeQuery {
  const result: Record<string, unknown> = {};
  for (const [key, input] of parameters) {
    if (
      Object.hasOwn(result, key) ||
      !Object.hasOwn(KNOWLEDGE_SCHEMA.$defs.queryRequest.properties, key)
    )
      throw protocolError(
        "invalid_request",
        "unknown or repeated query parameter",
      );
    let value: unknown = input;
    if (INTEGER_PARAMETERS.includes(key)) {
      if (!/^[0-9]+$/.test(input) || input.replace(/^0+/, "").length > 16)
        throw protocolError(
          "invalid_request",
          "HTTP integers require decimal digits",
        );
      value = Number(input);
    }
    Object.defineProperty(result, key, { value, enumerable: true });
  }
  validateKnowledgeQuery(result);
  return result;
}
/** Exact filter and text predicate; `after_seq`, `limit` and `cursor` are not payload filters. */
export function knowledgeQueryMatches(
  item: KnowledgeEnvelope,
  filters: KnowledgeQuery | KnowledgeFilters,
): boolean {
  const event = item.event,
    p = event.payload,
    publication = event.type === "knowledge.publish",
    pub = p as KnowledgePublishPayload;
  if (
    (filters.actor !== undefined && event.actor !== filters.actor) ||
    (filters.type !== undefined && event.type !== filters.type)
  )
    return false;
  if (
    "q" in filters &&
    filters.q !== undefined &&
    !knowledgeTextMatches(item, filters.q)
  )
    return false;
  if (
    filters.language !== undefined &&
    (!publication || fold(pub.language) !== fold(filters.language))
  )
    return false;
  if (
    filters.verdict !== undefined &&
    (event.type !== "knowledge.assess" ||
      (p as KnowledgeAssessPayload).verdict !== filters.verdict)
  )
    return false;
  if (
    (filters.created_from !== undefined &&
      event.created_at < filters.created_from) ||
    (filters.created_before !== undefined &&
      event.created_at >= filters.created_before)
  )
    return false;
  if (filters.kind !== undefined && (!publication || pub.kind !== filters.kind))
    return false;
  if (
    filters.tag !== undefined &&
    (!publication || !pub.tags?.includes(filters.tag))
  )
    return false;
  if (
    filters.profile !== undefined &&
    !(p as KnowledgeResearchPayload).profiles?.some(
      (b) => b.profile.digest === filters.profile,
    )
  )
    return false;
  if (filters.relation !== undefined) {
    if (
      !publication ||
      !pub.relations?.some(
        (r) =>
          r.relation === filters.relation &&
          (filters.target === undefined || r.target === filters.target),
      )
    )
      return false;
  } else if (
    filters.target !== undefined &&
    !knowledgeDependencies(item).includes(filters.target)
  )
    return false;
  return true;
}
export function parseKnowledgeReadJson(raw: string): unknown {
  try {
    return parseStrictJson(raw);
  } catch {
    throw protocolError("invalid_request", "read body violates strict I-JSON");
  }
}
export function validateKnowledgeBatchRequest(
  value: unknown,
): asserts value is KnowledgeBatchRequest {
  validateKnowledgeSchema(value, "batchRequest", "invalid_request");
  for (const id of (value as KnowledgeBatchRequest).hashes)
    validateKnowledgeId(id, "invalid_request");
}
/** An unadvertised mode is `unsupported_search_mode` and is never substituted. */
export function validateKnowledgeSearchRequest(
  value: unknown,
  modes: readonly string[] = KNOWLEDGE_SEARCH_MODES,
): asserts value is KnowledgeSearchRequest {
  jsonCheck(value, "invalid_request");
  const mode = (value as KnowledgeSearchRequest | null)?.mode;
  if (
    typeof mode === "string" &&
    (!(KNOWLEDGE_SEARCH_MODES as readonly string[]).includes(mode) ||
      !modes.includes(mode))
  )
    throw protocolError(
      "unsupported_search_mode",
      "requested mode is not advertised",
    );
  validateKnowledgeSchema(value, "searchRequest", "invalid_request");
  const request = value as KnowledgeSearchRequest;
  knowledgeTextTerms(request.text, mode === "lexical");
  filterCheck(request.filters ?? {});
}
export function validateKnowledgeRecord(
  value: unknown,
  expectedId?: string,
): asserts value is KnowledgeRecord {
  validateKnowledgeSchema(value, "acceptanceRecord", "invalid_response");
  const record = value as KnowledgeRecord;
  try {
    validateKnowledgeEnvelope(record.envelope);
  } catch {
    throw protocolError("invalid_response", "invalid returned envelope");
  }
  if (expectedId !== undefined && record.envelope.hash !== expectedId)
    throw protocolError(
      "invalid_response",
      "returned envelope ID does not match request",
    );
}
function responseRecords(
  value: unknown,
  definition: string,
  service: string,
): KnowledgeRecord[] {
  validateKnowledgeSchema(value, definition, "invalid_response");
  const response = value as
    KnowledgeQueryResponse | KnowledgeBatchResponse | KnowledgeSearchResponse;
  try {
    validateOrigin(response.service);
  } catch {
    throw protocolError("invalid_response", "noncanonical service origin");
  }
  if (response.service !== service)
    throw protocolError(
      "invalid_response",
      "response service differs from receiving origin",
    );
  const records =
    definition === "searchResponse"
      ? (response as KnowledgeSearchResponse).result.map((hit) => hit.record)
      : (response as KnowledgeQueryResponse).result;
  const ids = new Set<string>();
  for (const record of records) {
    if (record.seq > response.checkpoint || ids.has(record.envelope.hash))
      throw protocolError(
        "invalid_response",
        "duplicate event or record beyond checkpoint",
      );
    ids.add(record.envelope.hash);
    validateKnowledgeRecord(record);
  }
  return records;
}
export function validateKnowledgeQueryResponse(
  value: unknown,
  request: KnowledgeQuery,
  service: string,
): asserts value is KnowledgeQueryResponse {
  const records = responseRecords(value, "queryResponse", service);
  if (records.length > (request.limit ?? 100))
    throw protocolError("invalid_response", "query page exceeds limit");
  let previous = request.after_seq ?? 0;
  for (const record of records) {
    if (
      record.seq <= previous ||
      !knowledgeQueryMatches(record.envelope, request)
    )
      throw protocolError(
        "invalid_response",
        "query violated order or exact filters",
      );
    previous = record.seq;
  }
}
export function validateKnowledgeBatchResponse(
  value: unknown,
  hashes: readonly string[],
  service: string,
): asserts value is KnowledgeBatchResponse {
  const result = responseRecords(value, "batchResponse", service).map(
      (r) => r.envelope.hash,
    ),
    missing = (value as KnowledgeBatchResponse).missing;
  if (
    result.some((id) => missing.includes(id)) ||
    new Set([...result, ...missing]).size !== hashes.length ||
    [...result, ...missing].some((id) => !hashes.includes(id)) ||
    canonicalize(result) !==
      canonicalize(hashes.filter((id) => result.includes(id))) ||
    canonicalize(missing) !==
      canonicalize(hashes.filter((id) => missing.includes(id)))
  )
    throw protocolError(
      "invalid_response",
      "batch must form complete ordered partition",
    );
}
export function validateKnowledgeSearchResponse(
  value: unknown,
  request: KnowledgeSearchRequest,
  service: string,
): asserts value is KnowledgeSearchResponse {
  const records = responseRecords(value, "searchResponse", service);
  const response = value as KnowledgeSearchResponse;
  if (
    records.length > (request.limit ?? 20) ||
    response.ranking.mode !== request.mode
  )
    throw protocolError("invalid_response", "search limit or mode mismatch");
  for (const record of records)
    if (
      !knowledgeQueryMatches(record.envelope, request.filters ?? {}) ||
      (request.mode === "lexical" &&
        !knowledgeTextMatches(record.envelope, request.text))
    )
      throw protocolError(
        "invalid_response",
        "search violated exact filters or lexical text",
      );
}
export function validateKnowledgeDiscovery(
  value: unknown,
  origin: string,
): asserts value is KnowledgeDiscovery {
  validateKnowledgeSchema(value, "discoveryDocument", "invalid_discovery");
  const d = value as KnowledgeDiscovery;
  try {
    validateOrigin(origin);
    validateOrigin(d.service);
    if (d.service !== origin) throw new Error();
    for (const endpoint of Object.values(d.endpoints ?? {})) {
      const url = https(endpoint);
      if (url.origin !== origin || url.search || url.hash) throw new Error();
    }
    for (const peer of d.peers ?? []) {
      validateOrigin(peer);
      if (peer === origin) throw new Error();
    }
  } catch {
    throw protocolError(
      "invalid_discovery",
      "invalid service, endpoint or peer",
    );
  }
}

/** Effective request for cursor binding: no cursor, defaults applied. */
function queryBinding(request: KnowledgeQuery): string {
  const { cursor: _c, ...rest } = request;
  return canonicalize({
    ...rest,
    limit: request.limit ?? 100,
    after_seq: request.after_seq ?? 0,
  })!;
}

/** Verifies that query pages form one complete, consistent enumeration. */
export class KnowledgePageTracker {
  private binding?: string;
  private scope?: string;
  private last = 0;
  private next?: string;
  private readonly seen = new Set<string>();
  constructor(readonly service: string) {
    validateOrigin(service);
  }
  get complete(): boolean {
    return this.binding !== undefined && this.next === undefined;
  }
  /** The next poll's `after_seq`, available only after every page was consumed. */
  get checkpoint(): number | undefined {
    return this.complete ? JSON.parse(this.scope!).checkpoint : undefined;
  }
  accept(request: KnowledgeQuery, response: KnowledgeQueryResponse): void {
    validateKnowledgeQuery(request);
    validateKnowledgeQueryResponse(response, request, this.service);
    const binding = queryBinding(request);
    const scope = canonicalize({
      service: response.service,
      checkpoint: response.checkpoint,
      as_of: response.as_of,
    })!;
    if (this.binding === undefined) {
      if (request.cursor !== undefined)
        throw protocolError(
          "invalid_response",
          "a traversal must start without a cursor",
        );
      this.last = request.after_seq ?? 0;
    } else if (
      this.next === undefined ||
      request.cursor !== this.next ||
      binding !== this.binding ||
      scope !== this.scope
    )
      throw protocolError(
        "invalid_response",
        "pagination request or checkpoint scope changed",
      );
    const first = response.result[0];
    if (
      (first !== undefined && first.seq <= this.last) ||
      response.result.some((record) => this.seen.has(record.envelope.hash))
    )
      throw protocolError(
        "invalid_response",
        "pagination repeated an event or moved backwards",
      );
    for (const record of response.result) this.seen.add(record.envelope.hash);
    if (response.result.length) this.last = response.result.at(-1)!.seq;
    this.binding = binding;
    this.scope = scope;
    this.next = response.next_cursor;
  }
}

export interface KnowledgeStoreOptions {
  service: string;
  clock?: () => number;
  /** Allowance for `created_at` ahead of the clock; there is no lower bound. */
  futureSkewMs?: number;
  maxEnvelopeBytes?: number;
  /** Runs for each new acceptance after protocol checks; throw to refuse. */
  admit?: (envelope: KnowledgeEnvelope) => void;
}
export interface KnowledgeSearchSelection {
  /** Ranked event IDs. Candidates must be visible and satisfy all exact filters. */
  candidates: readonly string[];
  ranking: KnowledgeRanking;
  coverage: KnowledgeCoverage;
  explanations?: Readonly<Record<string, string>>;
}
/**
 * Synchronous in-memory reference service engine with checkpoint-bound,
 * stateless query cursors. Applications supply persistence and HTTP policy.
 */
export class KnowledgeStore {
  readonly service: string;
  private readonly clock: () => number;
  private readonly futureSkewMs: number;
  private readonly maxEnvelopeBytes: number;
  private readonly admit?: (envelope: KnowledgeEnvelope) => void;
  /** Insertion order is ascending seq: new records always get a larger seq. */
  private readonly records = new Map<string, KnowledgeRecord>();
  private readonly hidden = new Set<string>();
  private highWater = 0;
  constructor(options: KnowledgeStoreOptions) {
    validateOrigin(options.service);
    this.service = options.service;
    this.clock = options.clock ?? Date.now;
    this.futureSkewMs = options.futureSkewMs ?? DEFAULT_FUTURE_SKEW_MS;
    this.maxEnvelopeBytes =
      options.maxEnvelopeBytes ?? DEFAULT_MAX_ENVELOPE_BYTES;
    this.admit = options.admit;
    for (const [name, value] of [
      ["futureSkewMs", this.futureSkewMs],
      ["maxEnvelopeBytes", this.maxEnvelopeBytes],
    ] as const)
      if (!Number.isSafeInteger(value) || value < 0)
        throw protocolError("invalid_request", `invalid store option ${name}`);
  }
  get checkpoint(): number {
    return this.highWater;
  }
  private now(): number {
    const now = this.clock();
    if (!Number.isSafeInteger(now) || now < 0)
      throw protocolError("invalid_request", "invalid service clock");
    return now;
  }
  private visible(id: string): boolean {
    return this.records.has(id) && !this.hidden.has(id);
  }
  /** Publicly visible envelopes keyed by event ID; copies cannot mutate storage. */
  knownEnvelopes(): Map<string, KnowledgeEnvelope> {
    return new Map(
      [...this.records]
        .filter(([id]) => this.visible(id))
        .map(([id, record]) => [id, structuredClone(record.envelope)]),
    );
  }
  /** Accept a signed event, or return the original record of an exact resubmission. */
  submit(envelope: KnowledgeEnvelope, now = this.now()): KnowledgeRecord {
    if (!Number.isSafeInteger(now) || now < 0)
      throw protocolError("invalid_request", "invalid service clock");
    const copy = structuredClone(envelope);
    validateKnowledgeEnvelope(copy);
    const retained = this.records.get(copy.hash);
    if (retained) return structuredClone(retained);
    if (copy.event.created_at > now + this.futureSkewMs)
      throw protocolError(
        "timestamp_out_of_window",
        "created_at is too far in the future",
      );
    checkDependencies(copy, (id) => this.records.get(id)?.envelope);
    if (Buffer.byteLength(JSON.stringify(copy)) > this.maxEnvelopeBytes)
      throw protocolError(
        "payload_too_large",
        "envelope exceeds configured byte limit",
      );
    if (this.highWater === Number.MAX_SAFE_INTEGER)
      throw protocolError("permission_denied", "sequence space exhausted");
    this.admit?.(structuredClone(copy));
    const record: KnowledgeRecord = {
      envelope: copy,
      accepted_at: now,
      seq: ++this.highWater,
    };
    this.records.set(copy.hash, record);
    return structuredClone(record);
  }
  event(id: string): KnowledgeRecord {
    validateKnowledgeId(id, "invalid_request");
    if (!this.visible(id))
      throw protocolError("not_found", "event unavailable");
    return structuredClone(this.records.get(id)!);
  }
  /** Withhold from public reads; the record still answers exact retries and resolves dependencies. */
  hide(id: string): void {
    validateKnowledgeId(id, "invalid_request");
    if (this.records.has(id)) this.hidden.add(id);
  }
  unhide(id: string): void {
    validateKnowledgeId(id, "invalid_request");
    this.hidden.delete(id);
  }
  /** Drop content and record; the sequence high-water mark is preserved. */
  prune(id: string): void {
    validateKnowledgeId(id, "invalid_request");
    this.records.delete(id);
    this.hidden.delete(id);
  }
  private scope(checkpoint: number, asOf: number): KnowledgeScope {
    return { service: this.service, checkpoint, as_of: asOf };
  }
  batch(request: KnowledgeBatchRequest): KnowledgeBatchResponse {
    validateKnowledgeBatchRequest(request);
    const response: KnowledgeBatchResponse = {
      result: [],
      missing: [],
      ...this.scope(this.highWater, this.now()),
    };
    for (const id of request.hashes)
      if (this.visible(id))
        response.result.push(structuredClone(this.records.get(id)!));
      else response.missing.push(id);
    return response;
  }
  query(request: KnowledgeQuery = {}): KnowledgeQueryResponse {
    validateKnowledgeQuery(request);
    const digest = sha3(queryBinding(request));
    const after = request.after_seq ?? 0,
      limit = request.limit ?? 100;
    let checkpoint: number, asOf: number, last: number;
    if (request.cursor !== undefined)
      [checkpoint, asOf, last] = this.decodeCursor(
        request.cursor,
        digest,
        after,
      );
    else {
      if (after > this.highWater)
        throw protocolError(
          "invalid_request",
          "after_seq is greater than the current checkpoint",
        );
      [checkpoint, asOf, last] = [this.highWater, this.now(), after];
    }
    const response: KnowledgeQueryResponse = {
      result: [],
      ...this.scope(checkpoint, asOf),
    };
    for (const [id, record] of this.records) {
      if (record.seq <= last || record.seq > checkpoint || this.hidden.has(id))
        continue;
      if (!knowledgeQueryMatches(record.envelope, request)) continue;
      if (response.result.length === limit) {
        response.next_cursor = `${checkpoint}.${asOf}.${response.result.at(-1)!.seq}.${digest}`;
        break;
      }
      response.result.push(structuredClone(record));
    }
    return response;
  }
  private decodeCursor(
    cursor: string,
    digest: string,
    after: number,
  ): [number, number, number] {
    const parts = cursor.split(".");
    if (
      parts.length !== 4 ||
      parts[3] !== digest ||
      parts.slice(0, 3).some((part) => !/^[0-9]{1,16}$/.test(part))
    )
      throw protocolError(
        "invalid_cursor",
        "malformed cursor or different request",
      );
    const [checkpoint, asOf, last] = parts.slice(0, 3).map(Number);
    if (
      !(after <= last && last <= checkpoint && checkpoint <= this.highWater) ||
      !Number.isSafeInteger(asOf)
    )
      throw protocolError(
        "invalid_cursor",
        "cursor does not belong to this service state",
      );
    return [checkpoint, asOf, last];
  }
  /**
   * Return one page of caller-ranked candidates; no ranking model is implied.
   * Only a lexical page containing every match may claim exhaustive coverage.
   */
  search(
    request: KnowledgeSearchRequest,
    selection: KnowledgeSearchSelection,
    modes: readonly string[] = KNOWLEDGE_SEARCH_MODES,
  ): KnowledgeSearchResponse {
    validateKnowledgeSearchRequest(request, modes);
    const limit = request.limit ?? 20;
    const eligible = new Set<string>();
    for (const [id, record] of this.records)
      if (
        !this.hidden.has(id) &&
        knowledgeQueryMatches(record.envelope, request.filters ?? {}) &&
        (request.mode !== "lexical" ||
          knowledgeTextMatches(record.envelope, request.text))
      )
        eligible.add(id);
    const ids = selection.candidates;
    if (new Set(ids).size !== ids.length || ids.some((id) => !eligible.has(id)))
      throw protocolError(
        "invalid_response",
        "candidate list repeats IDs or violates exact filters",
      );
    if (
      selection.coverage.exhaustive &&
      (ids.length !== eligible.size || ids.length > limit)
    )
      throw protocolError("invalid_response", "false exhaustive coverage");
    const response: KnowledgeSearchResponse = {
      result: ids.slice(0, limit).map((id) => ({
        record: structuredClone(this.records.get(id)!),
        explanation:
          selection.explanations?.[id] ??
          `Selected by ranking configuration ${selection.ranking.id}`,
      })),
      ...this.scope(this.highWater, this.now()),
      ranking: structuredClone(selection.ranking),
      coverage: structuredClone(selection.coverage),
    };
    validateKnowledgeSchema(response, "searchResponse", "invalid_response");
    if (response.ranking.mode !== request.mode)
      throw protocolError(
        "invalid_response",
        "ranking mode differs from requested mode",
      );
    return response;
  }
}
