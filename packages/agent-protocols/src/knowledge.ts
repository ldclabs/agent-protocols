/** Agent Knowledge 1.0. Signatures establish attribution, never scientific truth. */
import { createHash, randomUUID } from "node:crypto";
import canonicalize from "canonicalize";
import { Validator, type Schema } from "@cfworker/json-schema";
import { protocolError } from "./errors.js";
import {
  AgentId,
  Envelope,
  Event,
  MemoryNonceStore,
  type NonceStore,
  createEvent,
  parseStrictJson,
  validateOrigin,
  verifyEnvelope,
  verifySubmission,
  DEFAULT_LIVE_WRITE_WINDOW_MS,
  DEFAULT_NONCE_TTL_MS,
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
interface KnowledgePublicPayload {
  visibility: "public";
  license: string;
  extra?: Record<string, unknown>;
}
interface KnowledgeResearchPayload extends KnowledgePublicPayload {
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
  learned_at?: number;
}
export interface KnowledgeAssessPayload extends KnowledgeResearchPayload {
  target: string;
  verdict: KnowledgeVerdict;
  summary: string;
}
export interface KnowledgeRetractPayload extends KnowledgePublicPayload {
  target: string;
  reason: string;
}
export type KnowledgePayload =
  | KnowledgePublishPayload
  | KnowledgeAssessPayload
  | KnowledgeRetractPayload;
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
  limit?: number;
  cursor?: string;
}
export interface KnowledgeChangesRequest {
  after?: number;
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
export interface KnowledgeChangesResponse {
  result: KnowledgeRecord[];
  checkpoint: number;
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
  cursor?: string;
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
  rank: number;
  explanation: string;
  [key: string]: unknown;
}
export interface KnowledgeSearchResponse extends KnowledgeScope {
  result: KnowledgeSearchHit[];
  ranking: KnowledgeRanking;
  coverage: KnowledgeCoverage;
  next_cursor?: string;
  [key: string]: unknown;
}
export interface KnowledgeEndpoints {
  events: string;
  query: string;
  batch: string;
  changes: string;
  import?: string;
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
  collection_scope?: {
    description?: string;
    tags?: string[];
    languages?: string[];
    profiles?: string[];
    [key: string]: unknown;
  };
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
/** Structure only. Signature, canonical encodings and references are separate checks. */
export function knowledgeSchemaValid(
  value: unknown,
  definition = "signedEnvelope",
): boolean {
  let validator = validators.get(definition);
  if (!validator) {
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
  return validator.validate(value).valid;
}
function shape(value: unknown, definition: string, code: string): void {
  if (!knowledgeSchemaValid(value, definition))
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
export function validateKnowledgeEnvelope(
  value: unknown,
): asserts value is KnowledgeEnvelope {
  jsonCheck(value);
  shape(value, "signedEnvelope", "invalid_event");
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
  if ("learned_at" in payload && payload.learned_at! > item.event.created_at)
    throw protocolError("invalid_event", "learned_at exceeds created_at");
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
/** Targets must already have passed common and dependency validation in this dataset. */
export function validateKnowledgeDependencies(
  item: KnowledgeEnvelope,
  known: KnowledgeKnownSet,
): void {
  const retained = knownMap(known),
    missing = knowledgeDependencies(item).filter((id) => !retained.has(id));
  if (missing.length)
    throw protocolError(
      "missing_dependency",
      "unresolved or withheld targets",
      { missing },
    );
  const links =
    item.event.type === "knowledge.publish"
      ? ((item.event.payload as KnowledgePublishPayload).relations ?? [])
      : [
          {
            relation: item.event.type,
            target: (
              item.event.payload as
                | KnowledgeAssessPayload
                | KnowledgeRetractPayload
            ).target,
          },
        ];
  for (const link of links) {
    const target = retained.get(link.target)!.event;
    if (
      !(
        link.relation === "knowledge.retract"
          ? ["knowledge.publish", "knowledge.assess"]
          : ["knowledge.publish"]
      ).includes(target.type)
    )
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
    validateKnowledgeDependencies(item, retained);
  }
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
  | "unchecked"
  | "matched"
  | "mismatched"
  | "unavailable";
/** Bytes must be the complete representation after transfer/content decoding, before text conversion. No fetching occurs. */
export function verifyKnowledgeEvidence(
  digest: string | undefined,
  bytes?: Uint8Array,
  options: { fetched?: boolean; complete?: boolean } = {},
): KnowledgeEvidenceStatus {
  if (digest === undefined || options.fetched === false) return "unchecked";
  validateKnowledgeId(digest);
  if (!bytes || options.complete !== true) return "unavailable";
  return createHash("sha3-256").update(bytes).digest("base64url") === digest
    ? "matched"
    : "mismatched";
}
export interface KnowledgeProfileResult {
  event_id: string;
  profile_digest: string;
  status: "unchecked" | "conformant" | "nonconformant" | "unavailable";
}
/** Report separately authorized profile evaluation, bound to exact event and artifact bytes. */
export function knowledgeProfileResult(
  item: KnowledgeEnvelope,
  digest: string,
  evaluation: {
    supported?: boolean;
    artifact?: Uint8Array;
    dependenciesVerified?: boolean;
    checksPassed?: boolean;
  } = {},
): KnowledgeProfileResult {
  validateKnowledgeEnvelope(item);
  validateKnowledgeId(digest);
  if (
    !("profiles" in item.event.payload) ||
    !item.event.payload.profiles?.some((b) => b.profile.digest === digest)
  )
    throw protocolError("invalid_request", "profile is not bound to event");
  let status: KnowledgeProfileResult["status"] = "unchecked";
  if (evaluation.supported) {
    if (
      verifyKnowledgeEvidence(digest, evaluation.artifact, {
        complete: true,
      }) !== "matched" ||
      evaluation.dependenciesVerified !== true
    )
      status = "unavailable";
    else if (evaluation.checksPassed === true) status = "conformant";
    else if (evaluation.checksPassed === false) status = "nonconformant";
  }
  return { event_id: item.hash, profile_digest: digest, status };
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
  shape(filters, "searchFilters", "invalid_request");
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
  jsonCheck(value, "invalid_request");
  shape(value, "queryRequest", "invalid_request");
  const { q, limit: _l, cursor: _c, ...filters } = value as KnowledgeQuery;
  filterCheck(filters);
  if (q !== undefined) knowledgeTextTerms(q);
}
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
    if (["created_from", "created_before", "limit"].includes(key)) {
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
  jsonCheck(value, "invalid_request");
  shape(value, "batchRequest", "invalid_request");
  for (const id of (value as KnowledgeBatchRequest).hashes)
    validateKnowledgeId(id, "invalid_request");
}
export function validateKnowledgeSearchRequest(
  value: unknown,
  modes: readonly string[] = KNOWLEDGE_SEARCH_MODES,
): asserts value is KnowledgeSearchRequest {
  jsonCheck(value, "invalid_request");
  const mode = (value as KnowledgeSearchRequest | null)?.mode;
  if (
    typeof mode === "string" &&
    (!KNOWLEDGE_SEARCH_MODES.includes(mode) || !modes.includes(mode))
  )
    throw protocolError(
      "unsupported_search_mode",
      "requested mode is not advertised",
    );
  shape(value, "searchRequest", "invalid_request");
  const request = value as KnowledgeSearchRequest;
  knowledgeTextTerms(request.text, mode === "lexical");
  filterCheck(request.filters ?? {});
}
export function validateKnowledgeRecord(
  value: unknown,
  expectedId?: string,
): asserts value is KnowledgeRecord {
  jsonCheck(value, "invalid_response");
  shape(value, "acceptanceRecord", "invalid_response");
  const record = value as KnowledgeRecord;
  validateKnowledgeEnvelope(record.envelope);
  if (expectedId !== undefined && record.envelope.hash !== expectedId)
    throw protocolError(
      "invalid_response",
      "returned envelope ID does not match request",
    );
}
function responseShape(
  value: unknown,
  definition: string,
  service: string,
): void {
  jsonCheck(value, "invalid_response");
  shape(value, definition, "invalid_response");
  const response = value as
    | KnowledgeQueryResponse
    | KnowledgeBatchResponse
    | KnowledgeSearchResponse;
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
  const sequences = new Set<number>();
  for (const record of records) {
    validateKnowledgeRecord(record);
    if (
      record.seq > response.checkpoint ||
      ids.has(record.envelope.hash) ||
      sequences.has(record.seq)
    )
      throw protocolError(
        "invalid_response",
        "duplicate event, reused acceptance sequence, or sequence beyond snapshot",
      );
    ids.add(record.envelope.hash);
    sequences.add(record.seq);
  }
}
export function validateKnowledgeQueryResponse(
  value: unknown,
  request: KnowledgeQuery,
  service: string,
): asserts value is KnowledgeQueryResponse {
  responseShape(value, "queryResponse", service);
  const response = value as KnowledgeQueryResponse;
  if (response.result.length > (request.limit ?? 100))
    throw protocolError("invalid_response", "query page exceeds limit");
  let previous = 0;
  for (const record of response.result) {
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
  responseShape(value, "batchResponse", service);
  const response = value as KnowledgeBatchResponse;
  const result = response.result.map((r) => r.envelope.hash),
    missing = response.missing;
  for (const id of missing) validateKnowledgeId(id, "invalid_response");
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
  responseShape(value, "searchResponse", service);
  const response = value as KnowledgeSearchResponse;
  if (
    response.result.length > (request.limit ?? 20) ||
    response.ranking.mode !== request.mode
  )
    throw protocolError("invalid_response", "search limit or mode mismatch");
  let rank = 0;
  for (const hit of response.result) {
    if (
      hit.rank <= rank ||
      !knowledgeQueryMatches(hit.record.envelope, request.filters ?? {}) ||
      (request.mode === "lexical" &&
        !knowledgeTextMatches(hit.record.envelope, request.text))
    )
      throw protocolError(
        "invalid_response",
        "search violated ranks, exact filters or lexical text",
      );
    rank = hit.rank;
  }
}
export function validateKnowledgeChangesRequest(
  value: unknown,
): asserts value is KnowledgeChangesRequest {
  jsonCheck(value, "invalid_request");
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).some(
      (key) => !["after", "limit", "cursor"].includes(key),
    )
  )
    throw protocolError("invalid_request", "invalid changes parameters");
  const r = value as KnowledgeChangesRequest;
  if (
    (r.after !== undefined &&
      (!Number.isSafeInteger(r.after) || r.after < 0)) ||
    (r.limit !== undefined &&
      (!Number.isInteger(r.limit) || r.limit < 1 || r.limit > 1000)) ||
    (r.cursor !== undefined && (typeof r.cursor !== "string" || !r.cursor))
  )
    throw protocolError("invalid_request", "invalid changes parameters");
}
/** Parse decoded changes parameters while preserving duplicate-name detection. */
export function parseKnowledgeChanges(
  parameters: Iterable<readonly [string, string]> | URLSearchParams,
): KnowledgeChangesRequest {
  const request: Record<string, unknown> = {};
  for (const [key, value] of parameters) {
    if (
      !["after", "limit", "cursor"].includes(key) ||
      Object.hasOwn(request, key)
    )
      throw protocolError(
        "invalid_request",
        "unknown or repeated changes parameter",
      );
    if (
      key !== "cursor" &&
      (!/^[0-9]+$/.test(value) || value.replace(/^0+/, "").length > 16)
    )
      throw protocolError(
        "invalid_request",
        "HTTP integers require decimal digits",
      );
    request[key] = key === "cursor" ? value : Number(value);
  }
  validateKnowledgeChangesRequest(request);
  return request;
}
export function validateKnowledgeChangesResponse(
  value: unknown,
  request: KnowledgeChangesRequest,
): asserts value is KnowledgeChangesResponse {
  jsonCheck(value, "invalid_response");
  const response = value as KnowledgeChangesResponse;
  if (
    !response ||
    !Array.isArray(response.result) ||
    !Number.isSafeInteger(response.checkpoint) ||
    response.checkpoint < 0 ||
    (response.next_cursor !== undefined &&
      (typeof response.next_cursor !== "string" || !response.next_cursor))
  )
    throw protocolError("invalid_response", "invalid changes response");
  let seq = request.after ?? 0;
  const seen = new Set<string>();
  if (
    response.result.length > (request.limit ?? 100) ||
    response.checkpoint < seq
  )
    throw protocolError(
      "invalid_response",
      "changes limit or checkpoint mismatch",
    );
  for (const record of response.result) {
    validateKnowledgeRecord(record);
    if (
      record.seq <= seq ||
      record.seq > response.checkpoint ||
      seen.has(record.envelope.hash)
    )
      throw protocolError("invalid_response", "invalid changes sequence");
    seq = record.seq;
    seen.add(record.envelope.hash);
  }
}
export function validateKnowledgeDiscovery(
  value: unknown,
  origin: string,
): asserts value is KnowledgeDiscovery {
  jsonCheck(value, "invalid_discovery");
  shape(value, "discoveryDocument", "invalid_discovery");
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
    const scope = d.collection_scope ?? {},
      langs = (scope.languages ?? []).map(fold);
    if (new Set(langs).size !== langs.length) throw new Error();
    for (const digest of scope.profiles ?? []) validateKnowledgeId(digest);
  } catch {
    throw protocolError(
      "invalid_discovery",
      "invalid service, endpoint, peer or scope",
    );
  }
}

interface KnowledgeSnapshot {
  operation: "query" | "search" | "changes";
  binding: string;
  entries: { id: string; seq: number; explanation?: string }[];
  offset: number;
  scope: KnowledgeScope;
  expires: number;
  ranking?: KnowledgeRanking;
  coverage?: KnowledgeCoverage;
}
export interface KnowledgeStoreOptions {
  service: string;
  clock?: () => number;
  windowMs?: number;
  nonceTtlMs?: number;
  /** Share this store with other protocols served by the same origin. */
  nonceStore?: NonceStore;
  maxEnvelopeBytes?: number;
  maxSnapshots?: number;
  snapshotTtlMs?: number;
  maxSnapshotRecords?: number;
  /** Called only for new acceptance, before nonce mutation. */
  admit?: (envelope: KnowledgeEnvelope, mode: "live" | "import") => void;
}
export interface KnowledgeSearchSelection {
  /** Frozen ranked event IDs. Candidates must be visible and satisfy all exact filters. */
  candidates: readonly string[];
  ranking: KnowledgeRanking;
  coverage: KnowledgeCoverage;
  explanations?: Readonly<Record<string, string>>;
}
/** Synchronous in-memory reference service engine. Applications supply persistence and HTTP policy separately. */
export class KnowledgeStore {
  private readonly records = new Map<string, KnowledgeRecord>();
  private readonly hidden = new Set<string>();
  private readonly nonces: NonceStore;
  private readonly snapshots = new Map<string, KnowledgeSnapshot>();
  private highWater = 0;
  private readonly options: Required<Omit<KnowledgeStoreOptions, "admit">> &
    Pick<KnowledgeStoreOptions, "admit">;
  constructor(options: KnowledgeStoreOptions) {
    validateOrigin(options.service);
    this.nonces = options.nonceStore ?? new MemoryNonceStore();
    this.options = {
      nonceStore: this.nonces,
      clock: Date.now,
      windowMs: DEFAULT_LIVE_WRITE_WINDOW_MS,
      nonceTtlMs: DEFAULT_NONCE_TTL_MS,
      maxEnvelopeBytes: 262144,
      maxSnapshots: 128,
      snapshotTtlMs: 600000,
      maxSnapshotRecords: 100000,
      ...options,
    };
    for (const key of [
      "windowMs",
      "nonceTtlMs",
      "maxEnvelopeBytes",
      "maxSnapshots",
      "snapshotTtlMs",
      "maxSnapshotRecords",
    ] as const)
      if (!Number.isSafeInteger(this.options[key]) || this.options[key] <= 0)
        throw protocolError("invalid_request", `invalid store option ${key}`);
    if (this.options.nonceTtlMs < 2 * this.options.windowMs)
      throw protocolError(
        "invalid_request",
        "nonce TTL must cover twice the live window",
      );
  }
  get service(): string {
    return this.options.service;
  }
  get checkpoint(): number {
    return this.highWater;
  }
  maxNonce(actor: AgentId, now = this.now()): number | undefined {
    return this.nonces.maxNonce(actor, now);
  }
  private now(): number {
    const now = this.options.clock();
    if (!Number.isSafeInteger(now) || now < 0)
      throw protocolError("invalid_request", "invalid service clock");
    return now;
  }
  private visible(id: string, seq?: number): boolean {
    const record = this.records.get(id);
    return (
      record !== undefined &&
      !this.hidden.has(id) &&
      (seq === undefined || seq === record.seq)
    );
  }
  private known(): Map<string, KnowledgeEnvelope> {
    return new Map(
      [...this.records]
        .filter(([id]) => this.visible(id))
        .map(([id, record]) => [id, record.envelope]),
    );
  }
  /** Copies prevent callers from mutating accepted storage through a retained reference. */
  knownEnvelopes(): Map<string, KnowledgeEnvelope> {
    return structuredClone(this.known());
  }
  submit(
    envelope: KnowledgeEnvelope,
    mode: "live" | "import" = "live",
    now = this.now(),
  ): KnowledgeRecord {
    if (mode !== "live" && mode !== "import")
      throw protocolError("invalid_request", "unknown submission mode");
    if (!Number.isSafeInteger(now) || now < 0)
      throw protocolError("invalid_request", "invalid service clock");
    validateKnowledgeEnvelope(envelope);
    const retained = this.records.get(envelope.hash);
    if (retained) return structuredClone(retained);
    validateKnowledgeDependencies(envelope, this.known());
    if (
      Buffer.byteLength(JSON.stringify(envelope)) >
      this.options.maxEnvelopeBytes
    )
      throw protocolError(
        "payload_too_large",
        "envelope exceeds configured byte limit",
      );
    if (this.highWater === Number.MAX_SAFE_INTEGER)
      throw protocolError("query_unavailable", "sequence space exhausted");
    const copy = structuredClone(envelope);
    this.options.admit?.(structuredClone(copy), mode);
    if (mode === "live")
      verifySubmission(copy, this.nonces, {
        nowMs: now,
        windowMs: this.options.windowMs,
        nonceTtlMs: this.options.nonceTtlMs,
      });
    else if (copy.event.created_at > now + this.options.windowMs)
      throw protocolError(
        "timestamp_out_of_window",
        "historical object is too far in the future",
      );
    const record: KnowledgeRecord = {
      envelope: copy,
      seq: ++this.highWater,
      accepted_at: now,
    };
    this.records.set(copy.hash, record);
    return structuredClone(record);
  }
  import(envelope: KnowledgeEnvelope, now = this.now()): KnowledgeRecord {
    return this.submit(envelope, "import", now);
  }
  event(id: string): KnowledgeRecord {
    validateKnowledgeId(id, "invalid_request");
    if (!this.visible(id))
      throw protocolError("not_found", "event unavailable");
    return structuredClone(this.records.get(id)!);
  }
  hide(id: string): void {
    validateKnowledgeId(id, "invalid_request");
    if (this.records.has(id)) this.hidden.add(id);
  }
  unhide(id: string): void {
    validateKnowledgeId(id, "invalid_request");
    this.hidden.delete(id);
  }
  /** Pruning keeps sequence and live nonce high-water state; a later acceptance allocates a fresh sequence. */
  prune(id: string): void {
    validateKnowledgeId(id, "invalid_request");
    this.records.delete(id);
    this.hidden.delete(id);
  }
  expireSnapshots(): void {
    this.snapshots.clear();
  }
  private scope(): KnowledgeScope {
    return {
      service: this.service,
      checkpoint: this.highWater,
      as_of: this.now(),
    };
  }
  batch(request: KnowledgeBatchRequest): KnowledgeBatchResponse {
    validateKnowledgeBatchRequest(request);
    const response: KnowledgeBatchResponse = {
      ...this.scope(),
      result: [],
      missing: [],
    };
    for (const id of request.hashes)
      this.visible(id)
        ? response.result.push(structuredClone(this.records.get(id)!))
        : response.missing.push(id);
    return response;
  }
  query(
    request: KnowledgeQuery = {},
    available = true,
  ): KnowledgeQueryResponse {
    validateKnowledgeQuery(request);
    const response = this.page(
      "query",
      request,
      undefined,
      available,
    ) as KnowledgeQueryResponse;
    validateKnowledgeQueryResponse(response, request, this.service);
    return response;
  }
  changes(request: KnowledgeChangesRequest = {}): KnowledgeChangesResponse {
    validateKnowledgeChangesRequest(request);
    const response = this.page("changes", request) as KnowledgeChangesResponse;
    validateKnowledgeChangesResponse(response, request);
    return response;
  }
  /** Ranking is supplied by the application; no embedding, fetching or code execution is implicit. */
  search(
    request: KnowledgeSearchRequest,
    selection?: KnowledgeSearchSelection,
    modes: readonly string[] = KNOWLEDGE_SEARCH_MODES,
  ): KnowledgeSearchResponse {
    validateKnowledgeSearchRequest(request, modes);
    const response = this.page(
      "search",
      request,
      selection,
    ) as KnowledgeSearchResponse;
    validateKnowledgeSearchResponse(response, request, this.service);
    return response;
  }
  private page(
    operation: KnowledgeSnapshot["operation"],
    request: KnowledgeQuery | KnowledgeSearchRequest | KnowledgeChangesRequest,
    selection?: KnowledgeSearchSelection,
    available = true,
  ):
    | KnowledgeQueryResponse
    | KnowledgeSearchResponse
    | KnowledgeChangesResponse {
    const { cursor, ...effective } = request,
      limit = request.limit ?? (operation === "search" ? 20 : 100);
    const binding = canonicalize({
      ...effective,
      limit,
      ...(operation === "search"
        ? { filters: (request as KnowledgeSearchRequest).filters ?? {} }
        : operation === "changes"
          ? { after: (request as KnowledgeChangesRequest).after ?? 0 }
          : {}),
    })!;
    const now = this.now();
    for (const [token, snapshot] of this.snapshots)
      if (snapshot.expires <= now) this.snapshots.delete(token);
    let snapshot: KnowledgeSnapshot;
    if (cursor !== undefined) {
      const found = this.snapshots.get(cursor);
      if (!found || found.binding !== binding || found.operation !== operation)
        throw protocolError("invalid_cursor", "expired or incompatible cursor");
      snapshot = structuredClone(found);
    } else {
      if (!available)
        throw protocolError(
          "query_unavailable",
          "exact enumeration unavailable",
        );
      if (this.records.size > this.options.maxSnapshotRecords)
        throw protocolError(
          "query_too_broad",
          "configured scan budget exceeded",
        );
      const after = (request as KnowledgeChangesRequest).after ?? 0;
      if (operation === "changes" && after > this.highWater)
        throw protocolError("invalid_request", "after exceeds checkpoint");
      const eligible = [...this.records.values()]
        .filter(
          (record) =>
            this.visible(record.envelope.hash) &&
            (operation === "changes"
              ? record.seq > after
              : knowledgeQueryMatches(
                  record.envelope,
                  operation === "search"
                    ? ((request as KnowledgeSearchRequest).filters ?? {})
                    : (request as KnowledgeQuery),
                ) &&
                (operation !== "search" ||
                  (request as KnowledgeSearchRequest).mode !== "lexical" ||
                  knowledgeTextMatches(
                    record.envelope,
                    (request as KnowledgeSearchRequest).text,
                  ))),
        )
        .sort((a, b) => a.seq - b.seq);
      let ids = eligible.map((record) => record.envelope.hash);
      if (operation === "search") {
        if (!selection)
          throw protocolError(
            "invalid_request",
            "new search requires explicit ranking selection",
          );
        if (selection.candidates.length > this.options.maxSnapshotRecords)
          throw protocolError("query_too_broad", "candidate budget exceeded");
        if (
          new Set(selection.candidates).size !== selection.candidates.length ||
          selection.candidates.some((id) => !ids.includes(id))
        )
          throw protocolError(
            "invalid_response",
            "candidate list repeats IDs or violates exact filters",
          );
        if (
          selection.coverage.exhaustive &&
          selection.candidates.length !== ids.length
        )
          throw protocolError("invalid_response", "false exhaustive coverage");
        ids = [...selection.candidates];
      }
      snapshot = {
        operation,
        binding,
        entries: ids.map((id) => ({
          id,
          seq: this.records.get(id)!.seq,
          ...(operation === "search"
            ? {
                explanation:
                  selection!.explanations?.[id] ??
                  `Candidate selected by ${selection!.ranking.id}`,
              }
            : {}),
        })),
        offset: 0,
        scope: this.scope(),
        expires: now + this.options.snapshotTtlMs,
        ...(operation === "search"
          ? {
              ranking: structuredClone(selection!.ranking),
              coverage: structuredClone(selection!.coverage),
            }
          : {}),
      };
    }
    const response: KnowledgeQueryResponse | KnowledgeSearchResponse = {
      ...snapshot.scope,
      result: [],
      ...(operation === "search"
        ? { ranking: snapshot.ranking!, coverage: snapshot.coverage! }
        : {}),
    } as KnowledgeQueryResponse | KnowledgeSearchResponse;
    while (
      snapshot.offset < snapshot.entries.length &&
      response.result.length < limit
    ) {
      const index = snapshot.offset++,
        entry = snapshot.entries[index];
      if (!this.visible(entry.id, entry.seq)) continue;
      const record = structuredClone(this.records.get(entry.id)!);
      if (operation === "search")
        (response as KnowledgeSearchResponse).result.push({
          record,
          rank: index + 1,
          explanation: entry.explanation!,
        });
      else (response as KnowledgeQueryResponse).result.push(record);
    }
    if (
      snapshot.entries
        .slice(snapshot.offset)
        .some((entry) => this.visible(entry.id, entry.seq))
    ) {
      // Eviction is explicit through invalid_cursor on use, never a silently restarted scan.
      if (this.snapshots.size >= this.options.maxSnapshots)
        this.snapshots.delete(this.snapshots.keys().next().value!);
      const token = randomUUID();
      this.snapshots.set(token, snapshot);
      response.next_cursor = token;
    }
    if (operation === "changes") {
      const {
        service: _s,
        as_of: _a,
        ...changes
      } = response as KnowledgeQueryResponse;
      return changes;
    }
    return structuredClone(response);
  }
}

/** Stateful consumer guard. Complete is true only after consuming the last page of a verified scope. */
export class KnowledgePageTracker {
  private binding?: string;
  private scope?: string;
  private previous = 0;
  private next?: string;
  private seen = new Set<string>();
  private readonly seenSequences = new Set<number>();
  private readonly cursors = new Set<string>();
  private started = false;
  private ended = false;
  constructor(
    readonly operation: "query" | "search" | "changes",
    readonly service: string,
  ) {
    validateOrigin(service);
  }
  get complete(): boolean {
    return this.ended;
  }
  accept(
    request: KnowledgeQuery | KnowledgeSearchRequest | KnowledgeChangesRequest,
    response:
      | KnowledgeQueryResponse
      | KnowledgeSearchResponse
      | KnowledgeChangesResponse,
  ): void {
    const search = this.operation === "search",
      changes = this.operation === "changes";
    if (search) {
      validateKnowledgeSearchRequest(request);
      validateKnowledgeSearchResponse(
        response,
        request as KnowledgeSearchRequest,
        this.service,
      );
    } else if (changes) {
      validateKnowledgeChangesRequest(request);
      validateKnowledgeChangesResponse(response, request);
    } else {
      validateKnowledgeQuery(request);
      validateKnowledgeQueryResponse(response, request, this.service);
    }
    const { cursor, ...rest } = request,
      binding = canonicalize({
        ...rest,
        limit: request.limit ?? (search ? 20 : 100),
        ...(search
          ? { filters: (request as KnowledgeSearchRequest).filters ?? {} }
          : changes
            ? { after: (request as KnowledgeChangesRequest).after ?? 0 }
            : {}),
      })!;
    const scoped = response as KnowledgeSearchResponse;
    const scope = canonicalize({
      checkpoint: response.checkpoint,
      ...(!changes ? { service: scoped.service, as_of: scoped.as_of } : {}),
      ...(search ? { ranking: scoped.ranking, coverage: scoped.coverage } : {}),
    })!;
    if (
      this.ended ||
      (this.started &&
        (this.binding !== binding ||
          this.scope !== scope ||
          cursor !== this.next)) ||
      (!this.started && cursor !== undefined)
    )
      throw protocolError(
        "invalid_response",
        "page request or snapshot configuration drift",
      );
    if (
      response.next_cursor !== undefined &&
      (response.next_cursor === cursor ||
        this.cursors.has(response.next_cursor))
    )
      throw protocolError("invalid_response", "pagination cursor cycle");
    let previous = this.previous;
    const additions: string[] = [];
    const sequences: number[] = [];
    for (const value of response.result) {
      const record = search
          ? (value as KnowledgeSearchHit).record
          : (value as KnowledgeRecord),
        order = search ? (value as KnowledgeSearchHit).rank : record.seq;
      if (
        this.seen.has(record.envelope.hash) ||
        this.seenSequences.has(record.seq) ||
        order <= previous
      )
        throw protocolError(
          "invalid_response",
          "duplicate event, reused acceptance sequence, or nonincreasing cross-page order",
        );
      previous = order;
      additions.push(record.envelope.hash);
      sequences.push(record.seq);
    }
    if (cursor !== undefined) this.cursors.add(cursor);
    this.binding = binding;
    this.scope = scope;
    this.started = true;
    this.previous = previous;
    this.next = response.next_cursor;
    this.ended = this.next === undefined;
    for (const id of additions) this.seen.add(id);
    for (const seq of sequences) this.seenSequences.add(seq);
  }
}
