import {
  KnowledgePageTracker,
  validateKnowledgeEnvelope,
  validateKnowledgeId,
  validateKnowledgeRecord,
  validateKnowledgeQuery,
  validateKnowledgeQueryResponse,
  validateKnowledgeBatchRequest,
  validateKnowledgeBatchResponse,
  validateKnowledgeSearchRequest,
  validateKnowledgeSearchResponse,
  validateKnowledgeDiscovery,
  type KnowledgeEnvelope,
  type KnowledgeRecord,
  type KnowledgeDiscovery,
  type KnowledgeEndpoints,
  type KnowledgeQuery,
  type KnowledgeQueryResponse,
  type KnowledgeBatchResponse,
  type KnowledgeSearchRequest,
  type KnowledgeSearchResponse,
} from "./knowledge.js";
import {
  parseStrictJson,
  validateOrigin,
  verifyRequestJwt,
} from "./identity.js";
import { protocolError } from "./errors.js";

import {
  validateDelegationId,
  validateDelegationQueryRequest,
  validatePrincipalDocument,
  validatePrincipalResolution,
  type DelegationCredential,
  type DelegationEventsResponse,
  type DelegationPayload,
  type DelegationQueryRequest,
  type DelegationQueryResponse,
  type DelegationServiceDiscovery,
  type DelegationServiceEndpoints,
  type PrincipalDocument,
} from "./delegation.js";
import {
  AgentStatus,
  AgentStatusInput,
  AgentStatusListResponse,
  DiscourseProtocolDiscovery,
  RoomCreatePayload,
  RoomEventsResponse,
  RoomJoinPayload,
  RoomJoinRequest,
  RoomJoinRequestPayload,
  RoomLeavePayload,
  RoomResponse,
  ServerRecord,
} from "./discourse.js";
import {
  AgentId,
  Envelope,
  ErrorResponse,
  ListResponse,
  MAX_NONCE_HEADER,
} from "./identity.js";
import {
  AgentProfile,
  ProfileCache,
  ProfileBatchReadResponse,
  ProfileEventsResponse,
  ProfileServiceDiscovery,
  ProfileServiceEndpoints,
  ProfileUpdatePayload,
} from "./profile.js";

export type FetchLike = typeof fetch;

/**
 * Principal URLs come from signed events that anyone can submit, so every
 * principal read is bounded in time and size (Agent Identity Section 10).
 */
const PRINCIPAL_TIMEOUT_MS = 30_000;
const MAX_PRINCIPAL_DOCUMENT_BYTES = 1024 * 1024;

export interface RoomEventsOptions {
  afterSeq?: number;
  limit?: number;
  cursor?: string;
  jwt?: string;
}

export interface MyRoomsOptions {
  status?: string;
  membership?: string;
  limit?: number;
  cursor?: string;
}

export interface PublicRoomsOptions {
  status?: string;
  tag?: string;
  keyword?: string;
  creator?: string;
  startsAfter?: number;
  endsBefore?: number;
  language?: string;
  limit?: number;
  cursor?: string;
}

export interface JoinRequestsOptions {
  status?: string;
  limit?: number;
  cursor?: string;
}

/**
 * Agent Profile client. Without `endpoints` it uses the RECOMMENDED paths
 * under `baseUrl`; {@link ProfileClient.discover} reads the service's
 * discovery document instead, whose endpoints clients MUST prefer.
 */
export class ProfileClient {
  /** Base URL of profile reads, event history, and submission (Section 7.1). */
  readonly profilesUrl: string;
  private readonly batchUrl: string;

  constructor(
    baseUrl: string,
    private readonly fetchImpl: FetchLike = fetch,
    endpoints?: Partial<ProfileServiceEndpoints>,
    readonly profileCache = new ProfileCache(),
  ) {
    const base = baseUrl.replace(/\/$/, "");
    this.profilesUrl = (endpoints?.profiles ?? `${base}/v1/profiles`).replace(
      /\/$/,
      "",
    );
    this.batchUrl = endpoints?.profile_batch ?? `${this.profilesUrl}/batch`;
  }

  /**
   * Builds a client for the service at `origin` from its discovery document,
   * falling back to the default paths when the service publishes none.
   */
  static async discover(
    origin: string,
    fetchImpl: FetchLike = fetch,
    profileCache = new ProfileCache(),
  ): Promise<ProfileClient> {
    const base = origin.replace(/\/$/, "");
    try {
      const response = await fetchImpl(`${base}/.well-known/agent-profile`);
      if (response.ok) {
        const discovery =
          await readProtocolJson<ProfileServiceDiscovery>(response);
        return new ProfileClient(
          base,
          fetchImpl,
          discovery.endpoints,
          profileCache,
        );
      }
    } catch {
      // Discovery is optional; the default paths apply.
    }
    return new ProfileClient(base, fetchImpl, undefined, profileCache);
  }

  async latestProfileUpdate(
    agentId: AgentId,
  ): Promise<Envelope<ProfileUpdatePayload>> {
    const page = await this.profileEvents(agentId, 1);
    if (!page || !Array.isArray(page.result) || page.result.length > 1)
      throw protocolError("invalid_response", "invalid latest profile page");
    if (!page.result.length)
      throw protocolError("not_found", "profile not found");
    return this.profileCache.observe(page.result[0], agentId);
  }

  async getProfile(agentId: AgentId): Promise<AgentProfile> {
    return this.getJson(`${this.profilesUrl}/${agentId}`);
  }

  async getProfiles(agentIds: AgentId[]): Promise<ProfileBatchReadResponse> {
    return this.postJson(this.batchUrl, { ids: agentIds });
  }

  async profileEvents(
    agentId: AgentId,
    limit = 1,
    cursor?: string,
  ): Promise<ProfileEventsResponse> {
    return this.getJson(
      addQuery(`${this.profilesUrl}/${agentId}/events`, { limit, cursor }),
    );
  }

  async submitProfileUpdate(
    envelope: Envelope<ProfileUpdatePayload>,
  ): Promise<AgentProfile> {
    return this.postJson(this.profilesUrl, envelope);
  }

  private async getJson<T>(url: string): Promise<T> {
    const response = await this.fetchImpl(url);
    return readProtocolJson<T>(response);
  }

  private async postJson<T>(url: string, body: unknown): Promise<T> {
    const response = await this.fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return readProtocolJson<T>(response);
  }
}

export class DiscourseClient {
  /**
   * The `rooms` endpoint: `POST` creates rooms, `GET` lists discoverable rooms,
   * and each room URL extends it with `/{room_id}` (ADP Section 15.1).
   */
  readonly roomsUrl: string;
  private readonly baseUrl: string;
  readonly myRoomsUrl: string;

  constructor(
    baseUrl: string,
    private readonly fetchImpl: FetchLike = fetch,
    endpoints?: Partial<Record<"rooms" | "my_rooms", string>>,
  ) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.roomsUrl = (endpoints?.rooms ?? `${this.baseUrl}/v1/rooms`).replace(
      /\/$/,
      "",
    );
    this.myRoomsUrl = endpoints?.my_rooms ?? `${this.baseUrl}/v1/me/rooms`;
  }

  /**
   * Builds a client for the host at `origin` from its discovery document,
   * falling back to the default paths when the host publishes none.
   */
  static async discover(
    origin: string,
    fetchImpl: FetchLike = fetch,
  ): Promise<DiscourseClient> {
    const base = origin.replace(/\/$/, "");
    try {
      const response = await fetchImpl(`${base}/.well-known/agent-discourse`);
      if (response.ok) {
        const discovery =
          await readProtocolJson<DiscourseProtocolDiscovery>(response);
        return new DiscourseClient(base, fetchImpl, discovery.endpoints);
      }
    } catch {
      // Discovery is optional; the default paths apply.
    }
    return new DiscourseClient(base, fetchImpl);
  }

  async protocol(): Promise<DiscourseProtocolDiscovery> {
    return this.getJson(`${this.baseUrl}/.well-known/agent-discourse`);
  }

  async createRoom(
    envelope: Envelope<RoomCreatePayload>,
  ): Promise<RoomResponse> {
    return this.postJson(this.roomsUrl, envelope);
  }

  async room(roomId: string, jwt?: string): Promise<RoomResponse> {
    return this.getJson(this.roomUrl(roomId), jwt);
  }

  async publicRooms(
    options: PublicRoomsOptions = {},
  ): Promise<ListResponse<RoomResponse>> {
    return this.getJson(
      addQuery(this.roomsUrl, {
        status: options.status,
        tag: options.tag,
        keyword: options.keyword,
        creator: options.creator,
        starts_after: options.startsAfter,
        ends_before: options.endsBefore,
        language: options.language,
        limit: options.limit,
        cursor: options.cursor,
      }),
    );
  }

  async myRooms(
    jwt: string,
    options: MyRoomsOptions = {},
  ): Promise<ListResponse<RoomResponse>> {
    return this.getJson(
      addQuery(this.myRoomsUrl, {
        status: options.status,
        membership: options.membership,
        limit: options.limit,
        cursor: options.cursor,
      }),
      jwt,
    );
  }

  /** Submits a signed `room.join.request`; the signature authenticates the applicant. */
  async requestJoin(
    roomId: string,
    envelope: Envelope<RoomJoinRequestPayload>,
  ): Promise<RoomJoinRequest> {
    return this.postJson(`${this.roomUrl(roomId)}/join-requests`, envelope);
  }

  async joinRequest(
    roomId: string,
    requestId: string,
    jwt: string,
  ): Promise<RoomJoinRequest> {
    return this.getJson(
      `${this.roomUrl(roomId)}/join-requests/${requestId}`,
      jwt,
    );
  }

  async joinRequests(
    roomId: string,
    jwt: string,
    options: JoinRequestsOptions = {},
  ): Promise<ListResponse<RoomJoinRequest>> {
    return this.getJson(
      addQuery(`${this.roomUrl(roomId)}/join-requests`, {
        status: options.status,
        limit: options.limit,
        cursor: options.cursor,
      }),
      jwt,
    );
  }

  async joinRoom(
    roomId: string,
    envelope: Envelope<RoomJoinPayload>,
  ): Promise<ServerRecord<RoomJoinPayload>> {
    return this.postJson(this.roomUrl(roomId), envelope);
  }

  async leaveRoom(
    roomId: string,
    envelope: Envelope<RoomLeavePayload>,
  ): Promise<ServerRecord<RoomLeavePayload>> {
    return this.postJson(this.roomUrl(roomId), envelope);
  }

  async submitEvent<P>(
    roomId: string,
    envelope: Envelope<P>,
  ): Promise<ServerRecord<P>> {
    return this.postJson(this.roomUrl(roomId), envelope);
  }

  async events(
    roomId: string,
    options: RoomEventsOptions = {},
  ): Promise<RoomEventsResponse> {
    return this.getJson(
      addQuery(`${this.roomUrl(roomId)}/events`, {
        after_seq: options.afterSeq,
        limit: options.limit,
        cursor: options.cursor,
      }),
      options.jwt,
    );
  }

  async agentStatuses(
    roomId: string,
    jwt?: string,
  ): Promise<AgentStatusListResponse> {
    return this.getJson(`${this.roomUrl(roomId)}/agent-status`, jwt);
  }

  async agentStatus(
    roomId: string,
    agentId: AgentId,
    jwt?: string,
  ): Promise<AgentStatus> {
    return this.getJson(`${this.roomUrl(roomId)}/agent-status/${agentId}`, jwt);
  }

  async setAgentStatus(
    roomId: string,
    jwt: string,
    status: AgentStatusInput,
  ): Promise<AgentStatus> {
    return this.putJson(`${this.roomUrl(roomId)}/agent-status`, status, jwt);
  }

  sseEventsUrl(roomId: string): string {
    return `${this.roomsUrl}/${encodeURIComponent(roomId)}/events/live`;
  }

  async archive(roomId: string): Promise<unknown> {
    return this.getJson(`${this.roomUrl(roomId)}/archive`);
  }

  private async getJson<T>(url: string, jwt?: string): Promise<T> {
    const response = await this.fetchImpl(url, {
      headers: jwt ? { authorization: `Bearer ${jwt}` } : undefined,
    });
    return readProtocolJson<T>(response);
  }

  private async postJson<T>(
    url: string,
    body: unknown,
    jwt?: string,
  ): Promise<T> {
    const response = await this.fetchImpl(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(jwt ? { authorization: `Bearer ${jwt}` } : {}),
      },
      body: JSON.stringify(body),
    });
    return readProtocolJson<T>(response);
  }

  private async putJson<T>(
    url: string,
    body: unknown,
    jwt?: string,
  ): Promise<T> {
    const response = await this.fetchImpl(url, {
      method: "PUT",
      headers: {
        "content-type": "application/json",
        ...(jwt ? { authorization: `Bearer ${jwt}` } : {}),
      },
      body: JSON.stringify(body),
    });
    return readProtocolJson<T>(response);
  }

  private roomUrl(roomId: string): string {
    return `${this.roomsUrl}/${roomId}`;
  }
}

/**
 * Agent Delegation client. Without `endpoints` it uses the RECOMMENDED paths
 * under `baseUrl`; {@link DelegationClient.discover} reads the service's
 * discovery document instead, whose endpoints clients MUST prefer.
 */
export class DelegationClient {
  private readonly delegationsUrl: string;
  /** The query endpoint this client uses: discovered, or the RECOMMENDED default. */
  readonly queryUrl: string;

  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: FetchLike = fetch,
    endpoints?: Partial<DelegationServiceEndpoints>,
  ) {
    const base = baseUrl.replace(/\/$/, "");
    this.delegationsUrl = (
      endpoints?.delegations ?? `${base}/v1/delegations`
    ).replace(/\/$/, "");
    this.queryUrl = endpoints?.query ?? `${this.delegationsUrl}/query`;
  }

  /**
   * Builds a client for the service at `origin` from its discovery document,
   * falling back to the default paths when the service publishes none.
   */
  static async discover(
    origin: string,
    fetchImpl: FetchLike = fetch,
  ): Promise<DelegationClient> {
    const base = origin.replace(/\/$/, "");
    try {
      const response = await fetchImpl(`${base}/.well-known/agent-delegation`);
      if (response.ok) {
        const discovery =
          await readProtocolJson<DelegationServiceDiscovery>(response);
        return new DelegationClient(base, fetchImpl, discovery.endpoints);
      }
    } catch {
      // Discovery is optional; the default paths apply.
    }
    return new DelegationClient(base, fetchImpl);
  }

  async protocol(): Promise<DelegationServiceDiscovery> {
    return this.getJson(
      `${this.baseUrl.replace(/\/$/, "")}/.well-known/agent-delegation`,
    );
  }

  /**
   * Resolves a principal document per Agent Delegation Section 3. A document
   * is authoritative only when read at its own `id`, so one served elsewhere
   * (an alias hosting a copy rather than redirecting) is discarded and
   * `document.id` is resolved once more.
   */
  async principal(principalUrl = this.baseUrl): Promise<PrincipalDocument> {
    const first = await this.readPrincipal(principalUrl);
    if (first.document.id === first.resolvedUrl) return first.document;
    const canonical = await this.readPrincipal(first.document.id);
    validatePrincipalResolution(canonical.document, canonical.resolvedUrl);
    return canonical.document;
  }

  async delegation(delegationId: string): Promise<DelegationCredential> {
    validateDelegationId(delegationId);
    return this.getJson(`${this.delegationsUrl}/${delegationId}`);
  }

  async delegationEvents(
    delegationId: string,
    cursor?: string,
  ): Promise<DelegationEventsResponse> {
    validateDelegationId(delegationId);
    return this.getJson(
      addQuery(`${this.delegationsUrl}/${delegationId}/events`, { cursor }),
    );
  }

  /** Every accepted record of a credential, following `next_cursor`. */
  async allDelegationEvents(
    delegationId: string,
  ): Promise<DelegationEventsResponse["result"]> {
    const records: DelegationEventsResponse["result"] = [];
    let cursor: string | undefined;
    do {
      const page = await this.delegationEvents(delegationId, cursor);
      records.push(...page.result);
      cursor = page.next_cursor;
    } while (cursor !== undefined);
    return records;
  }

  async submitDelegationEvent(
    envelope: Envelope<DelegationPayload>,
  ): Promise<DelegationCredential> {
    return this.postJson(this.delegationsUrl, envelope);
  }

  /**
   * Public queries are existence checks and carry both `subject` and
   * `principal_id`. Passing a request JWT authorizes an enumeration query,
   * which a service must otherwise refuse.
   */
  async queryDelegations(
    request: DelegationQueryRequest,
    jwt?: string,
  ): Promise<DelegationQueryResponse> {
    return this.queryDelegationsAt(this.queryUrl, request, jwt);
  }

  /**
   * Queries an explicit endpoint, such as the `query` endpoint discovered at
   * a principal's `delegation_service` origin. A relying party reaches a
   * principal's authoritative service through that origin, never through a
   * URL supplied by whoever presented the credential.
   */
  async queryDelegationsAt(
    queryUrl: string,
    request: DelegationQueryRequest,
    jwt?: string,
  ): Promise<DelegationQueryResponse> {
    validateDelegationQueryRequest(request, {
      allowEnumeration: jwt !== undefined,
    });
    const response = await this.fetchImpl(queryUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(jwt ? { authorization: `Bearer ${jwt}` } : {}),
      },
      body: JSON.stringify(request),
    });
    return readProtocolJson<DelegationQueryResponse>(response);
  }

  private async readPrincipal(
    url: string,
  ): Promise<{ document: PrincipalDocument; resolvedUrl: string }> {
    for (let redirects = 0; ; redirects++) {
      if (new URL(url).protocol !== "https:")
        throw new Error("principal resolution requires HTTPS");
      const response = await this.fetchImpl(url, {
        headers: { accept: "application/json" },
        redirect: "manual",
        signal: AbortSignal.timeout(PRINCIPAL_TIMEOUT_MS),
      });
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        if (!location || redirects >= 5)
          throw new Error("invalid principal redirect chain");
        url = new URL(location, url).href;
        continue;
      }
      const document = await readBoundedJson<PrincipalDocument>(
        response,
        MAX_PRINCIPAL_DOCUMENT_BYTES,
      );
      const resolvedUrl = response.url || url;
      if (
        new URL(resolvedUrl).protocol !== "https:" ||
        typeof document?.id !== "string" ||
        new URL(document.id).protocol !== "https:"
      )
        throw new Error("invalid principal HTTPS URL");
      // Copies contribute only the canonical ID, never authority fields.
      if (document.id === resolvedUrl) validatePrincipalDocument(document);
      return { document, resolvedUrl };
    }
  }

  private async getJson<T>(url: string): Promise<T> {
    const response = await this.fetchImpl(url);
    return readProtocolJson<T>(response);
  }

  private async postJson<T>(url: string, body: unknown): Promise<T> {
    const response = await this.fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return readProtocolJson<T>(response);
  }
}

/**
 * URL of a room's SSE stream. Send the request JWT in the `Authorization`
 * header, never in this URL; the host closes the stream by the JWT's `exp`
 * (Agent Discourse Section 16.1).
 */
export function sseEventsUrl(baseUrl: string, roomId: string): string {
  return `${baseUrl.replace(/\/$/, "")}/v1/rooms/${encodeURIComponent(roomId)}/events/live`;
}

function addQuery(
  path: string,
  params: Record<string, string | number | undefined>,
): string {
  const encoded = Object.entries(params)
    .filter(
      (entry): entry is [string, string | number] => entry[1] !== undefined,
    )
    .map(
      ([key, value]) =>
        `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`,
    )
    .join("&");
  return encoded ? `${path}?${encoded}` : path;
}

export async function readProtocolJson<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const text = await response.text();
    throw new HttpResponseError(
      response.status,
      text,
      response.headers?.get?.(MAX_NONCE_HEADER) ?? undefined,
    );
  }
  const bytes = await response.arrayBuffer();
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      bytes,
    );
  } catch {
    throw protocolError("invalid_event", "response is not UTF-8");
  }
  return parseStrictJson(text) as T;
}

/** Like {@link readJson}, but rejects a body over `limit` bytes. */
async function readBoundedJson<T>(
  response: Response,
  limit: number,
): Promise<T> {
  const tooLarge = () =>
    protocolError("payload_too_large", `response exceeds ${limit} bytes`);
  const declared = response.headers?.get?.("content-length");
  if (declared != null && Number(declared) > limit) throw tooLarge();
  let text: string;
  const reader = response.body?.getReader();
  if (reader) {
    const chunks: Uint8Array[] = [];
    let count = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        count += value.length;
        if (count > limit) {
          await reader.cancel();
          throw tooLarge();
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    const bytes = new Uint8Array(count);
    let at = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, at);
      at += chunk.length;
    }
    text = new TextDecoder().decode(bytes);
  } else {
    text = await response.text();
    if (new TextEncoder().encode(text).length > limit) throw tooLarge();
  }
  if (!response.ok) {
    throw new HttpResponseError(
      response.status,
      text,
      response.headers?.get?.(MAX_NONCE_HEADER) ?? undefined,
    );
  }
  return parseStrictJson(text) as T;
}

/**
 * A non-2xx response. `code` and `data` come from the Agent Identity error body
 * (Section 8.1) when the service sent one; `maxSeenNonce` from the
 * `Max-Seen-Nonce` header.
 */
export class HttpResponseError extends Error {
  readonly code?: string;
  readonly data?: Record<string, unknown>;
  readonly maxSeenNonce?: string;

  constructor(
    public readonly status: number,
    body: string,
    maxSeenNonce?: string,
  ) {
    super(`HTTP ${status}: ${body}`);
    try {
      const parsed = JSON.parse(body) as ErrorResponse;
      if (typeof parsed?.error?.code === "string") {
        this.code = parsed.error.code;
        this.data = parsed.error.data;
      }
    } catch {
      // Not an Agent Identity error body.
    }
    if (maxSeenNonce !== undefined && maxSeenNonce !== null)
      this.maxSeenNonce = maxSeenNonce;
  }
}

/** Public reads require no signer. Discovery controls the optional search capability. */
export class KnowledgeClient {
  readonly service: string;
  private readonly endpoints: KnowledgeEndpoints;
  private readonly metadata?: KnowledgeDiscovery;
  constructor(
    service: string,
    private readonly fetchImpl: FetchLike = fetch,
    discovery?: KnowledgeDiscovery,
  ) {
    validateOrigin(service);
    this.service = service;
    if (discovery !== undefined) validateKnowledgeDiscovery(discovery, service);
    this.metadata =
      discovery === undefined ? undefined : structuredClone(discovery);
    this.endpoints = {
      events: `${service}/v1/knowledge/events`,
      query: `${service}/v1/knowledge/query`,
      batch: `${service}/v1/knowledge/batch`,
      ...discovery?.endpoints,
    };
  }
  static async discover(
    service: string,
    fetchImpl: FetchLike = fetch,
  ): Promise<KnowledgeClient> {
    const initial = new KnowledgeClient(service, fetchImpl);
    const discovery = await initial.protocol();
    return new KnowledgeClient(service, fetchImpl, discovery);
  }
  async protocol(): Promise<KnowledgeDiscovery> {
    const value = await this.request(
      `${this.service}/.well-known/agent-knowledge`,
    );
    validateKnowledgeDiscovery(value, this.service);
    return value;
  }
  async event(id: string): Promise<KnowledgeRecord> {
    validateKnowledgeId(id, "invalid_request");
    const result = await this.request(`${this.endpoints.events}/${id}`);
    validateKnowledgeRecord(result, id);
    return result;
  }
  async submit(
    envelope: KnowledgeEnvelope,
    jwt?: string,
  ): Promise<KnowledgeRecord> {
    envelope = structuredClone(envelope);
    validateKnowledgeEnvelope(envelope);
    const result = await this.request(this.endpoints.events, envelope, jwt);
    validateKnowledgeRecord(result, envelope.hash);
    return result;
  }
  async query(request: KnowledgeQuery = {}): Promise<KnowledgeQueryResponse> {
    request = structuredClone(request);
    validateKnowledgeQuery(request);
    const result = await this.request(
      addQuery(this.endpoints.query, { ...request }),
    );
    validateKnowledgeQueryResponse(result, request, this.service);
    return result;
  }
  /**
   * Validated pages of one checkpoint-bound enumeration. Persist the checkpoint
   * as the next `after_seq` only after iteration completes.
   */
  async *queryPages(
    request: KnowledgeQuery = {},
  ): AsyncGenerator<KnowledgeQueryResponse> {
    request = structuredClone(request);
    if (request.cursor !== undefined)
      throw protocolError(
        "invalid_request",
        "queryPages must start without a cursor",
      );
    const tracker = new KnowledgePageTracker(this.service);
    let cursor: string | undefined;
    do {
      const current = {
        ...request,
        ...(cursor === undefined ? {} : { cursor }),
      };
      const response = await this.query(current);
      tracker.accept(current, response);
      cursor = response.next_cursor;
      yield response;
    } while (cursor !== undefined);
  }
  async batch(hashes: string[]): Promise<KnowledgeBatchResponse> {
    hashes = [...hashes];
    const request = { hashes };
    validateKnowledgeBatchRequest(request);
    const result = await this.request(this.endpoints.batch, request);
    validateKnowledgeBatchResponse(result, hashes, this.service);
    return result;
  }
  async search(
    request: KnowledgeSearchRequest,
  ): Promise<KnowledgeSearchResponse> {
    request = structuredClone(request);
    validateKnowledgeSearchRequest(request, this.metadata?.search_modes ?? []);
    if (
      !this.metadata?.features?.includes("ranked-search") ||
      !this.endpoints.search
    )
      throw protocolError(
        "unsupported_search_mode",
        "service has not advertised ranked search",
      );
    const result = await this.request(this.endpoints.search, request);
    validateKnowledgeSearchResponse(result, request, this.service);
    return result;
  }
  private async request(
    url: string,
    body?: unknown,
    jwt?: string,
  ): Promise<unknown> {
    if (new URL(url).origin !== this.service)
      throw protocolError("invalid_request", "cross-origin endpoint");
    if (jwt !== undefined) verifyRequestJwt(jwt, { audience: this.service });
    const response = await this.fetchImpl(url, {
      method: body === undefined ? "GET" : "POST",
      redirect: "error",
      credentials: "omit",
      headers: {
        accept: "application/json",
        ...(body === undefined ? {} : { "content-type": "application/json" }),
        ...(jwt === undefined ? {} : { authorization: `Bearer ${jwt}` }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (response.url && new URL(response.url).origin !== this.service)
      throw protocolError(
        "invalid_response",
        "response came from another origin",
      );
    const text = await response.text();
    if (!response.ok)
      throw new HttpResponseError(
        response.status,
        text,
        response.headers.get(MAX_NONCE_HEADER) ?? undefined,
      );
    if (response.status !== 200)
      throw protocolError(
        "invalid_response",
        "Knowledge success requires HTTP 200",
      );
    try {
      return parseStrictJson(text);
    } catch {
      throw protocolError(
        "invalid_response",
        "response violates strict I-JSON",
      );
    }
  }
}
