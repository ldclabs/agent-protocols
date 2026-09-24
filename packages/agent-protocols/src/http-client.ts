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
  ProfileBatchReadResponse,
  ProfileEventsResponse,
  ProfileUpdatePayload,
} from "./profile.js";

export type FetchLike = typeof fetch;

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

export class ProfileClient {
  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: FetchLike = fetch,
  ) {}

  async getProfile(agentId: AgentId): Promise<AgentProfile> {
    return this.getJson(`/v1/profiles/${agentId}`);
  }

  async getProfiles(agentIds: AgentId[]): Promise<ProfileBatchReadResponse> {
    return this.postJson("/v1/profiles/batch", { ids: agentIds });
  }

  async profileEvents(
    agentId: AgentId,
    limit = 1,
    cursor?: string,
  ): Promise<ProfileEventsResponse> {
    return this.getJson(addQuery(`/v1/profiles/${agentId}/events`, { limit, cursor }));
  }

  async submitProfileUpdate(
    envelope: Envelope<ProfileUpdatePayload>,
  ): Promise<AgentProfile> {
    return this.postJson("/v1/profiles", envelope);
  }

  private async getJson<T>(path: string): Promise<T> {
    const response = await this.fetchImpl(this.url(path));
    return readJson<T>(response);
  }

  private async postJson<T>(path: string, body: unknown): Promise<T> {
    const response = await this.fetchImpl(this.url(path), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return readJson<T>(response);
  }

  private url(path: string): string {
    return `${this.baseUrl.replace(/\/$/, "")}/${path.replace(/^\//, "")}`;
  }
}

export class DiscourseClient {
  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: FetchLike = fetch,
  ) {}

  async protocol(): Promise<DiscourseProtocolDiscovery> {
    return this.getJson("/.well-known/agent-discourse");
  }

  async createRoom(
    envelope: Envelope<RoomCreatePayload>,
  ): Promise<RoomResponse> {
    return this.postJson("/v1/rooms", envelope);
  }

  async room(roomId: string, jwt?: string): Promise<RoomResponse> {
    return this.getJson(`/v1/rooms/${roomId}`, jwt);
  }

  async publicRooms(options: PublicRoomsOptions = {}): Promise<ListResponse<RoomResponse>> {
    return this.getJson(
      addQuery("/v1/rooms/public", {
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

  async myRooms(jwt: string, options: MyRoomsOptions = {}): Promise<ListResponse<RoomResponse>> {
    return this.getJson(
      addQuery("/v1/me/rooms", {
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
    return this.postJson(`/v1/rooms/${roomId}/join-requests`, envelope);
  }

  async joinRequest(
    roomId: string,
    requestId: string,
    jwt: string,
  ): Promise<RoomJoinRequest> {
    return this.getJson(`/v1/rooms/${roomId}/join-requests/${requestId}`, jwt);
  }

  async joinRequests(
    roomId: string,
    jwt: string,
    options: JoinRequestsOptions = {},
  ): Promise<ListResponse<RoomJoinRequest>> {
    return this.getJson(
      addQuery(`/v1/rooms/${roomId}/join-requests`, {
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
    return this.postJson(`/v1/rooms/${roomId}`, envelope);
  }

  async leaveRoom(
    roomId: string,
    envelope: Envelope<RoomLeavePayload>,
  ): Promise<ServerRecord<RoomLeavePayload>> {
    return this.postJson(`/v1/rooms/${roomId}`, envelope);
  }

  async submitEvent<P>(
    roomId: string,
    envelope: Envelope<P>,
  ): Promise<ServerRecord<P>> {
    return this.postJson(`/v1/rooms/${roomId}`, envelope);
  }

  async events(
    roomId: string,
    options: RoomEventsOptions = {},
  ): Promise<RoomEventsResponse> {
    return this.getJson(
      addQuery(`/v1/rooms/${roomId}/events`, {
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
    return this.getJson(`/v1/rooms/${roomId}/agent-status`, jwt);
  }

  async agentStatus(
    roomId: string,
    agentId: AgentId,
    jwt?: string,
  ): Promise<AgentStatus> {
    return this.getJson(`/v1/rooms/${roomId}/agent-status/${agentId}`, jwt);
  }

  async setAgentStatus(
    roomId: string,
    jwt: string,
    status: AgentStatusInput,
  ): Promise<AgentStatus> {
    return this.putJson(`/v1/rooms/${roomId}/agent-status`, status, jwt);
  }

  sseEventsUrl(roomId: string): string {
    return sseEventsUrl(this.baseUrl, roomId);
  }

  async archive(roomId: string): Promise<unknown> {
    return this.getJson(`/v1/rooms/${roomId}/archive`);
  }

  private async getJson<T>(path: string, jwt?: string): Promise<T> {
    const response = await this.fetchImpl(this.url(path), {
      headers: jwt ? { authorization: `Bearer ${jwt}` } : undefined,
    });
    return readJson<T>(response);
  }

  private async postJson<T>(
    path: string,
    body: unknown,
    jwt?: string,
  ): Promise<T> {
    const response = await this.fetchImpl(this.url(path), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(jwt ? { authorization: `Bearer ${jwt}` } : {}),
      },
      body: JSON.stringify(body),
    });
    return readJson<T>(response);
  }

  private async putJson<T>(
    path: string,
    body: unknown,
    jwt?: string,
  ): Promise<T> {
    const response = await this.fetchImpl(this.url(path), {
      method: "PUT",
      headers: {
        "content-type": "application/json",
        ...(jwt ? { authorization: `Bearer ${jwt}` } : {}),
      },
      body: JSON.stringify(body),
    });
    return readJson<T>(response);
  }

  private url(path: string): string {
    return `${this.baseUrl.replace(/\/$/, "")}/${path.replace(/^\//, "")}`;
  }
}

/**
 * Agent Delegation client. Without `endpoints` it uses the RECOMMENDED paths
 * under `baseUrl`; {@link DelegationClient.discover} reads the service's
 * discovery document instead, whose endpoints clients MUST prefer.
 */
export class DelegationClient {
  private readonly delegationsUrl: string;
  private readonly queryUrl: string;

  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: FetchLike = fetch,
    endpoints?: Partial<DelegationServiceEndpoints>,
  ) {
    const base = baseUrl.replace(/\/$/, "");
    this.delegationsUrl = (endpoints?.delegations ?? `${base}/v1/delegations`).replace(/\/$/, "");
    this.queryUrl = endpoints?.query ?? `${this.delegationsUrl}/query`;
  }

  /**
   * Builds a client for the service at `origin` from its discovery document,
   * falling back to the default paths when the service publishes none.
   */
  static async discover(origin: string, fetchImpl: FetchLike = fetch): Promise<DelegationClient> {
    const base = origin.replace(/\/$/, "");
    try {
      const response = await fetchImpl(`${base}/.well-known/agent-delegation`);
      if (response.ok) {
        const discovery = (await response.json()) as DelegationServiceDiscovery;
        return new DelegationClient(base, fetchImpl, discovery.endpoints);
      }
    } catch {
      // Discovery is optional; the default paths apply.
    }
    return new DelegationClient(base, fetchImpl);
  }

  async protocol(): Promise<DelegationServiceDiscovery> {
    return this.getJson(`${this.baseUrl.replace(/\/$/, "")}/.well-known/agent-delegation`);
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
    return this.getJson(addQuery(`${this.delegationsUrl}/${delegationId}/events`, { cursor }));
  }

  /** Every accepted record of a credential, following `next_cursor`. */
  async allDelegationEvents(delegationId: string): Promise<DelegationEventsResponse["result"]> {
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
   * Queries the endpoint a principal document names in its
   * `delegation_query_url`. That is how a relying party reaches the
   * authoritative service for a principal without trusting a URL supplied by
   * whoever presented the credential.
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
    return readJson<DelegationQueryResponse>(response);
  }

  private async readPrincipal(
    url: string,
  ): Promise<{ document: PrincipalDocument; resolvedUrl: string }> {
    for (let redirects = 0; ; redirects++) {
      if (new URL(url).protocol !== "https:") throw new Error("principal resolution requires HTTPS");
      const response = await this.fetchImpl(url, { headers: { accept: "application/json" }, redirect: "manual" });
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        if (!location || redirects >= 5) throw new Error("invalid principal redirect chain");
        url = new URL(location, url).href;
        continue;
      }
      const document = await readJson<PrincipalDocument>(response);
      const resolvedUrl = response.url || url;
      if (new URL(resolvedUrl).protocol !== "https:" || typeof document?.id !== "string" || new URL(document.id).protocol !== "https:") throw new Error("invalid principal HTTPS URL");
      // Copies contribute only the canonical ID, never authority fields.
      if (document.id === resolvedUrl) validatePrincipalDocument(document);
      return { document, resolvedUrl };
    }
  }

  private async getJson<T>(url: string): Promise<T> {
    const response = await this.fetchImpl(url);
    return readJson<T>(response);
  }

  private async postJson<T>(url: string, body: unknown): Promise<T> {
    const response = await this.fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return readJson<T>(response);
  }
}

export function sseEventsUrl(baseUrl: string, roomId: string): string {
  return `${baseUrl.replace(/\/$/, "")}/v1/rooms/${encodeURIComponent(roomId)}/events/live`;
}

function addQuery(
  path: string,
  params: Record<string, string | number | undefined>,
): string {
  const encoded = Object.entries(params)
    .filter((entry): entry is [string, string | number] => entry[1] !== undefined)
    .map(
      ([key, value]) =>
        `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`,
    )
    .join("&");
  return encoded ? `${path}?${encoded}` : path;
}

async function readJson<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const text = await response.text();
    throw new HttpResponseError(response.status, text, response.headers?.get?.(MAX_NONCE_HEADER) ?? undefined);
  }
  return response.json() as Promise<T>;
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

  constructor(public readonly status: number, body: string, maxSeenNonce?: string) {
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
    if (maxSeenNonce !== undefined && maxSeenNonce !== null) this.maxSeenNonce = maxSeenNonce;
  }
}
