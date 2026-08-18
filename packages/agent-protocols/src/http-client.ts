import {
  validateDelegationQueryRequest,
  validatePrincipalDocument,
  validatePrincipalResolution,
  type DelegationCredential,
  type DelegationEventsResponse,
  type DelegationPayload,
  type DelegationQueryRequest,
  type DelegationQueryResponse,
  type DelegationServiceDiscovery,
  type DelegationStatusDocument,
  type PrincipalDocument,
} from "./delegation.js";
import {
  AgentStatus,
  AgentStatusGetResponse,
  AgentStatusInput,
  AgentStatusListResponse,
  DiscourseProtocolDiscovery,
  RoomCreatePayload,
  RoomResponse,
  RoomJoinPayload,
  RoomJoinRequestInput,
  RoomJoinRequestStatus,
  RoomLeavePayload,
  ServerRecord,
} from "./discourse.js";
import { AgentId, Envelope } from "./identity.js";
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
    const query = cursor
      ? `limit=${limit}&cursor=${encodeURIComponent(cursor)}`
      : `limit=${limit}`;
    return this.getJson(`/v1/profiles/${agentId}/events?${query}`);
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

  async room(roomId: string): Promise<RoomResponse> {
    return this.getJson(`/v1/rooms/${roomId}`);
  }

  async publicRooms(options: PublicRoomsOptions = {}): Promise<RoomResponse[]> {
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

  async myRooms(jwt: string, options: MyRoomsOptions = {}): Promise<RoomResponse[]> {
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

  async requestJoin(
    roomId: string,
    jwt: string,
    request: RoomJoinRequestInput,
  ): Promise<RoomJoinRequestStatus> {
    return this.postJson(`/v1/rooms/${roomId}/join-requests`, request, jwt);
  }

  async joinRequest(
    roomId: string,
    requestId: string,
    jwt: string,
  ): Promise<RoomJoinRequestStatus> {
    return this.getJson(`/v1/rooms/${roomId}/join-requests/${requestId}`, jwt);
  }

  async joinRequests(
    roomId: string,
    jwt: string,
  ): Promise<RoomJoinRequestStatus[]> {
    return this.getJson(`/v1/rooms/${roomId}/join-requests`, jwt);
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
  ): Promise<ServerRecord[]> {
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
  ): Promise<AgentStatusGetResponse> {
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

export class DelegationClient {
  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: FetchLike = fetch,
  ) {}

  async protocol(): Promise<DelegationServiceDiscovery> {
    return this.getJson("/.well-known/agent-delegation");
  }

  /**
   * Resolves a principal document per Agent Delegation Section 5.3. A document
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
    return this.getJson(`/v1/delegations/${delegationId}`);
  }

  async delegationStatus(
    delegationId: string,
  ): Promise<DelegationStatusDocument> {
    return this.getJson(`/v1/delegations/${delegationId}/status`);
  }

  async delegationEvents(
    delegationId: string,
  ): Promise<DelegationEventsResponse> {
    return this.getJson(`/v1/delegations/${delegationId}/events`);
  }

  async submitDelegationEvent(
    envelope: Envelope<DelegationPayload>,
  ): Promise<DelegationCredential | DelegationStatusDocument> {
    return this.postJson("/v1/delegations", envelope);
  }

  /**
   * Public queries are existence checks and carry both `subject` and
   * `principal_id`. Pass `allowEnumeration` only for a request the service has
   * authorized to enumerate one side.
   */
  async queryDelegations(
    request: DelegationQueryRequest,
    options: { allowEnumeration?: boolean } = {},
  ): Promise<DelegationQueryResponse> {
    validateDelegationQueryRequest(request, options);
    return this.postJson("/v1/delegations/query", request);
  }

  private async readPrincipal(
    url: string,
  ): Promise<{ document: PrincipalDocument; resolvedUrl: string }> {
    const response = await this.fetchImpl(url, {
      headers: { accept: "application/json" },
    });
    const document = await readJson<PrincipalDocument>(response);
    validatePrincipalDocument(document);
    return { document, resolvedUrl: (response as { url?: string }).url || url };
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
    throw new Error(`HTTP ${response.status}: ${text}`);
  }
  return response.json() as Promise<T>;
}
