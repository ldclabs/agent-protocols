import {
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
  ): Promise<ProfileEventsResponse> {
    return this.getJson(`/v1/profiles/${agentId}/events?limit=${limit}`);
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

  websocketEventsUrl(roomId: string, jwt: string): string {
    return websocketEventsUrl(this.baseUrl, roomId, jwt);
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

  private url(path: string): string {
    return `${this.baseUrl.replace(/\/$/, "")}/${path.replace(/^\//, "")}`;
  }
}

export function websocketEventsUrl(
  baseUrl: string,
  roomId: string,
  jwt: string,
): string {
  const websocketBase = baseUrl
    .replace(/\/$/, "")
    .replace(/^https:/, "wss:")
    .replace(/^http:/, "ws:");
  return `${websocketBase}/v1/rooms/${encodeURIComponent(roomId)}/events/live?access_token=${encodeURIComponent(jwt)}`;
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
