import {
  DiscourseProtocolDiscovery,
  RoomCreatePayload,
  RoomCreateResponse,
  RoomJoinPayload,
  RoomLeavePayload,
  ServerRecord,
} from "./discourse.js";
import { AgentId, Envelope } from "./identity.js";
import {
  AgentProfile,
  ProfileReadResponse,
  ProfileUpdatePayload,
} from "./profile.js";

export type FetchLike = typeof fetch;

export class ProfileClient {
  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: FetchLike = fetch,
  ) {}

  async getProfile(agentId: AgentId): Promise<ProfileReadResponse> {
    return this.getJson(`/v1/profiles/${agentId}`);
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
    return this.getJson("/v1/protocol");
  }

  async createRoom(
    envelope: Envelope<RoomCreatePayload>,
  ): Promise<RoomCreateResponse> {
    return this.postJson("/v1/rooms", envelope);
  }

  async joinRoom(
    roomId: string,
    envelope: Envelope<RoomJoinPayload>,
  ): Promise<unknown> {
    return this.postJson(`/v1/rooms/${roomId}/join`, envelope);
  }

  async leaveRoom(
    roomId: string,
    envelope: Envelope<RoomLeavePayload>,
  ): Promise<unknown> {
    return this.postJson(`/v1/rooms/${roomId}/leave`, envelope);
  }

  async submitEvent<P>(
    roomId: string,
    envelope: Envelope<P>,
  ): Promise<ServerRecord> {
    return this.postJson(`/v1/rooms/${roomId}/events`, envelope);
  }

  async events(roomId: string): Promise<ServerRecord[]> {
    return this.getJson(`/v1/rooms/${roomId}/events`);
  }

  async archive(roomId: string): Promise<unknown> {
    return this.getJson(`/v1/rooms/${roomId}/archive`);
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

async function readJson<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`HTTP ${response.status}: ${text}`);
  }
  return response.json() as Promise<T>;
}
