// Shared primitives used across the local connector submodules: value guards,
// host normalization, and the two error constructors. Kept out of the public
// barrel — nothing here is part of the connector's interface.

import { protocolError } from "../errors.js";

/** ADP `invalid_payload` — the connector's generic client-side rejection. */
export function invalidPayload(message: string): Error {
  return protocolError("invalid_payload", message);
}

export function permissionDenied(): Error {
  return protocolError("permission_denied", "permission denied");
}

export function normalizeHost(host: string): string {
  return host.replace(/\/$/, "");
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
