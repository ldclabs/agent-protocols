export type McpAuthorizationMode = "none" | "agent-jwt";

export interface McpAuthorizationMetadata {
  mode: McpAuthorizationMode;
  agent_jwt_audience?: string;
}

export interface McpServiceInterfaceDiscovery {
  spec_version: "2025-11-25";
  endpoint: string;
  transport: "streamable-http";
  authorization?: McpAuthorizationMetadata;
  tools?: string[];
  resources?: string[];
  prompts?: string[];
  extra?: Record<string, unknown>;
}
