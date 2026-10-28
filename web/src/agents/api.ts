import { request } from "../api/client";
import type { components } from "../api/schema";

type S = components["schemas"];
export type Agent = S["Agent"];
export type McpServer = S["MCPServer"];
export type AgentTool = S["AgentTool"];
export type AgentToolDetail = S["AgentToolDetail"];
export type Risk = AgentTool["risk"];
export type ToolStatus = AgentTool["status"];

const id = encodeURIComponent;

export interface ToolFilter {
  status?: ToolStatus;
  mcp_server_id?: string;
}

// Права проверяет сервер, консоль только скрывает недоступное. Учётные данные MCP-серверов только отправляются, обратно не приходят.
export const agentsApi = {
  agents: (signal?: AbortSignal) => request<S["AgentList"]>("GET", "/api/v1/agents", undefined, signal),
  servers: (signal?: AbortSignal) => request<S["MCPServerList"]>("GET", "/api/v1/mcp-servers", undefined, signal),
  tools: (f: ToolFilter, signal?: AbortSignal) => {
    const p = new URLSearchParams();
    if (f.status) p.set("status", f.status);
    if (f.mcp_server_id) p.set("mcp_server_id", f.mcp_server_id);
    const q = p.toString();
    return request<S["AgentToolList"]>("GET", `/api/v1/agent-tools${q ? `?${q}` : ""}`, undefined, signal);
  },
  tool: (tid: string, signal?: AbortSignal) => request<AgentToolDetail>("GET", `/api/v1/agent-tools/${id(tid)}`, undefined, signal),
  approve: (tid: string, b: S["AgentToolApprove"]) => request<AgentTool>("POST", `/api/v1/agent-tools/${id(tid)}/approve`, b),
  revoke: (tid: string, comment: string) => request<AgentTool>("POST", `/api/v1/agent-tools/${id(tid)}/revoke`, comment ? { comment } : {}),
  setRisk: (tid: string, b: S["AgentToolRisk"]) => request<AgentTool>("PUT", `/api/v1/agent-tools/${id(tid)}/risk`, b),
  setCredential: (sid: string, credential: string) => request<McpServer>("PUT", `/api/v1/mcp-servers/${id(sid)}/credentials`, { credential }),
};
