import { request } from "../api/client";
import type { components } from "../api/schema";

type S = components["schemas"];
export type Approval = S["Approval"];
export type ApprovalState = Approval["state"];

const id = encodeURIComponent;

export const approvalsApi = {
  list: (state: ApprovalState | undefined, signal?: AbortSignal) =>
    request<S["ApprovalList"]>("GET", `/api/v1/approvals?limit=100${state ? `&state=${state}` : ""}`, undefined, signal),
  get: (aid: string, signal?: AbortSignal) => request<Approval>("GET", `/api/v1/approvals/${id(aid)}`, undefined, signal),
  approve: (aid: string, b: S["ApprovalApprove"]) => request<Approval>("POST", `/api/v1/approvals/${id(aid)}/approve`, b),
  deny: (aid: string, comment: string) => request<Approval>("POST", `/api/v1/approvals/${id(aid)}/deny`, comment ? { comment } : {}),
};
