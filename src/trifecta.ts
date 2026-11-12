/** TrifectaGate: session-aware exfiltration gate ($0.002 per check). */
export type TrifectaEvent = {
  type: "private_data" | "untrusted_content";
  source: string;
  origin?: string;
  verdict?: "allow" | "warn" | "review" | "block" | "deny";
  labels?: string[];
};
export type EgressAction = {
  type: "http_request" | "webhook" | "email" | "message" | "image_url" | "dns" | "payment" | "file_write" | "code_exec" | "tool_call";
  destination?: string;
  tool?: string;
  method?: string;
  payload_preview?: string;
  data_classes?: string[];
};
export type TrifectaPolicy = {
  mode?: "balanced" | "strict";
  allow_hosts?: string[];
  internal_domains?: string[];
  trusted_sources?: string[];
};
export type EgressInput = {
  session_id?: string;
  session_ttl_seconds?: number;
  events?: TrifectaEvent[];
  action?: EgressAction;
  policy?: TrifectaPolicy;
  session_facts?: { private_data?: boolean; untrusted_content?: boolean; untrusted_flagged?: boolean };
};

/** Random, unguessable session id (sess_ + 32 hex). */
export function newSessionId(): string {
  const a = new Uint8Array(16);
  crypto.getRandomValues(a);
  return "sess_" + [...a].map((b) => b.toString(16).padStart(2, "0")).join("");
}
