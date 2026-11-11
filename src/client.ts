import { wrapFetchWithPaymentFromConfig } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm";
import { privateKeyToAccount } from "viem/accounts";
import { GuardConfigError, GuardError } from "./errors.js";
import { NETWORK } from "./services.js";

const KEY_RE = /^0x[0-9a-fA-F]{64}$/;
const DEFAULT_TIMEOUT_MS = 15_000;

export type PaidFetch = typeof fetch;

export type ClientOptions = {
  /** Caller wallet. Falls back to X402_PRIVATE_KEY, PRIVATE_KEY, or EVM_PRIVATE_KEY. */
  privateKey?: string;
  /**
   * Injected fetch. Use this in tests (mocked, never pays) or to supply a
   * pre-wrapped x402 fetch. When set, no private key is read or required.
   */
  fetch?: PaidFetch;
  timeoutMs?: number;
};

export function readPrivateKey(explicit?: string): string | undefined {
  return explicit || process.env.X402_PRIVATE_KEY || process.env.PRIVATE_KEY || process.env.EVM_PRIVATE_KEY;
}

export function createPaidFetch(opts: ClientOptions = {}): PaidFetch {
  if (opts.fetch) return opts.fetch;
  const pk = readPrivateKey(opts.privateKey);
  if (!pk) {
    throw new GuardConfigError(
      "Missing X402_PRIVATE_KEY (or PRIVATE_KEY / EVM_PRIVATE_KEY). Set the caller's Base USDC wallet key. GrindFree never supplies keys. For tests, pass { fetch } with a mock.",
    );
  }
  if (!KEY_RE.test(pk)) {
    throw new GuardConfigError("X402_PRIVATE_KEY / PRIVATE_KEY / EVM_PRIVATE_KEY must be 0x + 64 hex characters (caller wallet only).");
  }
  const account = privateKeyToAccount(pk as `0x${string}`);
  return wrapFetchWithPaymentFromConfig(fetch, {
    schemes: [{ network: NETWORK, client: new ExactEvmScheme(account) }],
  });
}

export async function postJson(
  paidFetch: PaidFetch,
  url: string,
  body: unknown,
  opts: { timeoutMs?: number; service: string } = { service: "unknown" },
): Promise<Record<string, unknown>> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res: Response;
  try {
    res = await paidFetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body ?? {}),
      signal: controller.signal,
    });
  } catch (err) {
    const aborted = err instanceof Error && err.name === "AbortError";
    throw new GuardError(aborted ? `Request timed out after ${timeoutMs}ms` : err instanceof Error ? err.message : String(err), {
      service: opts.service,
    });
  } finally {
    clearTimeout(timer);
  }

  const text = await res.text();
  let json: Record<string, unknown>;
  try {
    json = text ? (JSON.parse(text) as Record<string, unknown>) : {};
  } catch {
    json = { raw: text.slice(0, 2000) };
  }
  if (!res.ok) {
    throw new GuardError(`${opts.service} HTTP ${res.status}`, {
      service: opts.service,
      status: res.status,
      body: json,
    });
  }
  return json;
}
