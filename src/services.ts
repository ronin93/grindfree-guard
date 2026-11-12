/** Live GrindFree x402 origins, prices, and paths. USDC on Base. */

export const NETWORK = "eip155:8453" as const;
export const PAY_TO = "0xe4b5827994B7B3Cd38F9830d9ECF58b51B77721b" as const;

export type ServiceName =
  | "promptshield"
  | "crawlsafe"
  | "toolguard"
  | "commandguard"
  | "memoryguard"
  | "wireshield"
  | "docshield"
  | "saferead"
  | "askhuman";

export interface EndpointSpec {
  path: string;
  priceUsdc: string;
}

export interface ServiceSpec {
  origin: string;
  endpoints: Record<string, EndpointSpec>;
}

export const SERVICES = {
  promptshield: {
    origin: "https://promptshield.grindfree.net",
    endpoints: {
      screen: { path: "/v1/screen", priceUsdc: "0.002" },
      clean: { path: "/v1/clean", priceUsdc: "0.002" },
    },
  },
  crawlsafe: {
    origin: "https://crawlsafe.grindfree.net",
    endpoints: {
      check: { path: "/v1/check", priceUsdc: "0.002" },
    },
  },
  toolguard: {
    origin: "https://toolguard.grindfree.net",
    endpoints: {
      evaluate: { path: "/v1/evaluate", priceUsdc: "0.002" },
    },
  },
  commandguard: {
    origin: "https://commandguard.grindfree.net",
    endpoints: {
      command: { path: "/v1/command", priceUsdc: "0.001" },
      sql: { path: "/v1/sql", priceUsdc: "0.001" },
    },
  },
  memoryguard: {
    origin: "https://memoryguard.grindfree.net",
    endpoints: {
      screen: { path: "/v1/screen", priceUsdc: "0.002" },
    },
  },
  wireshield: {
    origin: "https://wireshield.grindfree.net",
    endpoints: {
      scan: { path: "/v1/scan", priceUsdc: "0.002" },
    },
  },
  docshield: {
    origin: "https://docshield.grindfree.net",
    endpoints: {
      scan: { path: "/v1/scan", priceUsdc: "0.004" },
    },
  },
  saferead: {
    origin: "https://saferead.grindfree.net",
    endpoints: {
      read: { path: "/v1/read", priceUsdc: "0.003" },
    },
  },
  askhuman: {
    origin: "https://askhuman.grindfree.net",
    endpoints: {
      request: { path: "/v1/request", priceUsdc: "0.03" },
    },
  },
} as const satisfies Record<ServiceName, ServiceSpec>;

export function serviceUrl(service: ServiceName, endpoint: string): string {
  const spec = SERVICES[service] as ServiceSpec;
  const ep = spec.endpoints[endpoint];
  if (!ep) throw new Error(`Unknown endpoint ${service} ${endpoint}`);
  return `${spec.origin}${ep.path}`;
}
