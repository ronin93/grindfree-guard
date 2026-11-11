import type { PaidFetch } from "../src/client.js";

export type MockRoute = {
  urlIncludes: string;
  status?: number;
  body: unknown;
  delayMs?: number;
};

/**
 * A fetch mock that never talks to the network and never pays.
 * Routes are matched on substring of the request URL, in order.
 */
export function mockPaidFetch(routes: MockRoute[], calls?: Array<{ url: string; body: unknown }>): PaidFetch {
  const log = calls ?? [];
  return async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    let parsed: unknown = undefined;
    if (typeof init?.body === "string") {
      try {
        parsed = JSON.parse(init.body);
      } catch {
        parsed = init.body;
      }
    }
    log.push({ url, body: parsed });
    const route = routes.find((r) => url.includes(r.urlIncludes));
    if (!route) {
      return new Response(JSON.stringify({ error: `unmocked ${url}` }), {
        status: 500,
        headers: { "content-type": "application/json" },
      });
    }
    if (route.delayMs) {
      const signal = init?.signal;
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(resolve, route.delayMs);
        if (!signal) return;
        if (signal.aborted) {
          clearTimeout(timer);
          reject(Object.assign(new Error("The operation was aborted"), { name: "AbortError" }));
          return;
        }
        signal.addEventListener(
          "abort",
          () => {
            clearTimeout(timer);
            reject(Object.assign(new Error("The operation was aborted"), { name: "AbortError" }));
          },
          { once: true },
        );
      });
    }
    return new Response(JSON.stringify(route.body), {
      status: route.status ?? 200,
      headers: { "content-type": "application/json" },
    });
  };
}
