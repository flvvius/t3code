import { describe, expect, it } from "vite-plus/test";

import {
  canChooseSelfHostedRelay,
  discoverSelfHostedRelay,
  encodeSelfHostedRelay,
  parseRelayPolicy,
  parseStoredSelfHostedRelay,
} from "./selfHostedRelay.ts";

const OIDC = { issuer: "https://sso.example.com", clientId: "t3-code" };

const replying = (reply: () => Response) => {
  const requests: Array<string> = [];
  const fetchImpl = (async (input: RequestInfo | URL) => {
    requests.push(String(input));
    return reply();
  }) as typeof fetch;
  return { requests, fetchImpl };
};

describe("discoverSelfHostedRelay", () => {
  it("reads the sign-in provider from the relay, accepting a bare host name", async () => {
    const { requests, fetchImpl } = replying(() =>
      Response.json({ oidc: OIDC, managedTunnels: false }),
    );
    await expect(discoverSelfHostedRelay(" relay.example.com/ ", { fetch: fetchImpl })).resolves.toEqual({
      relayUrl: "https://relay.example.com",
      oidcIssuer: OIDC.issuer,
      oidcClientId: OIDC.clientId,
      managedTunnels: false,
    });
    expect(requests).toEqual(["https://relay.example.com/.well-known/t3-relay"]);
  });

  it.each([
    ["http://relay.example.com", () => Response.json({ oidc: OIDC, managedTunnels: false })],
    ["relay.example.com", () => new Response("not found", { status: 404 })],
    ["relay.example.com", () => Response.json({ oidc: { issuer: OIDC.issuer } })],
    ["relay.example.com", () => Response.json({ oidc: null, managedTunnels: true })],
  ])("rejects %s when the relay cannot be used", async (address, reply) => {
    const { fetchImpl } = replying(reply);
    await expect(discoverSelfHostedRelay(address, { fetch: fetchImpl })).rejects.toThrow();
  });
});

describe("parseStoredSelfHostedRelay", () => {
  it("round-trips a stored relay and ignores anything else", () => {
    const relay = {
      relayUrl: "https://relay.example.com",
      oidcIssuer: OIDC.issuer,
      oidcClientId: OIDC.clientId,
      managedTunnels: false,
    };
    expect(parseStoredSelfHostedRelay(encodeSelfHostedRelay(relay))).toEqual(relay);
    expect(parseStoredSelfHostedRelay(null)).toBeNull();
    expect(parseStoredSelfHostedRelay("{")).toBeNull();
    expect(
      parseStoredSelfHostedRelay(
        encodeSelfHostedRelay({ ...relay, relayUrl: "http://relay.example.com" }),
      ),
    ).toBeNull();
  });
});

describe("relay policy", () => {
  const relay = {
    relayUrl: "https://relay.example.com",
    oidcIssuer: OIDC.issuer,
    oidcClientId: OIDC.clientId,
    managedTunnels: false,
  };

  it.each([
    [{}, true, true],
    [{ pinned: "true" }, false, false],
    [{ pinned: "1", allowlist: "https://relay.example.com" }, false, false],
    [{ allowlist: "https://other.example.com, https://relay.example.com/" }, true, true],
    [{ allowlist: "https://other.example.com" }, true, false],
    // A list with nothing usable in it fails closed instead of allowing every relay.
    [{ allowlist: "http://relay.example.com" }, false, false],
  ])("%j offers the choice: %s, keeps the stored relay: %s", (input, offered, kept) => {
    const policy = parseRelayPolicy(input);
    expect(canChooseSelfHostedRelay(policy)).toBe(offered);
    expect(parseStoredSelfHostedRelay(encodeSelfHostedRelay(relay), policy)).toEqual(
      kept ? relay : null,
    );
  });

  it.each([{ pinned: "true" }, { allowlist: "https://other.example.com" }])(
    "refuses a relay %j does not allow before contacting it",
    async (input) => {
      const { requests, fetchImpl } = replying(() =>
        Response.json({ oidc: OIDC, managedTunnels: false }),
      );
      await expect(
        discoverSelfHostedRelay("relay.example.com", {
          fetch: fetchImpl,
          policy: parseRelayPolicy(input),
        }),
      ).rejects.toThrow(/only connects/u);
      expect(requests).toEqual([]);
    },
  );
});
