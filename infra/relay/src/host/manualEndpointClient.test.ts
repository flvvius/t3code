import type * as Dns from "node:dns";

import { describe, expect, it } from "@effect/vitest";
import * as Effect from "effect/Effect";

import {
  EndpointAddressBlocked,
  endpointAddressRejection,
  makeGuardedLookup,
  makeManualEndpointHttpClient,
} from "./manualEndpointClient.ts";

const lookupWith =
  (addresses: ReadonlyArray<Dns.LookupAddress>, policy: "public" | "private" = "public") =>
  (all: boolean) =>
    new Promise<{ error: Error | null; result: unknown }>((resolve) =>
      makeGuardedLookup(policy, (_hostname, _options, callback) => callback(null, [...addresses]))(
        "t3.example.dev",
        { all },
        (error, address, family) => resolve({ error, result: all ? address : [address, family] }),
      ),
    );

describe("endpointAddressRejection", () => {
  it.each([
    ["127.0.0.1", "internal_address"],
    ["0.0.0.0", "internal_address"],
    ["169.254.169.254", "internal_address"],
    ["224.0.0.1", "internal_address"],
    ["255.255.255.255", "internal_address"],
    ["::", "internal_address"],
    ["::1", "internal_address"],
    ["fe80::1", "internal_address"],
    ["ff02::1", "internal_address"],
    ["::ffff:127.0.0.1", "internal_address"],
    ["::ffff:a9fe:a9fe", "internal_address"],
    ["64:ff9b::a9fe:a9fe", "internal_address"],
    ["2002:a9fe:a9fe::1", "internal_address"],
    ["10.0.0.5", "private_network"],
    ["172.16.4.1", "private_network"],
    ["192.168.1.1", "private_network"],
    ["100.64.0.1", "private_network"],
    ["fd00::1", "private_network"],
    ["::ffff:10.0.0.5", "private_network"],
    ["8.8.8.8", null],
    ["2606:4700::1111", null],
    ["::ffff:8.8.8.8", null],
  ] as const)("classifies %s", (address, rejection) => {
    expect(endpointAddressRejection(address, "public")).toBe(rejection);
  });

  it("allows private networks, but never internal addresses, when the relay opts in", () => {
    expect(endpointAddressRejection("10.0.0.5", "private")).toBeNull();
    expect(endpointAddressRejection("fd00::1", "private")).toBeNull();
    expect(endpointAddressRejection("169.254.169.254", "private")).toBe("internal_address");
    expect(endpointAddressRejection("127.0.0.1", "private")).toBe("internal_address");
  });
});

describe("makeGuardedLookup", () => {
  it("hands the socket the addresses it checked", async () => {
    const lookup = lookupWith([{ address: "8.8.8.8", family: 4 }]);
    expect(await lookup(true)).toEqual({
      error: null,
      result: [{ address: "8.8.8.8", family: 4 }],
    });
    expect(await lookup(false)).toEqual({ error: null, result: ["8.8.8.8", 4] });
  });

  it("refuses the whole answer when any address is internal", async () => {
    const { error } = await lookupWith([
      { address: "8.8.8.8", family: 4 },
      { address: "127.0.0.1", family: 4 },
    ])(true);
    expect(error).toBeInstanceOf(EndpointAddressBlocked);
    expect(error).toMatchObject({ address: "127.0.0.1", rejection: "internal_address" });
  });

  it("refuses names that resolve to a private network unless the relay allows them", async () => {
    const answer = [{ address: "10.1.2.3", family: 4 }] as const;
    expect((await lookupWith(answer)(false)).error).toMatchObject({
      rejection: "private_network",
    });
    expect((await lookupWith(answer, "private")(false)).error).toBeNull();
  });
});

describe("makeManualEndpointHttpClient", () => {
  it.effect("refuses literal internal addresses and plain HTTP before connecting", () =>
    Effect.gen(function* () {
      const client = yield* makeManualEndpointHttpClient("public");
      for (const url of [
        "https://169.254.169.254/latest",
        "https://[::1]/",
        "http://t3.example/",
      ]) {
        const error = yield* Effect.flip(client.get(url));
        expect(error.reason._tag === "TransportError" && error.reason.cause).toBeInstanceOf(
          EndpointAddressBlocked,
        );
      }
    }).pipe(Effect.scoped),
  );
});
