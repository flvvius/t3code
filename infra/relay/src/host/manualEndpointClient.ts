// @effect-diagnostics nodeBuiltinImport:off - the guard must see the addresses Node's own sockets dial.
import * as Dns from "node:dns";
import * as Net from "node:net";

import * as NodeHttpClient from "@effect/platform-node/NodeHttpClient";
import * as Effect from "effect/Effect";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientError from "effect/http/HttpClientError";
import * as Schema from "effect/Schema";

/** "public" refuses private networks too; "private" refuses only addresses that never name another machine. */
export type EndpointAddressPolicy = "public" | "private";
export type EndpointAddressRejection = "internal_address" | "private_network";

const blockList = (ranges: ReadonlyArray<readonly [string, number, "ipv4" | "ipv6"]>) => {
  const list = new Net.BlockList();
  for (const [network, prefix, family] of ranges) list.addSubnet(network, prefix, family);
  return list;
};

// Loopback, link-local (cloud metadata), unspecified, multicast and reserved space, plus the IPv6
// forms that embed an IPv4 address (compatible, NAT64, 6to4), which could carry any of these.
// BlockList also matches IPv4-mapped IPv6 (::ffff:a.b.c.d) against the IPv4 rules.
const INTERNAL = blockList([
  ["0.0.0.0", 8, "ipv4"],
  ["127.0.0.0", 8, "ipv4"],
  ["169.254.0.0", 16, "ipv4"],
  ["224.0.0.0", 4, "ipv4"],
  ["240.0.0.0", 4, "ipv4"],
  ["::", 96, "ipv6"],
  ["64:ff9b::", 96, "ipv6"],
  ["64:ff9b:1::", 48, "ipv6"],
  ["100::", 64, "ipv6"],
  ["2001::", 23, "ipv6"],
  ["2002::", 16, "ipv6"],
  ["fe80::", 10, "ipv6"],
  ["fec0::", 10, "ipv6"],
  ["ff00::", 8, "ipv6"],
]);

// Private, shared (CGNAT), documentation and benchmarking networks, and IPv6 unique-local.
const PRIVATE = blockList([
  ["10.0.0.0", 8, "ipv4"],
  ["100.64.0.0", 10, "ipv4"],
  ["172.16.0.0", 12, "ipv4"],
  ["192.0.0.0", 24, "ipv4"],
  ["192.0.2.0", 24, "ipv4"],
  ["192.88.99.0", 24, "ipv4"],
  ["192.168.0.0", 16, "ipv4"],
  ["198.18.0.0", 15, "ipv4"],
  ["198.51.100.0", 24, "ipv4"],
  ["203.0.113.0", 24, "ipv4"],
  ["2001:db8::", 32, "ipv6"],
  ["fc00::", 7, "ipv6"],
]);

export function endpointAddressRejection(
  address: string,
  policy: EndpointAddressPolicy,
): EndpointAddressRejection | null {
  const family = Net.isIP(address);
  if (family === 0) return "internal_address";
  const type = family === 4 ? "ipv4" : "ipv6";
  if (INTERNAL.check(address, type)) return "internal_address";
  return policy === "public" && PRIVATE.check(address, type) ? "private_network" : null;
}

export class EndpointAddressBlocked extends Schema.TaggedError<EndpointAddressBlocked>()(
  "EndpointAddressBlocked",
  {
    hostname: Schema.String,
    address: Schema.String,
    rejection: Schema.Literals(["internal_address", "private_network"]),
  },
) {
  override get message(): string {
    return `Endpoint ${this.hostname} resolves to '${this.address}', an address of kind ${this.rejection}`;
  }
}

const blocked = (hostname: string, address: string, rejection: EndpointAddressRejection) =>
  new EndpointAddressBlocked({ hostname, address, rejection });

type Resolve = (
  hostname: string,
  options: Dns.LookupAllOptions,
  callback: (error: NodeJS.ErrnoException | null, addresses: Array<Dns.LookupAddress>) => void,
) => void;

/**
 * A `lookup` for Node sockets that refuses the whole answer when any address is not allowed. The
 * socket then dials the address checked here, so a second DNS answer cannot swap it.
 */
export const makeGuardedLookup =
  (policy: EndpointAddressPolicy, resolve: Resolve = Dns.lookup): Net.LookupFunction =>
  (hostname, options, callback) => {
    resolve(hostname, { ...options, all: true }, (error, addresses) => {
      if (error) return callback(error, "", 0);
      const first = addresses[0];
      if (first === undefined) {
        return callback(blocked(hostname, "", "internal_address"), "", 0);
      }
      for (const { address } of addresses) {
        const rejection = endpointAddressRejection(address, policy);
        if (rejection !== null) {
          return callback(blocked(hostname, address, rejection), "", 0);
        }
      }
      return options.all ? callback(null, addresses) : callback(null, first.address, first.family);
    });
  };

/**
 * The client the relay uses for endpoints environments declare themselves. Sockets skip `lookup`
 * for IP literals, so those are checked here before any connection.
 */
export const makeManualEndpointHttpClient = Effect.fn("relay.node.manual_endpoint_client")(
  function* (policy: EndpointAddressPolicy) {
    const client = yield* NodeHttpClient.makeNodeHttp.pipe(
      Effect.provideServiceEffect(
        NodeHttpClient.HttpAgent,
        NodeHttpClient.makeAgent({ lookup: makeGuardedLookup(policy), keepAlive: false }),
      ),
    );
    return HttpClient.mapRequestEffect(client, (request) => {
      const url = URL.parse(request.url);
      const hostname = url?.hostname.replace(/^\[|\]$/gu, "") ?? "";
      const rejection =
        url?.protocol !== "https:"
          ? "internal_address"
          : Net.isIP(hostname) === 0
            ? null
            : endpointAddressRejection(hostname, policy);
      return rejection === null
        ? Effect.succeed(request)
        : Effect.fail(
            new HttpClientError.HttpClientError({
              reason: new HttpClientError.TransportError({
                request,
                cause: blocked(hostname, hostname, rejection),
              }),
            }),
          );
    });
  },
);
