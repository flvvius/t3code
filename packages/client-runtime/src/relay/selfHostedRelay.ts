import { RelayServiceMetadata } from "@t3tools/contracts/relay";
import { normalizeSecureRelayUrl } from "@t3tools/shared/relayUrl";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";

/** Where each app keeps the relay a user chose instead of the build's default T3 Connect. */
export const SELF_HOSTED_RELAY_STORAGE_KEY = "t3-connect-self-hosted-relay";

export const SelfHostedRelay = Schema.Struct({
  relayUrl: Schema.String,
  oidcIssuer: Schema.String,
  oidcClientId: Schema.String,
  managedTunnels: Schema.Boolean,
});
export type SelfHostedRelay = typeof SelfHostedRelay.Type;

/** Which relays a build lets the user choose instead of its own. */
export interface RelayPolicy {
  /** Only the build's relay; the self-hosted choice is hidden and any stored one ignored. */
  readonly pinned: boolean;
  /** HTTPS origins the self-hosted choice accepts; null accepts any. */
  readonly allowedOrigins: ReadonlyArray<string> | null;
}

const UNRESTRICTED_RELAY_POLICY: RelayPolicy = { pinned: false, allowedOrigins: null };

/**
 * Reads the build's `T3CODE_RELAY_PINNED` (`true`/`1`) and `T3CODE_RELAY_ALLOWLIST` (origins
 * separated by commas or spaces). An allowlist with no valid origin allows none.
 */
export function parseRelayPolicy(input: {
  readonly pinned?: unknown;
  readonly allowlist?: unknown;
}): RelayPolicy {
  const pinned =
    input.pinned === true ||
    (typeof input.pinned === "string" && /^(?:1|true|yes)$/iu.test(input.pinned.trim()));
  const entries =
    typeof input.allowlist === "string" ? input.allowlist.split(/[\s,]+/u).filter(Boolean) : [];
  return {
    pinned,
    allowedOrigins:
      entries.length === 0
        ? null
        : entries.flatMap((entry) => normalizeSecureRelayUrl(entry) ?? []),
  };
}

export const canChooseSelfHostedRelay = (policy: RelayPolicy): boolean =>
  !policy.pinned && (policy.allowedOrigins === null || policy.allowedOrigins.length > 0);

const isSelfHostedRelayAllowed = (policy: RelayPolicy, relayUrl: string): boolean =>
  canChooseSelfHostedRelay(policy) &&
  (policy.allowedOrigins === null || policy.allowedOrigins.includes(relayUrl));

const decodeStoredRelay = Schema.decodeUnknownOption(Schema.fromJsonString(SelfHostedRelay));
const decodeServiceMetadata = Schema.decodeUnknownOption(RelayServiceMetadata);

/**
 * Null for anything but a relay this module stored that the build still allows, so a corrupt or
 * no longer allowed entry falls back to the build's relay.
 */
export function parseStoredSelfHostedRelay(
  value: string | null,
  policy: RelayPolicy = UNRESTRICTED_RELAY_POLICY,
): SelfHostedRelay | null {
  if (value === null) return null;
  const relay = Option.getOrNull(decodeStoredRelay(value));
  return relay !== null &&
    normalizeSecureRelayUrl(relay.relayUrl) === relay.relayUrl &&
    isSelfHostedRelayAllowed(policy, relay.relayUrl)
    ? relay
    : null;
}

export const encodeSelfHostedRelay = (relay: SelfHostedRelay): string => JSON.stringify(relay);

/** Asks the relay at a user-entered address how to sign in, so the user only types the address. */
export async function discoverSelfHostedRelay(
  address: string,
  options: { readonly fetch?: typeof fetch; readonly policy?: RelayPolicy } = {},
): Promise<SelfHostedRelay> {
  const fetchImpl = options.fetch ?? fetch;
  const policy = options.policy ?? UNRESTRICTED_RELAY_POLICY;
  const trimmed = address.trim();
  const relayUrl = normalizeSecureRelayUrl(
    /^[a-z][a-z0-9+.-]*:\/\//iu.test(trimmed) ? trimmed : `https://${trimmed}`,
  );
  if (relayUrl === null) {
    throw new Error("Enter the relay's HTTPS address, for example https://relay.example.com.");
  }
  // Checked before any request, so a relay outside the list never learns this app asked.
  if (!isSelfHostedRelayAllowed(policy, relayUrl)) {
    throw new Error(
      policy.allowedOrigins === null || policy.pinned
        ? "This build only connects to its own relay."
        : `This build only connects to these relays: ${policy.allowedOrigins.join(", ")}.`,
    );
  }
  const response = await fetchImpl(`${relayUrl}/.well-known/t3-relay`, {
    headers: { accept: "application/json" },
  }).catch(() => null);
  if (response === null) throw new Error(`Could not reach ${relayUrl}.`);
  const metadata = response.ok
    ? Option.getOrNull(decodeServiceMetadata(await response.json().catch(() => null)))
    : null;
  if (metadata === null) {
    throw new Error(
      `${relayUrl} did not answer as a T3 relay. Check the address, or update the relay.`,
    );
  }
  if (metadata.oidc === null) {
    throw new Error(
      `${relayUrl} signs in with Clerk. Configure OIDC on the relay to use it from here.`,
    );
  }
  return {
    relayUrl,
    oidcIssuer: metadata.oidc.issuer,
    oidcClientId: metadata.oidc.clientId,
    managedTunnels: metadata.managedTunnels,
  };
}
