import { oidcAccountId } from "@t3tools/shared/oidc";
import { and, eq, isNull } from "drizzle-orm";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";

import * as RelayDb from "./db.ts";
import * as EnvironmentCredentials from "./environments/EnvironmentCredentials.ts";
import {
  relayEnvironmentLinks,
  relayLiveActivities,
  relayMobileDevices,
} from "./persistence/schema.ts";

export class OffboardPersistenceError extends Schema.TaggedError<OffboardPersistenceError>()(
  "OffboardPersistenceError",
  {
    stage: Schema.Literals(["revoke-links", "delete-devices", "delete-live-activities"]),
    cause: Schema.Defect(),
  },
) {
  override get message(): string {
    return `Offboarding failed during '${this.stage}'`;
  }
}

export interface OffboardResult {
  readonly userId: string;
  readonly linksRevoked: number;
  readonly credentialsRevoked: number;
  readonly devicesRemoved: number;
  readonly liveActivitiesRemoved: number;
}

/**
 * Cuts one OIDC account off the relay: revokes its environment links and the credentials behind
 * them, which closes their channels, and forgets its devices and push tokens. Signing in again
 * still works unless the identity provider stops issuing that account tokens.
 */
export const offboardOidcSubject = Effect.fn("relay.offboard_oidc_subject")(function* (input: {
  readonly issuer: string;
  readonly subject: string;
}) {
  const db = yield* RelayDb.RelayDb;
  const transactions = yield* RelayDb.RelayTransactions;
  const credentials = yield* EnvironmentCredentials.EnvironmentCredentials;
  const userId = oidcAccountId(input.issuer, input.subject);
  const failed = (stage: OffboardPersistenceError["stage"]) => (cause: unknown) =>
    new OffboardPersistenceError({ stage, cause });

  return yield* transactions
    .withTransaction(
      Effect.gen(function* () {
        const now = DateTime.formatIso(yield* DateTime.now);
        const links = yield* db
          .update(relayEnvironmentLinks)
          .set({ revokedAt: now, updatedAt: now })
          .where(
            and(eq(relayEnvironmentLinks.userId, userId), isNull(relayEnvironmentLinks.revokedAt)),
          )
          .returning({
            environmentId: relayEnvironmentLinks.environmentId,
            environmentPublicKey: relayEnvironmentLinks.environmentPublicKey,
          })
          .pipe(Effect.mapError(failed("revoke-links")));
        // Another account may still link the same environment key; its credentials then stay.
        const revoked = yield* Effect.forEach(links, (link) =>
          credentials.revokeForEnvironmentPublicKey(link),
        );
        const devices = yield* db
          .delete(relayMobileDevices)
          .where(eq(relayMobileDevices.userId, userId))
          .returning({ deviceId: relayMobileDevices.deviceId })
          .pipe(Effect.mapError(failed("delete-devices")));
        const liveActivities = yield* db
          .delete(relayLiveActivities)
          .where(eq(relayLiveActivities.userId, userId))
          .returning({ deviceId: relayLiveActivities.deviceId })
          .pipe(Effect.mapError(failed("delete-live-activities")));
        return {
          userId,
          linksRevoked: links.length,
          credentialsRevoked: revoked.filter(Boolean).length,
          devicesRemoved: devices.length,
          liveActivitiesRemoved: liveActivities.length,
        } satisfies OffboardResult;
      }),
    )
    .pipe(Effect.catchTag("SqlError", (cause) => Effect.fail(failed("revoke-links")(cause))));
});

/**
 * Reads `offboard --subject <sub> [--issuer <iss>]`; null when the arguments are anything else.
 * The issuer defaults to the relay's own, since account ids embed it exactly.
 */
export function parseOffboardArgs(
  args: ReadonlyArray<string>,
): { readonly issuer: string | undefined; readonly subject: string } | null {
  if (args[0] !== "offboard") return null;
  const values = new Map<string, string>();
  for (let index = 1; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1]?.trim();
    if ((name !== "--issuer" && name !== "--subject") || !value || values.has(name)) return null;
    values.set(name, value);
  }
  const subject = values.get("--subject");
  return subject === undefined ? null : { issuer: values.get("--issuer"), subject };
}
