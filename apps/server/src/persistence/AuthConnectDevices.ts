import * as Context from "effect/Context";
import * as NodeSqliteClient from "@t3tools/shared/nodeSqliteClient";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Schema from "effect/Schema";
import * as SqlClient from "effect/sql/SqlClient";
import * as SqlSchema from "effect/sql/SqlSchema";

import { AuthClientMetadata } from "@t3tools/contracts";

import { type AuthPairingLinkRepositoryError, PersistenceSqlError } from "./Errors.ts";

export const AuthConnectDeviceRecord = Schema.Struct({
  proofKeyThumbprint: Schema.String,
  client: Schema.NullOr(Schema.fromJsonString(AuthClientMetadata)),
  approvedAt: Schema.DateTimeUtcFromString,
});
export type AuthConnectDeviceRecord = typeof AuthConnectDeviceRecord.Type;

/** Trust approved before this lapsed; null keeps it forever. */
const TrustedSince = Schema.NullOr(Schema.DateTimeUtcFromString);

const TrustInput = Schema.Struct({
  proofKeyThumbprint: Schema.String,
  client: Schema.NullOr(Schema.fromJsonString(AuthClientMetadata)),
  approvedAt: Schema.DateTimeUtcFromString,
  trustedSince: TrustedSince,
});

const IsTrustedInput = Schema.Struct({
  proofKeyThumbprint: Schema.String,
  trustedSince: TrustedSince,
});

const ListInput = Schema.Struct({ trustedSince: TrustedSince });

const ThumbprintInput = Schema.Struct({ proofKeyThumbprint: Schema.String });

const RemoveAllExceptInput = Schema.Struct({
  keepProofKeyThumbprint: Schema.NullOr(Schema.String),
});

/** T3 Connect device keys this environment lets in without asking. A key leaves when revoked. */
export class AuthConnectDeviceRepository extends Context.Service<
  AuthConnectDeviceRepository,
  {
    /**
     * Adds the key, or refreshes how an already trusted key describes itself. A key whose trust
     * lapsed before `trustedSince` is trusted again from `approvedAt`.
     */
    readonly trust: (
      input: typeof TrustInput.Type,
    ) => Effect.Effect<void, AuthPairingLinkRepositoryError>;
    readonly isTrusted: (
      input: typeof IsTrustedInput.Type,
    ) => Effect.Effect<boolean, AuthPairingLinkRepositoryError>;
    readonly list: (
      input: typeof ListInput.Type,
    ) => Effect.Effect<ReadonlyArray<AuthConnectDeviceRecord>, AuthPairingLinkRepositoryError>;
    /** Forgets keys approved before `trustedSince`, so their waiting requests need approval. */
    readonly removeLapsed: (
      input: typeof ListInput.Type,
    ) => Effect.Effect<number, AuthPairingLinkRepositoryError>;
    readonly remove: (
      proofKeyThumbprint: string,
    ) => Effect.Effect<boolean, AuthPairingLinkRepositoryError>;
    readonly removeAllExcept: (
      keepProofKeyThumbprint: string | null,
    ) => Effect.Effect<number, AuthPairingLinkRepositoryError>;
  }
>()("t3/persistence/AuthConnectDevices/AuthConnectDeviceRepository") {}

const sqlError = (operation: string) => (cause: unknown) =>
  new PersistenceSqlError({ operation, cause });

/** @public */
export const make = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;

  const trustRow = SqlSchema.void({
    Request: TrustInput,
    // ISO timestamps from one encoder, so text comparison orders them.
    execute: ({ proofKeyThumbprint, client, approvedAt, trustedSince }) =>
      sql`
        INSERT INTO auth_connect_devices (proof_key_thumbprint, client_json, approved_at)
        VALUES (${proofKeyThumbprint}, ${client}, ${approvedAt})
        ON CONFLICT (proof_key_thumbprint) DO UPDATE
          SET client_json = COALESCE(excluded.client_json, auth_connect_devices.client_json),
            approved_at = CASE
              WHEN auth_connect_devices.approved_at < ${trustedSince} THEN excluded.approved_at
              ELSE auth_connect_devices.approved_at
            END
      `,
  });

  const isTrustedRow = SqlSchema.findAll({
    Request: IsTrustedInput,
    Result: Schema.Struct({ proofKeyThumbprint: Schema.String }),
    execute: ({ proofKeyThumbprint, trustedSince }) =>
      sql`
        SELECT proof_key_thumbprint AS "proofKeyThumbprint"
        FROM auth_connect_devices
        WHERE proof_key_thumbprint = ${proofKeyThumbprint}
          AND (${trustedSince} IS NULL OR approved_at >= ${trustedSince})
      `,
  });

  const listRows = SqlSchema.findAll({
    Request: ListInput,
    Result: AuthConnectDeviceRecord,
    execute: ({ trustedSince }) =>
      sql`
        SELECT
          proof_key_thumbprint AS "proofKeyThumbprint",
          client_json AS "client",
          approved_at AS "approvedAt"
        FROM auth_connect_devices
        WHERE ${trustedSince} IS NULL OR approved_at >= ${trustedSince}
        ORDER BY approved_at DESC, proof_key_thumbprint
      `,
  });

  const removeLapsedRows = SqlSchema.findAll({
    Request: ListInput,
    Result: Schema.Struct({ proofKeyThumbprint: Schema.String }),
    execute: ({ trustedSince }) =>
      sql`
        DELETE FROM auth_connect_devices
        WHERE approved_at < ${trustedSince}
        RETURNING proof_key_thumbprint AS "proofKeyThumbprint"
      `,
  });

  const removeRows = SqlSchema.findAll({
    Request: ThumbprintInput,
    Result: Schema.Struct({ proofKeyThumbprint: Schema.String }),
    execute: ({ proofKeyThumbprint }) =>
      sql`
        DELETE FROM auth_connect_devices
        WHERE proof_key_thumbprint = ${proofKeyThumbprint}
        RETURNING proof_key_thumbprint AS "proofKeyThumbprint"
      `,
  });

  const removeAllExceptRows = SqlSchema.findAll({
    Request: RemoveAllExceptInput,
    Result: Schema.Struct({ proofKeyThumbprint: Schema.String }),
    execute: ({ keepProofKeyThumbprint }) =>
      sql`
        DELETE FROM auth_connect_devices
        WHERE proof_key_thumbprint IS NOT ${keepProofKeyThumbprint}
        RETURNING proof_key_thumbprint AS "proofKeyThumbprint"
      `,
  });

  const trust: AuthConnectDeviceRepository["Service"]["trust"] = (input) =>
    trustRow(input).pipe(Effect.mapError(sqlError("AuthConnectDeviceRepository.trust")));

  const isTrusted: AuthConnectDeviceRepository["Service"]["isTrusted"] = (input) =>
    isTrustedRow(input).pipe(
      NodeSqliteClient.readOnly,
      Effect.map((rows) => rows.length > 0),
      Effect.mapError(sqlError("AuthConnectDeviceRepository.isTrusted")),
    );

  const list: AuthConnectDeviceRepository["Service"]["list"] = (input) =>
    listRows(input).pipe(
      NodeSqliteClient.readOnly,
      Effect.mapError(sqlError("AuthConnectDeviceRepository.list")),
    );

  const removeLapsed: AuthConnectDeviceRepository["Service"]["removeLapsed"] = (input) =>
    (input.trustedSince === null ? Effect.succeed([]) : removeLapsedRows(input)).pipe(
      Effect.map((rows) => rows.length),
      Effect.mapError(sqlError("AuthConnectDeviceRepository.removeLapsed")),
    );

  const remove: AuthConnectDeviceRepository["Service"]["remove"] = (proofKeyThumbprint) =>
    removeRows({ proofKeyThumbprint }).pipe(
      Effect.map((rows) => rows.length > 0),
      Effect.mapError(sqlError("AuthConnectDeviceRepository.remove")),
    );

  const removeAllExcept: AuthConnectDeviceRepository["Service"]["removeAllExcept"] = (
    keepProofKeyThumbprint,
  ) =>
    removeAllExceptRows({ keepProofKeyThumbprint }).pipe(
      Effect.map((rows) => rows.length),
      Effect.mapError(sqlError("AuthConnectDeviceRepository.removeAllExcept")),
    );

  return {
    trust,
    isTrusted,
    list,
    removeLapsed,
    remove,
    removeAllExcept,
  } satisfies AuthConnectDeviceRepository["Service"];
});

export const layer = Layer.effect(AuthConnectDeviceRepository, make);
