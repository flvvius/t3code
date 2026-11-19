import { describe, expect, it } from "@effect/vitest";
import { PgDialect } from "drizzle-orm/pg-core";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";

import * as RelayDb from "./db.ts";
import * as EnvironmentCredentials from "./environments/EnvironmentCredentials.ts";
import { offboardOidcSubject, parseOffboardArgs } from "./offboard.ts";
import {
  relayEnvironmentLinks,
  relayLiveActivities,
  relayMobileDevices,
} from "./persistence/schema.ts";

const USER_ID = "oidc:https://login.example.test/v2.0|subject-1";

describe("offboardOidcSubject", () => {
  it.effect("revokes the account's links and credentials and forgets its devices", () => {
    const dialect = new PgDialect();
    const writes: Array<{ table: unknown; sql: string; params: unknown; inTransaction: boolean }> =
      [];
    const revokedKeys: Array<unknown> = [];
    let inTransaction = false;
    const record = (table: unknown, condition: unknown) => {
      const query = dialect.sqlToQuery(condition as never);
      writes.push({ table, sql: query.sql, params: query.params, inTransaction });
    };
    const fakeDb = {
      update: (table: unknown) => ({
        set: () => ({
          where: (condition: unknown) => ({
            returning: () =>
              Effect.sync(() => {
                record(table, condition);
                return [
                  { environmentId: "env-1", environmentPublicKey: "key-1" },
                  { environmentId: "env-2", environmentPublicKey: "key-2" },
                ];
              }),
          }),
        }),
      }),
      delete: (table: unknown) => ({
        where: (condition: unknown) => ({
          returning: () =>
            Effect.sync(() => {
              record(table, condition);
              return table === relayMobileDevices ? [{ deviceId: "d1" }] : [];
            }),
        }),
      }),
    } as unknown as RelayDb.RelayDb["Service"];

    return Effect.gen(function* () {
      const result = yield* offboardOidcSubject({
        issuer: "https://login.example.test/v2.0",
        subject: "subject-1",
      });
      expect(result).toEqual({
        userId: USER_ID,
        linksRevoked: 2,
        credentialsRevoked: 1,
        devicesRemoved: 1,
        liveActivitiesRemoved: 0,
      });
      expect(revokedKeys).toEqual([
        { environmentId: "env-1", environmentPublicKey: "key-1", inTransaction: true },
        { environmentId: "env-2", environmentPublicKey: "key-2", inTransaction: true },
      ]);
      expect(writes.map((write) => write.table)).toEqual([
        relayEnvironmentLinks,
        relayMobileDevices,
        relayLiveActivities,
      ]);
      for (const write of writes) {
        expect(write.inTransaction).toBe(true);
        expect(write.params).toEqual([USER_ID]);
      }
      expect(writes[0]?.sql).toContain('"relay_environment_links"."revoked_at" is null');
    }).pipe(
      Effect.provide(
        Layer.mergeAll(
          Layer.succeed(RelayDb.RelayDb, fakeDb),
          Layer.succeed(RelayDb.RelayTransactions, {
            withTransaction: (effect) =>
              Effect.sync(() => {
                inTransaction = true;
              }).pipe(
                Effect.andThen(effect),
                Effect.ensuring(
                  Effect.sync(() => {
                    inTransaction = false;
                  }),
                ),
              ),
          }),
          Layer.succeed(EnvironmentCredentials.EnvironmentCredentials, {
            create: () => Effect.die("unused"),
            authenticate: () => Effect.die("unused"),
            pruneRevoked: () => Effect.die("unused"),
            // Another account still links env-2, so its credentials stay.
            revokeForEnvironmentPublicKey: (input) =>
              Effect.sync(() => {
                revokedKeys.push({ ...input, inTransaction });
                return input.environmentId === "env-1";
              }),
          }),
        ),
      ),
    );
  });
});

describe("parseOffboardArgs", () => {
  it.each([
    [["offboard", "--subject", "s"], { issuer: undefined, subject: "s" }],
    [
      ["offboard", "--issuer", "https://i.example/", "--subject", "s"],
      { issuer: "https://i.example/", subject: "s" },
    ],
    [["offboard"], null],
    [["offboard", "--issuer", "https://i.example/"], null],
    [["offboard", "--subject"], null],
    [["offboard", "--subject", "s", "--subject", "t"], null],
    [["offboard", "--user", "s"], null],
    [["serve"], null],
    [[], null],
  ] as const)("%j", (args, expected) => {
    expect(parseOffboardArgs(args)).toEqual(expected);
  });
});
