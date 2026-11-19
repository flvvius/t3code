// Self-hosted relay entrypoint. The same composition as the Cloudflare Worker (`composition.ts`),
// served from Node with Postgres. See `host/node.ts` for what differs and why.
// `node node.mjs offboard --subject <sub> [--issuer <iss>]` instead cuts one account off and exits.
// @effect-diagnostics nodeBuiltinImport:off - the Node HTTP server is the platform entry point.
import * as NodeHttp from "node:http";

import * as NodeHttpServer from "@effect/platform-node/NodeHttpServer";
import * as NodeRuntime from "@effect/platform-node/NodeRuntime";
import * as NodeServices from "@effect/platform-node/NodeServices";
import * as PgClient from "@effect/sql-pg/PgClient";
import { makeWithDefaults } from "drizzle-orm/effect-postgres";
import { migrate } from "drizzle-orm/effect-postgres/migrator";
import * as ByteSize from "effect/ByteSize";
import * as Config from "effect/Config";
import * as ConfigProvider from "effect/ConfigProvider";
import * as Console from "effect/Console";
import * as Digest from "effect/crypto/Digest";
import * as Effect from "effect/Effect";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import * as HttpIncomingMessage from "effect/http/HttpIncomingMessage";
import * as HttpServer from "effect/http/HttpServer";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Queue from "effect/Queue";
import * as Redacted from "effect/Redacted";
import * as Schedule from "effect/Schedule";
import * as SecureRandom from "effect/crypto/SecureRandom";

import { composeRelay } from "./composition.ts";
import { positiveIntConfig } from "./Config.ts";
import * as RelayDb from "./db.ts";
import * as EnvironmentCredentials from "./environments/EnvironmentCredentials.ts";
import { makeNodeHost, withFileSecrets, withPublicOrigin } from "./host/node.ts";
import {
  channelFrameBytesFor,
  DEFAULT_RELAY_CHANNEL_LIMITS,
  makeRelayChannels,
} from "./host/RelayChannels.ts";
import { offboardOidcSubject, parseOffboardArgs } from "./offboard.ts";

const channelLimitsConfig = Config.all({
  maxBodyBytes: positiveIntConfig(
    "RELAY_CHANNEL_MAX_BODY_BYTES",
    DEFAULT_RELAY_CHANNEL_LIMITS.maxBodyBytes,
  ),
  maxBufferedBytes: positiveIntConfig(
    "RELAY_CHANNEL_MAX_BUFFERED_BYTES",
    DEFAULT_RELAY_CHANNEL_LIMITS.maxBufferedBytes,
  ),
  maxPendingRequests: positiveIntConfig(
    "RELAY_CHANNEL_MAX_PENDING_REQUESTS",
    DEFAULT_RELAY_CHANNEL_LIMITS.maxPendingRequests,
  ),
  maxSockets: positiveIntConfig(
    "RELAY_CHANNEL_MAX_SOCKETS",
    DEFAULT_RELAY_CHANNEL_LIMITS.maxSockets,
  ),
  maxSocketQueueBytes: positiveIntConfig(
    "RELAY_CHANNEL_SOCKET_QUEUE_BYTES",
    DEFAULT_RELAY_CHANNEL_LIMITS.maxSocketQueueBytes,
  ),
});

const serve = Effect.gen(function* () {
  const fs = yield* FileSystem.FileSystem;
  const readSecret = (path: string) =>
    fs.readFileString(path).pipe(Effect.map((text) => text.trim()));

  const relayPublicOrigin = yield* Config.String("RELAY_PUBLIC_ORIGIN");
  const channels = yield* Config.Boolean("RELAY_CHANNELS").pipe(Config.withDefault(false));
  const channelLimits = yield* channelLimitsConfig;
  const apiMaxBodyBytes = yield* positiveIntConfig("RELAY_API_MAX_BODY_BYTES", 1024 * 1024);
  const maxEnvironmentsPerUser = yield* positiveIntConfig("RELAY_MAX_ENVIRONMENTS_PER_USER", 25);
  const migrationsFolder = yield* Config.String("RELAY_MIGRATIONS_FOLDER").pipe(
    Config.withDefault("migrations/postgres"),
  );
  const mintPrivateKey = yield* readSecret(yield* Config.String("CLOUD_MINT_PRIVATE_KEY_FILE"));
  const mintPublicKey = yield* readSecret(yield* Config.String("CLOUD_MINT_PUBLIC_KEY_FILE"));
  // Compose passes unset variables as empty strings; an empty secret must count as absent.
  const nonEmpty = (value: Redacted.Redacted<string>) => Redacted.value(value).trim().length > 0;
  const apnsJobSigningSecret = Option.filter(
    yield* Config.option(Config.Redacted("APNS_DELIVERY_JOB_SIGNING_SECRET")),
    nonEmpty,
  );
  const mobileTelemetryToken = Option.filter(
    yield* Config.option(Config.Redacted("MOBILE_TELEMETRY_TOKEN")),
    nonEmpty,
  );

  const database = yield* makeWithDefaults();
  // A failed migration leaves the database in an unknown state; refuse to start instead of serving.
  yield* migrate(database, { migrationsFolder, migrationsTable: "relay_migrations" }).pipe(
    Effect.orDie,
  );

  const host = yield* makeNodeHost({
    relayPublicOrigin,
    stage: "selfhost",
    channels,
    maxEnvironmentsPerUser,
    mintKeyPair: {
      privateKey: Redacted.make(mintPrivateKey),
      publicKey: mintPublicKey,
    },
    ...(apnsJobSigningSecret._tag === "Some"
      ? { apnsJobSigningSecret: apnsJobSigningSecret.value }
      : {}),
    database,
    mobileTelemetry: {
      token: mobileTelemetryToken._tag === "Some" ? mobileTelemetryToken.value : undefined,
      traces: yield* Config.String("MOBILE_TELEMETRY_TRACES_URL").pipe(Config.withDefault("")),
      logs: yield* Config.String("MOBILE_TELEMETRY_LOGS_URL").pipe(Config.withDefault("")),
      metrics: yield* Config.String("MOBILE_TELEMETRY_METRICS_URL").pipe(Config.withDefault("")),
    },
  });

  const relay = yield* composeRelay(host);
  // Built once: every request reuses the same services, as the Worker's per-isolate layers do.
  const context = yield* Layer.build(relay.runtime);
  const handler = yield* relay.fetch.pipe(Effect.provideContext(context));
  const relayChannels = channels ? makeRelayChannels(channelLimits) : undefined;
  if (relayChannels !== undefined) {
    // A revocation on any replica or from `offboard` closes the channels it covers right away.
    const pg = yield* PgClient.PgClient;
    yield* Effect.scoped(
      Effect.gen(function* () {
        const revocations = yield* pg.listen(EnvironmentCredentials.CREDENTIALS_REVOKED_CHANNEL);
        yield* relayChannels.recheckAll;
        return yield* Queue.take(revocations).pipe(
          Effect.andThen(relayChannels.recheckAll),
          Effect.forever,
        );
      }),
    ).pipe(
      Effect.tapCause((cause) =>
        Effect.logWarning("Listening for credential revocations failed; retrying", { cause }),
      ),
      Effect.retry(Schedule.spaced("5 seconds")),
      Effect.forkScoped,
    );
  }
  yield* HttpServer.serveEffect(
    handler.pipe(
      // The relay API takes small JSON bodies; carried environments get their own limit below.
      Effect.provideService(HttpIncomingMessage.MaxBodySize, ByteSize.bytes(apiMaxBodyBytes)),
      // Around the relay API, so channel traffic skips its middleware and tracing.
      (effect) => (relayChannels === undefined ? effect : relayChannels(effect)),
      // Outermost: carried environments rebuild the URLs clients sign from this host, whatever
      // Host the reverse proxy in front of the relay sends.
      withPublicOrigin(relayPublicOrigin),
      Effect.provideContext(context),
    ),
  );
  yield* Effect.logInfo("Self-hosted relay is serving", { relayPublicOrigin, channels });
  // Serving is scoped to this program; keep it alive until the process is stopped.
  return yield* Effect.never;
});

const offboard = Effect.fn("relay.node.offboard")(function* (args: {
  readonly issuer: string | undefined;
  readonly subject: string;
}) {
  const issuer = args.issuer ?? (yield* Config.String("OIDC_ISSUER")).trim();
  const database = yield* makeWithDefaults();
  const result = yield* offboardOidcSubject({ issuer, subject: args.subject }).pipe(
    Effect.provide(
      Layer.mergeAll(EnvironmentCredentials.layer, RelayDb.RelayTransactions.layer).pipe(
        Layer.provideMerge(Layer.succeed(RelayDb.RelayDb, database)),
        Layer.provide(Digest.layerWebCrypto),
        Layer.provide(SecureRandom.layerWebCrypto),
      ),
    ),
  );
  yield* Console.log(
    `Offboarded ${result.userId}: ${result.linksRevoked} links and ` +
      `${result.credentialsRevoked} credentials revoked, ${result.devicesRemoved} devices and ` +
      `${result.liveActivitiesRemoved} live activities removed.`,
  );
});

const args = process.argv.slice(2);
const offboardArgs = parseOffboardArgs(args);
const program = Effect.gen(function* () {
  if (offboardArgs !== null) return yield* offboard(offboardArgs);
  if (args.length > 0) {
    return yield* Effect.die("Usage: node node.mjs [offboard --subject <sub> [--issuer <iss>]]");
  }
  return yield* serve;
});

const serverLayer = Layer.unwrap(
  Effect.gen(function* () {
    const port = yield* Config.Int("PORT").pipe(Config.withDefault(8080));
    const { maxBodyBytes } = yield* channelLimitsConfig;
    // Any single frame must fit a forwarded body, so the default follows the channel body limit.
    const maxPayload = yield* positiveIntConfig(
      "RELAY_WS_MAX_FRAME_BYTES",
      channelFrameBytesFor(maxBodyBytes),
    );
    return NodeHttpServer.layer(NodeHttp.createServer, {
      port,
      host: "0.0.0.0",
      websocket: { maxPayload },
    });
  }),
);

// `<NAME>_FILE` secrets become `<NAME>` for every config read, the database URL included.
const configLayer = ConfigProvider.layer(
  withFileSecrets(process.env).pipe(Effect.map((env) => ConfigProvider.fromEnvRecord(env))),
).pipe(Layer.provide(NodeServices.layer));

NodeRuntime.runMain(
  program.pipe(
    Effect.scoped,
    Effect.provide(
      Layer.mergeAll(
        offboardArgs === null ? serverLayer : Layer.empty,
        NodeServices.layer,
        FetchHttpClient.layer,
        SecureRandom.layerWebCrypto,
        PgClient.layerConfig({ url: Config.Redacted("DATABASE_URL") }),
      ).pipe(Layer.provideMerge(configLayer)),
    ),
  ),
);
