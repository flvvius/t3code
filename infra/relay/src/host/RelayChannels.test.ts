// @effect-diagnostics nodeBuiltinImport:off globalFetchInEffect:off - the relay under test is a real Node HTTP server.
import * as NodeHttp from "node:http";

import * as NodeHttpServer from "@effect/platform-node/NodeHttpServer";
import { describe, expect, it } from "@effect/vitest";
import * as Effect from "effect/Effect";
import * as HttpServer from "effect/http/HttpServer";
import * as HttpServerResponse from "effect/http/HttpServerResponse";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as TestClock from "effect/testing/TestClock";

import * as EnvironmentCredentials from "../environments/EnvironmentCredentials.ts";
import { channelKey } from "../environments/RelayChannelEndpoint.ts";
import { makeRelayChannels, type RelayChannelLimits } from "./RelayChannels.ts";

const makeLayer = (credentialValid: () => boolean = () => true) =>
  Layer.mergeAll(
    NodeHttpServer.layer(() => NodeHttp.createServer(), { port: 0, host: "127.0.0.1" }),
    Layer.succeed(EnvironmentCredentials.EnvironmentCredentials, {
      create: () => Effect.die("unused"),
      authenticate: (token) =>
        Effect.sync(() =>
          token === "good" && credentialValid()
            ? Option.some({ credentialId: "c", environmentId: "env-1", environmentPublicKey: "k" })
            : Option.none(),
        ),
      revokeForEnvironmentPublicKey: () => Effect.die("unused"),
      pruneRevoked: () => Effect.die("unused"),
    }),
  );

const serveRelayWith = (limits: Partial<RelayChannelLimits> = {}) =>
  Effect.gen(function* () {
    const channels = makeRelayChannels(limits);
    yield* HttpServer.serveEffect(channels(Effect.succeed(HttpServerResponse.text("relay api"))));
    const { address } = yield* HttpServer.HttpServer;
    return { port: "port" in address ? address.port : 0, recheckAll: channels.recheckAll };
  });

const serveRelay = Effect.map(serveRelayWith(), ({ port }) => port);

const channelPrefix = Effect.map(channelKey("env-1", "k"), (key) => `/env/${key}`);

/** A fake environment that answers each forwarded request with what it received. */
const connectEnvironment = (port: number, token: string) =>
  Effect.acquireRelease(
    Effect.callback<WebSocket, string>((resume) => {
      const socket = new WebSocket(`ws://127.0.0.1:${port}/v1/environments/env-1/channel`, {
        headers: { authorization: `Bearer ${token}` },
      } as never);
      socket.addEventListener("message", (event) => {
        const frame = JSON.parse(String(event.data));
        // The relay pings once the channel is registered.
        if (frame.type === "ping") resume(Effect.succeed(socket));
        if (frame.type === "http-request") {
          const echo = [
            frame.method,
            frame.path,
            frame.headers["x-forwarded-prefix"],
            frame.headers["x-forwarded-for"],
            frame.headers["x-forwarded-host"] ?? "-",
            frame.headers.forwarded ?? "-",
            frame.headers["x-real-ip"] ?? "-",
          ].join(" ");
          socket.send(
            JSON.stringify({
              type: "http-response",
              id: frame.id,
              status: 302,
              headers: {
                "content-type": frame.path.endsWith(".pdf") ? "application/pdf" : "text/plain",
                location: frame.headers["x-test-location"] ?? "/next",
                "Set-Cookie": "s=1",
                "Content-Security-Policy": "default-src *",
                "Clear-Site-Data": '"*"',
              },
              body: Buffer.from(echo).toString("base64"),
            }),
          );
        }
      });
      socket.addEventListener("close", (event) => resume(Effect.fail(`closed ${event.code}`)));
    }),
    (socket) => Effect.sync(() => socket.close()),
  );

const get = (port: number, path: string, init: RequestInit = {}) =>
  Effect.promise(async () => {
    const response = await fetch(`http://127.0.0.1:${port}${path}`, {
      redirect: "manual",
      ...init,
    });
    return {
      status: response.status,
      body: await response.text(),
      location: response.headers.get("location"),
      cookie: response.headers.get("set-cookie"),
      csp: response.headers.get("content-security-policy"),
      clearSiteData: response.headers.get("clear-site-data"),
    };
  });

describe("makeRelayChannels", () => {
  it.live("forwards /env/<key> to its environment and leaves other paths to the relay", () =>
    Effect.gen(function* () {
      const port = yield* serveRelay;
      const prefix = yield* channelPrefix;
      yield* connectEnvironment(port, "good");

      expect(yield* get(port, `${prefix}/api/state?x=1`)).toEqual({
        status: 302,
        body: `GET /api/state?x=1 ${prefix} 127.0.0.1 - - -`,
        location: `${prefix}/next`,
        cookie: null,
        csp: "sandbox allow-scripts allow-forms allow-popups allow-downloads",
        clearSiteData: null,
      });
      // Any account can link an environment, so even its PDFs never render with the relay origin.
      expect((yield* get(port, `${prefix}/file.pdf`)).csp).toBe(
        "sandbox allow-scripts allow-forms allow-popups allow-downloads",
      );
      expect(yield* get(port, "/v1/metadata")).toEqual({
        status: 200,
        body: "relay api",
        location: null,
        cookie: null,
        csp: null,
        clearSiteData: null,
      });
    }).pipe(Effect.scoped, Effect.provide(makeLayer())),
  );

  it.live("states the client address itself and keeps redirects on the environment's path", () =>
    Effect.gen(function* () {
      const port = yield* serveRelay;
      const prefix = yield* channelPrefix;
      yield* connectEnvironment(port, "good");
      // The loopback peer stands in for the front proxy, whose own entry comes last.
      const spoofed = yield* get(port, `${prefix}/api/state`, {
        headers: {
          "x-forwarded-for": "198.51.100.1, 203.0.113.9",
          "x-forwarded-host": "elsewhere.example",
          forwarded: "for=198.51.100.1",
          "x-real-ip": "198.51.100.1",
        },
      });
      expect(spoofed.body).toBe(`GET /api/state ${prefix} 203.0.113.9 - - -`);

      const redirects = [
        ["next", `${prefix}/api/next`],
        ["/next?a=1", `${prefix}/next?a=1`],
        ["https://elsewhere.example/login", null],
        ["//elsewhere.example/login", null],
        ["/\\elsewhere.example/login", null],
        ["../../../login", null],
      ] as const;
      for (const [location, expected] of redirects) {
        const response = yield* get(port, `${prefix}/api/state`, {
          headers: { "x-test-location": location },
        });
        expect([location, response.location]).toEqual([location, expected]);
      }
    }).pipe(Effect.scoped, Effect.provide(makeLayer())),
  );

  it.live("refuses bodies past the limit and requests past the memory budget", () =>
    Effect.gen(function* () {
      const { port } = yield* serveRelayWith({ maxBodyBytes: 64, maxBufferedBytes: 1024 });
      const prefix = yield* channelPrefix;
      yield* connectEnvironment(port, "good");
      const post = (bytes: number) =>
        get(port, `${prefix}/upload`, { method: "POST", body: "x".repeat(bytes) });
      expect((yield* post(64)).status).toBe(302);
      expect((yield* post(65)).status).toBe(413);
    }).pipe(Effect.scoped, Effect.provide(makeLayer())),
  );

  it.live("answers 503 once carried bodies would pass the relay's memory budget", () =>
    Effect.gen(function* () {
      // A body is held twice while forwarded: as read, and base64-encoded in its frame.
      const { port } = yield* serveRelayWith({ maxBufferedBytes: 200 });
      yield* connectEnvironment(port, "good");
      const path = `${yield* channelPrefix}/upload`;
      expect((yield* get(port, path, { method: "POST", body: "x".repeat(50) })).status).toBe(302);
      expect((yield* get(port, path, { method: "POST", body: "x".repeat(101) })).status).toBe(503);
    }).pipe(Effect.scoped, Effect.provide(makeLayer())),
  );

  it.live("answers the environment's keepalive pings", () =>
    Effect.gen(function* () {
      const socket = yield* connectEnvironment(yield* serveRelay, "good");
      yield* Effect.callback<void>((resume) => {
        socket.addEventListener("message", (event) => {
          if (JSON.parse(String(event.data)).type === "ping") resume(Effect.void);
        });
        socket.send(JSON.stringify({ type: "ping" }));
      });
    }).pipe(Effect.scoped, Effect.provide(makeLayer())),
  );

  it.live("ends a channel once its environment reconnects", () =>
    Effect.gen(function* () {
      const port = yield* serveRelay;
      const first = yield* connectEnvironment(port, "good");
      const firstClosed = Effect.callback<void>((resume) =>
        first.addEventListener("close", () => resume(Effect.void)),
      );
      yield* connectEnvironment(port, "good");
      yield* firstClosed;
    }).pipe(Effect.scoped, Effect.provide(makeLayer())),
  );

  it.effect("closes a channel its environment went silent on", () =>
    Effect.gen(function* () {
      const socket = yield* connectEnvironment(yield* serveRelay, "good");
      const closed = Effect.callback<void>((resume) =>
        socket.addEventListener("close", () => resume(Effect.void)),
      );
      for (let check = 0; check < 3; check++) yield* TestClock.adjust("25 seconds");
      yield* closed;
    }).pipe(Effect.scoped, Effect.provide(makeLayer())),
  );

  it.live("answers 502 for an environment that has no channel open", () =>
    Effect.gen(function* () {
      const port = yield* serveRelay;
      expect((yield* get(port, `${yield* channelPrefix}/`)).status).toBe(502);
    }).pipe(Effect.provide(makeLayer())),
  );

  it.effect(
    "closes a channel once its credential is revoked, whatever the environment sends",
    () => {
      let valid = true;
      return Effect.gen(function* () {
        const port = yield* serveRelay;
        const socket = yield* connectEnvironment(port, "good");
        const closed = Effect.callback<void>((resume) =>
          socket.addEventListener("close", () => resume(Effect.void)),
        );
        valid = false;
        yield* TestClock.adjust("25 seconds");
        yield* closed;
        expect((yield* get(port, `${yield* channelPrefix}/`)).status).toBe(502);
      }).pipe(Effect.scoped, Effect.provide(makeLayer(() => valid)));
    },
  );

  it.effect("closes a revoked channel as soon as a revocation is announced", () => {
    let valid = true;
    return Effect.gen(function* () {
      const { port, recheckAll } = yield* serveRelayWith();
      const socket = yield* connectEnvironment(port, "good");
      const closed = Effect.callback<void>((resume) =>
        socket.addEventListener("close", () => resume(Effect.void)),
      );
      valid = false;
      // The test clock never moves, so only the announcement can end the channel.
      yield* recheckAll;
      yield* closed;
    }).pipe(Effect.scoped, Effect.provide(makeLayer(() => valid)));
  });

  it.live("refuses a channel opened with another credential", () =>
    Effect.gen(function* () {
      const port = yield* serveRelay;
      const opened = yield* Effect.exit(connectEnvironment(port, "bad"));
      expect(opened._tag).toBe("Failure");
    }).pipe(Effect.scoped, Effect.provide(makeLayer())),
  );
});
