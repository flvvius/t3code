import { PROVIDER_SEND_TURN_MAX_FILE_BYTES } from "@t3tools/contracts";
import { RELAY_CHANNEL_RESPONSE_TIMEOUT_MS, RelayChannelFrame } from "@t3tools/contracts/relay";
import * as ByteSize from "effect/ByteSize";
import * as Deferred from "effect/Deferred";
import * as Effect from "effect/Effect";
import * as Fiber from "effect/Fiber";
import * as HttpIncomingMessage from "effect/http/HttpIncomingMessage";
import * as HttpServerRequest from "effect/http/HttpServerRequest";
import * as HttpServerResponse from "effect/http/HttpServerResponse";
import * as Option from "effect/Option";
import * as Queue from "effect/Queue";
import * as Schema from "effect/Schema";
import * as Socket from "effect/socket/Socket";

import * as EnvironmentCredentials from "../environments/EnvironmentCredentials.ts";
import { channelKey, channelPathTarget } from "../environments/RelayChannelEndpoint.ts";
import { endpointAddressRejection, isIpAddress } from "./manualEndpointClient.ts";

type HttpResponseFrame = Extract<RelayChannelFrame, { readonly type: "http-response" }>;
type SocketFrame = Extract<
  RelayChannelFrame,
  { readonly type: "ws-opened" | "ws-message" | "ws-close" }
>;

interface CarriedSocket {
  readonly inbox: Queue.Queue<SocketFrame>;
  /** Bytes of `ws-message` data waiting in `inbox` for a slow client. */
  queuedBytes: number;
  /** Completed when the client falls too far behind; its socket is then closed. */
  readonly overflowed: Deferred.Deferred<void>;
}

interface Channel {
  readonly send: (frame: RelayChannelFrame) => Effect.Effect<void>;
  readonly responses: Map<number, Deferred.Deferred<HttpResponseFrame>>;
  readonly sockets: Map<number, CarriedSocket>;
  /** Completed when a reconnect takes this channel's place. */
  readonly replaced: Deferred.Deferred<void>;
  /** Completed once the channel's socket is gone. */
  readonly ended: Deferred.Deferred<void>;
  /** Rechecks since the environment last sent a frame. */
  quietChecks: number;
  /** Credential lookups failed in a row. */
  failedLookups: number;
  /** Asks for a credential check now rather than at the next interval. */
  readonly wakeups: Queue.Queue<void>;
}

/**
 * Memory bounds for carried traffic. Bodies and frames cross the channel whole, so these cap what
 * one environment, or anyone who knows its `/env/<key>/` path, can make the relay hold.
 */
export interface RelayChannelLimits {
  /** Largest request body forwarded to an environment. */
  readonly maxBodyBytes: number;
  /** Bodies and socket frames held across all channels at once; past it, new ones are refused. */
  readonly maxBufferedBytes: number;
  /** Requests waiting on one environment's answers. */
  readonly maxPendingRequests: number;
  /** WebSockets carried to one environment. */
  readonly maxSockets: number;
  /** Frames from the environment a slow client may leave unread before its socket is closed. */
  readonly maxSocketQueueBytes: number;
}

// The largest legitimate upload is a file attachment; RPC frames with images are smaller.
export const DEFAULT_RELAY_CHANNEL_LIMITS: RelayChannelLimits = {
  maxBodyBytes: PROVIDER_SEND_TURN_MAX_FILE_BYTES,
  maxBufferedBytes: 256 * 1024 * 1024,
  maxPendingRequests: 64,
  maxSockets: 64,
  maxSocketQueueBytes: 16 * 1024 * 1024,
};

/** A frame carrying a body this large, base64-encoded, plus room for the frame around it. */
export const channelFrameBytesFor = (bodyBytes: number) =>
  Math.ceil(bodyBytes / 3) * 4 + 1024 * 1024;

/** Shares one memory allowance between every carried request and socket. */
const makeByteBudget = (limit: number) => {
  let used = 0;
  return {
    acquire: (bytes: number) => {
      if (used + bytes > limit) return false;
      used += bytes;
      return true;
    },
    release: (bytes: number) => {
      used = Math.max(0, used - bytes);
    },
  };
};

// Socket writes do not wait for the peer; past this many unsent bytes the writer waits for drain.
const WRITE_HIGH_WATER_BYTES = 1024 * 1024;

interface WritableSocket {
  readonly writableLength: number;
  once(event: "drain" | "close", listener: () => void): unknown;
  off(event: "drain" | "close", listener: () => void): unknown;
}

/** The TCP socket under a Node request, which a WebSocket upgrade keeps using. */
function writableSocketOf(request: HttpServerRequest.HttpServerRequest): WritableSocket | null {
  const source: unknown = request.source;
  const socket: unknown =
    typeof source === "object" && source !== null ? Reflect.get(source, "socket") : null;
  return typeof socket === "object" && socket !== null && "writableLength" in socket
    ? (socket as WritableSocket)
    : null;
}

/** Waits until the peer has read enough of what was sent, so a slow reader slows the writer. */
const whenDrained = (socket: WritableSocket | null) =>
  socket === null || socket.writableLength <= WRITE_HIGH_WATER_BYTES
    ? Effect.void
    : Effect.callback<void>((resume) => {
        const done = () => resume(Effect.void);
        socket.once("drain", done);
        socket.once("close", done);
        return Effect.sync(() => {
          socket.off("drain", done);
          socket.off("close", done);
        });
      });

const CREDENTIAL_RECHECK_INTERVAL = "25 seconds";
// Environments ping as often as the relay rechecks, so this much silence is a dead connection.
const MAX_QUIET_CHECKS = 2;
// A database hiccup should not drop every environment, but an outage must not keep revoked ones.
const MAX_FAILED_LOOKUPS = 4;
// The environment's own document sandbox: scripts run, but in an opaque origin, never the relay's.
const CARRIED_CONTENT_SECURITY_POLICY =
  "sandbox allow-scripts allow-forms allow-popups allow-downloads";
const CHANNEL_SOCKET_PATH = /^\/v1\/environments\/([^/?]+)\/channel(?:\?.*)?$/u;
// Per-connection headers stay on their own side of the relay, and so do claims about the client's
// address, which the relay states itself.
const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "upgrade",
  "transfer-encoding",
  "content-length",
  "te",
  "trailer",
  "proxy-connection",
  "proxy-authorization",
  "proxy-authenticate",
  "forwarded",
  "x-real-ip",
]);
const isClientAddressClaim = (name: string) =>
  HOP_BY_HOP_HEADERS.has(name) || name.startsWith("x-forwarded-");

const decodeFrame = Schema.decodeUnknownOption(RelayChannelFrame);

function parseFrame(chunk: string | Uint8Array): Option.Option<RelayChannelFrame> {
  try {
    return decodeFrame(
      JSON.parse(typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk)),
    );
  } catch {
    return Option.none();
  }
}

// Response headers a carried environment may send through the relay's shared origin: content,
// caching, redirects, auth challenges and CORS. Anything else, such as cookies or site policies,
// would act on the relay origin itself.
const ALLOWED_RESPONSE_HEADERS = new Set([
  "content-type",
  "content-range",
  "content-disposition",
  "content-encoding",
  "content-language",
  "accept-ranges",
  "cache-control",
  "etag",
  "last-modified",
  "expires",
  "vary",
  "location",
  "www-authenticate",
  "retry-after",
  "dpop-nonce",
  "access-control-allow-origin",
  "access-control-allow-credentials",
  "access-control-allow-methods",
  "access-control-allow-headers",
  "access-control-expose-headers",
  "access-control-max-age",
]);

function withoutHopByHop(headers: Readonly<Record<string, string>>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers).filter(([name]) => !isClientAddressClaim(name.toLowerCase())),
  );
}

/**
 * The client as this relay sees it. A peer on a private or loopback address is the front proxy,
 * whose own entry is the last one; any other peer is the client itself.
 */
function clientAddress(request: HttpServerRequest.HttpServerRequest): string | undefined {
  const peer = Option.getOrUndefined(request.peerAddress);
  if (peer === undefined || endpointAddressRejection(peer, "public") === null) return peer;
  const forwarded = request.headers["x-forwarded-for"]?.split(",").at(-1)?.trim();
  return forwarded !== undefined && isIpAddress(forwarded) ? forwarded : peer;
}

/**
 * Keeps a redirect on the environment's own path: root-relative targets gain its prefix, and
 * anything a browser would resolve elsewhere, including `//host` and `/\host`, is dropped.
 */
function carriedLocation(location: string, target: ChannelTarget): string | undefined {
  const base = new URL(`${target.prefix}${target.path}`, "https://relay.invalid");
  const rooted = /^\/(?![/\\])/u.test(location) ? `${target.prefix}${location}` : location;
  try {
    const resolved = new URL(rooted, base);
    const path = `${resolved.pathname}${resolved.search}${resolved.hash}`;
    return resolved.origin === base.origin &&
      (resolved.pathname === target.prefix || resolved.pathname.startsWith(`${target.prefix}/`))
      ? path
      : undefined;
  } catch {
    return undefined;
  }
}

/** Lowercases names, which frames from an environment need not do, and keeps the allowlist. */
function allowedResponseHeaders(headers: Readonly<Record<string, string>>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers)
      .map(([name, value]) => [name.toLowerCase(), value] as const)
      .filter(([name]) => ALLOWED_RESPONSE_HEADERS.has(name)),
  );
}

// Only these codes may be sent in a close frame; 1005 and 1006 only describe a close.
function sendableCloseCode(code: number | undefined): number {
  return code !== undefined &&
    (code === 1000 ||
      (code >= 1001 && code <= 1003) ||
      (code >= 1007 && code <= 1014) ||
      (code >= 3000 && code <= 4999))
    ? code
    : 1000;
}

type ChannelTarget = NonNullable<ReturnType<typeof channelPathTarget>>;

/** The client's headers, telling the environment which prefix the relay stripped. */
function forwardedHeaders(request: HttpServerRequest.HttpServerRequest, target: ChannelTarget) {
  const client = clientAddress(request);
  return {
    ...withoutHopByHop(request.headers),
    "x-forwarded-prefix": target.prefix,
    ...(client === undefined ? {} : { "x-forwarded-for": client }),
  };
}

const busy = () =>
  HttpServerResponse.text("The relay is carrying too much for this environment right now.", {
    status: 503,
    headers: { "retry-after": "5" },
  });

const isWebSocketUpgrade = (request: HttpServerRequest.HttpServerRequest) =>
  request.headers.upgrade?.toLowerCase() === "websocket";

/**
 * Carries environments with no public address: each one dials `/v1/environments/:id/channel`,
 * and requests under its `/env/<key>/` path are forwarded over that socket, prefix stripped.
 * Channels live in this process, so a relay serving them must run as a single replica.
 */
export const makeRelayChannels = (options: Partial<RelayChannelLimits> = {}) => {
  const limits = { ...DEFAULT_RELAY_CHANNEL_LIMITS, ...options };
  const budget = makeByteBudget(limits.maxBufferedBytes);
  const channels = new Map<string, Channel>();
  let nextId = 0;

  const dispatch = (channel: Channel, chunk: string | Uint8Array) => {
    const frame = Option.getOrNull(parseFrame(chunk));
    if (frame?.type === "ping") return channel.send({ type: "ping" });
    if (frame?.type === "http-response") {
      const response = channel.responses.get(frame.id);
      return response ? Deferred.succeed(response, frame).pipe(Effect.asVoid) : Effect.void;
    }
    if (frame?.type === "ws-opened" || frame?.type === "ws-message" || frame?.type === "ws-close") {
      const carried = channel.sockets.get(frame.id);
      if (carried === undefined) return Effect.void;
      if (frame.type === "ws-message") {
        const size = frame.data.length;
        // A queue that is not empty belongs to a client that stopped reading; past the cap it is
        // closed rather than buffered, and one huge frame alone still gets through.
        if (
          (carried.queuedBytes > 0 && carried.queuedBytes + size > limits.maxSocketQueueBytes) ||
          !budget.acquire(size)
        ) {
          return Deferred.succeed(carried.overflowed, undefined).pipe(Effect.asVoid);
        }
        carried.queuedBytes += size;
      }
      return Queue.offer(carried.inbox, frame).pipe(Effect.asVoid);
    }
    return Effect.void;
  };

  const serveChannel = Effect.fn("RelayChannels.serveChannel")(function* (
    principal: EnvironmentCredentials.EnvironmentCredentialPrincipal,
    token: string,
    request: HttpServerRequest.HttpServerRequest,
  ) {
    const { environmentId } = principal;
    const credentials = yield* EnvironmentCredentials.EnvironmentCredentials;
    const key = yield* channelKey(environmentId, principal.environmentPublicKey);
    const socket = yield* request.upgrade;
    const writer = yield* socket.writer;
    const reader = yield* socket.reader;
    const socketEnded = yield* Deferred.make<void>();
    const environmentSocket = writableSocketOf(request);
    const channel: Channel = {
      // Once the socket closes, a write waits for it to reopen, which never happens.
      send: (frame) =>
        whenDrained(environmentSocket).pipe(
          Effect.andThen(writer.write(JSON.stringify(frame))),
          Effect.raceFirst(Deferred.await(socketEnded)),
          Effect.ignore,
        ),
      responses: new Map(),
      sockets: new Map(),
      replaced: yield* Deferred.make<void>(),
      ended: socketEnded,
      quietChecks: 0,
      failedLookups: 0,
      wakeups: yield* Queue.sliding<void>(1),
    };
    const previous = channels.get(key);
    channels.set(key, channel);
    // The environment reconnected, so the old connection is dead even if its socket looks open.
    if (previous !== undefined) yield* Deferred.succeed(previous.replaced, undefined);
    yield* Effect.logInfo("Relay channel connected", { environmentId });
    yield* Effect.addFinalizer(() =>
      Effect.gen(function* () {
        if (channels.get(key) === channel) channels.delete(key);
        // Pending requests answer 502, and sends stop waiting on the closed socket.
        yield* Deferred.succeed(socketEnded, undefined);
        for (const [id, carried] of channel.sockets) {
          yield* Queue.offer(carried.inbox, { type: "ws-close", id, code: 1012 });
        }
        yield* Effect.logInfo("Relay channel disconnected", { environmentId });
      }),
    );
    const readFrames = reader.pull.pipe(
      Effect.tap(() =>
        Effect.sync(() => {
          channel.quietChecks = 0;
        }),
      ),
      Effect.flatMap((chunks) =>
        Effect.forEach(chunks, (chunk) => dispatch(channel, chunk), { discard: true }),
      ),
      Effect.forever,
    );
    // Revocation and silence end the channel on the relay's own clock, whatever the environment
    // sends; a revocation elsewhere wakes the check early.
    const recheck = (timed: boolean) =>
      Effect.suspend(() => {
        if (timed) channel.quietChecks += 1;
        if (channel.quietChecks > MAX_QUIET_CHECKS) return Effect.succeed(false);
        return credentials.authenticate(token).pipe(
          Effect.match({
            onFailure: () => {
              channel.failedLookups += 1;
              return channel.failedLookups <= MAX_FAILED_LOOKUPS;
            },
            onSuccess: (current) => {
              channel.failedLookups = 0;
              return Option.exists(current, (now) => now.credentialId === principal.credentialId);
            },
          }),
        );
      });
    // True when the interval elapsed, false when woken early.
    const nextCheck = Queue.take(channel.wakeups).pipe(
      Effect.as(false),
      Effect.timeoutOrElse({
        duration: CREDENTIAL_RECHECK_INTERVAL,
        orElse: () => Effect.succeed(true),
      }),
    );
    const ended = yield* nextCheck.pipe(
      Effect.flatMap(recheck),
      Effect.repeat({ while: (stillValid) => stillValid }),
      Effect.forkScoped({ startImmediately: true }),
    );
    // Tells the environment its channel now receives traffic.
    yield* channel.send({ type: "ping" });
    yield* Effect.raceFirst(
      readFrames,
      Effect.raceFirst(Fiber.join(ended), Deferred.await(channel.replaced)),
    ).pipe(Effect.ignore);
    return HttpServerResponse.empty();
  }, Effect.scoped);

  const forwardHttp = Effect.fn("RelayChannels.forwardHttp")(function* (
    channel: Channel,
    request: HttpServerRequest.HttpServerRequest,
    target: ChannelTarget,
  ) {
    if (channel.responses.size >= limits.maxPendingRequests) return busy();
    // Held twice while forwarded: the body itself and its base64 copy in the frame.
    const declared = Number(request.headers["content-length"] ?? 0);
    const reserved =
      2 *
      (request.headers["transfer-encoding"] !== undefined || !Number.isFinite(declared)
        ? limits.maxBodyBytes
        : Math.min(declared, limits.maxBodyBytes));
    if (!budget.acquire(reserved)) return busy();
    yield* Effect.addFinalizer(() => Effect.sync(() => budget.release(reserved)));
    const body = yield* request.arrayBuffer.pipe(
      Effect.provideService(HttpIncomingMessage.MaxBodySize, ByteSize.bytes(limits.maxBodyBytes)),
      Effect.map((buffer) => new Uint8Array(buffer)),
      Effect.option,
    );
    if (Option.isNone(body)) {
      return HttpServerResponse.text("The request body is too large for the relay.", {
        status: 413,
      });
    }
    const id = ++nextId;
    const response = yield* Deferred.make<HttpResponseFrame>();
    channel.responses.set(id, response);
    const channelEnded = Deferred.await(channel.ended).pipe(
      Effect.as<HttpResponseFrame>({ type: "http-response", id, status: 502, headers: {} }),
    );
    const result = yield* channel
      .send({
        type: "http-request",
        id,
        method: request.method,
        path: target.path,
        headers: forwardedHeaders(request, target),
        ...(body.value.byteLength > 0 ? { body: Buffer.from(body.value).toString("base64") } : {}),
      })
      .pipe(
        Effect.andThen(Effect.raceFirst(Deferred.await(response), channelEnded)),
        Effect.timeoutOption(RELAY_CHANNEL_RESPONSE_TIMEOUT_MS),
        Effect.ensuring(Effect.sync(() => channel.responses.delete(id))),
      );
    if (Option.isNone(result)) {
      return HttpServerResponse.text("The environment did not answer in time.", { status: 504 });
    }
    // The answer is already in memory; refusing it keeps it from also being decoded and sent.
    const answerBytes = result.value.body?.length ?? 0;
    if (!budget.acquire(answerBytes)) return busy();
    yield* Effect.addFinalizer(() => Effect.sync(() => budget.release(answerBytes)));
    const { "content-type": contentType, ...forwarded } = allowedResponseHeaders(
      result.value.headers,
    );
    // Every carried environment shares the relay's origin, and anyone can link one: its responses
    // may not run script with that origin or set cookies the relay and other environments would
    // see. PDFs stay sandboxed too, so a browser shows them only as downloads, not inline.
    const headers: Record<string, string> = {
      ...forwarded,
      "content-security-policy": CARRIED_CONTENT_SECURITY_POLICY,
      "x-content-type-options": "nosniff",
    };
    if (headers.location !== undefined) {
      const location = carriedLocation(headers.location, target);
      if (location === undefined) delete headers.location;
      else headers.location = location;
    }
    return HttpServerResponse.uint8Array(
      result.value.body ? Buffer.from(result.value.body, "base64") : new Uint8Array(),
      { status: result.value.status, headers, ...(contentType ? { contentType } : {}) },
    );
  }, Effect.scoped);

  const forwardWebSocket = Effect.fn("RelayChannels.forwardWebSocket")(function* (
    channel: Channel,
    request: HttpServerRequest.HttpServerRequest,
    target: ChannelTarget,
  ) {
    if (channel.sockets.size >= limits.maxSockets) return busy();
    const id = ++nextId;
    const carried: CarriedSocket = {
      inbox: yield* Queue.unbounded<SocketFrame>(),
      queuedBytes: 0,
      overflowed: yield* Deferred.make<void>(),
    };
    const { inbox } = carried;
    channel.sockets.set(id, carried);
    // However this ends, even when the client vanishes mid-handshake, the environment closes its
    // side: its local socket would otherwise stay open, sending into an inbox nobody reads.
    yield* Effect.addFinalizer(() =>
      Effect.sync(() => {
        channel.sockets.delete(id);
        budget.release(carried.queuedBytes);
        carried.queuedBytes = 0;
      }).pipe(Effect.andThen(channel.send({ type: "ws-close", id }))),
    );
    yield* channel.send({
      type: "ws-open",
      id,
      path: target.path,
      headers: forwardedHeaders(request, target),
    });
    const opened = yield* Queue.take(inbox).pipe(Effect.timeoutOption("15 seconds"));
    if (Option.isNone(opened) || opened.value.type !== "ws-opened") {
      return HttpServerResponse.text("The environment refused the WebSocket.", { status: 502 });
    }
    const socket = yield* request.upgrade;
    const writer = yield* socket.writer;
    const reader = yield* socket.reader;
    const clientSocket = writableSocketOf(request);
    const toClient = Queue.take(inbox).pipe(
      Effect.tap((frame) =>
        Effect.sync(() => {
          if (frame.type !== "ws-message") return;
          carried.queuedBytes -= frame.data.length;
          budget.release(frame.data.length);
        }),
      ),
      Effect.flatMap((frame) =>
        frame.type === "ws-message"
          ? whenDrained(clientSocket).pipe(
              Effect.andThen(
                writer.write(frame.binary ? Buffer.from(frame.data, "base64") : frame.data),
              ),
            )
          : frame.type === "ws-close"
            ? writer
                .write(new Socket.CloseEvent(sendableCloseCode(frame.code), frame.reason))
                .pipe(Effect.andThen(Effect.fail("closed" as const)))
            : Effect.void,
      ),
      Effect.forever,
    );
    const toEnvironment = reader.pull.pipe(
      Effect.flatMap((chunks) =>
        Effect.forEach(
          chunks,
          (chunk) =>
            channel.send(
              typeof chunk === "string"
                ? { type: "ws-message", id, data: chunk }
                : {
                    type: "ws-message",
                    id,
                    data: Buffer.from(chunk).toString("base64"),
                    binary: true,
                  },
            ),
          { discard: true },
        ),
      ),
      Effect.forever,
    );
    // 1013 (try again later): the client fell too far behind what its environment sent.
    const overflowed = Deferred.await(carried.overflowed).pipe(
      Effect.andThen(writer.write(new Socket.CloseEvent(1013, "client too slow"))),
    );
    yield* Effect.raceFirst(toClient, Effect.raceFirst(toEnvironment, overflowed)).pipe(
      Effect.ignore,
    );
    return HttpServerResponse.empty();
  }, Effect.scoped);

  const authenticateChannel = Effect.fn("RelayChannels.authenticateChannel")(function* (
    request: HttpServerRequest.HttpServerRequest,
    pathId: string,
  ) {
    const token = /^Bearer +(.+)$/iu.exec(request.headers.authorization ?? "")?.[1];
    if (token === undefined) return null;
    const credentials = yield* EnvironmentCredentials.EnvironmentCredentials;
    const principal = yield* credentials
      .authenticate(token)
      .pipe(Effect.orElseSucceed(() => Option.none()));
    return Option.isSome(principal) && principal.value.environmentId === decodeURIComponent(pathId)
      ? { principal: principal.value, token }
      : null;
  });

  /** Rechecks every channel's credential now, as after a revocation. */
  const recheckAll = Effect.suspend(() =>
    Effect.forEach(channels.values(), (channel) => Queue.offer(channel.wakeups, undefined), {
      discard: true,
    }),
  );

  // Untraced: it wraps every relay request, and the relay API traces its own.
  const middleware = Effect.fnUntraced(function* <E, R>(
    handler: Effect.Effect<HttpServerResponse.HttpServerResponse, E, R>,
  ) {
    const request = yield* HttpServerRequest.HttpServerRequest;
    const channelPath = CHANNEL_SOCKET_PATH.exec(request.url);
    if (channelPath?.[1] !== undefined && isWebSocketUpgrade(request)) {
      const authorized = yield* authenticateChannel(request, channelPath[1]);
      if (authorized === null) return HttpServerResponse.empty({ status: 401 });
      return yield* serveChannel(authorized.principal, authorized.token, request).pipe(
        Effect.orElseSucceed(() => HttpServerResponse.empty({ status: 400 })),
      );
    }
    const target = channelPathTarget(request.url);
    if (target === null) return yield* handler;
    const channel = channels.get(target.key);
    if (channel === undefined) {
      return HttpServerResponse.text("This environment is not connected to the relay.", {
        status: 502,
      });
    }
    return yield* (
      isWebSocketUpgrade(request)
        ? forwardWebSocket(channel, request, target)
        : forwardHttp(channel, request, target)
    ).pipe(Effect.orElseSucceed(() => HttpServerResponse.empty({ status: 400 })));
  });
  return Object.assign(middleware, { recheckAll });
};
