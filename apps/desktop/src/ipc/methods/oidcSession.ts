import { writeFileStringAtomically } from "@t3tools/shared/atomicWrite";
import { oidcDiscoveryUrl, parseOidcMetadata } from "@t3tools/shared/oidc";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Base64 from "effect/encoding/Base64";
import * as FileSystem from "effect/FileSystem";
import * as Ref from "effect/Ref";
import * as Schema from "effect/Schema";
import * as Semaphore from "effect/Semaphore";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientRequest from "effect/http/HttpClientRequest";

import * as DesktopEnvironment from "../../app/DesktopEnvironment.ts";
import * as ElectronSafeStorage from "../../electron/ElectronSafeStorage.ts";
import * as IpcChannels from "../channels.ts";
import * as DesktopIpc from "../DesktopIpc.ts";

const OIDC_SESSION_FILE_NAME = "oidc-session.bin";
const TOKEN_REQUEST_TIMEOUT = Duration.seconds(10);
const TOKEN_GRANT_TYPES = new Set(["authorization_code", "refresh_token"]);

export class DesktopOidcTokenRequestError extends Schema.TaggedError<DesktopOidcTokenRequestError>()(
  "DesktopOidcTokenRequestError",
  { reason: Schema.String, cause: Schema.optional(Schema.Defect()) },
) {
  override get message(): string {
    return `The token request was refused: ${this.reason}.`;
  }
}

/**
 * Keeps the renderer's OpenID Connect session encrypted with safeStorage. Read once here because a
 * sync IPC handler cannot wait on the filesystem; every write updates this copy first. Without a
 * keychain the session stays in memory and ends with the app.
 */
export const installOidcSessionStore = Effect.fn("desktop.ipc.oidcSession.install")(function* () {
  const ipc = yield* DesktopIpc.DesktopIpc;
  const environment = yield* DesktopEnvironment.DesktopEnvironment;
  const fileSystem = yield* FileSystem.FileSystem;
  const safeStorage = yield* ElectronSafeStorage.ElectronSafeStorage;
  const filePath = environment.path.join(environment.stateDir, OIDC_SESSION_FILE_NAME);
  const encryptionAvailable = safeStorage.isEncryptionAvailable.pipe(
    Effect.orElseSucceed(() => false),
  );

  const stored = yield* fileSystem.readFileString(filePath).pipe(
    Effect.flatMap((encoded) => Effect.fromResult(Base64.decode(encoded.trim()))),
    Effect.flatMap(safeStorage.decryptString),
    Effect.orElseSucceed(() => null),
  );
  const session = yield* Ref.make<string | null>(stored);
  const writes = yield* Semaphore.make(1);

  yield* ipc.handleSync(
    DesktopIpc.makeSyncIpcMethod({
      channel: IpcChannels.GET_OIDC_SESSION_CHANNEL,
      result: Schema.NullOr(Schema.String),
      handler: () => Ref.get(session),
    }),
  );
  yield* ipc.handle(
    DesktopIpc.makeIpcMethod({
      channel: IpcChannels.SET_OIDC_SESSION_CHANNEL,
      payload: Schema.NullOr(Schema.String),
      result: Schema.Void,
      handler: Effect.fn("desktop.ipc.oidcSession.set")(function* (next) {
        yield* Ref.set(session, next);
        yield* writes.withPermits(1)(
          Effect.gen(function* () {
            if (next !== null && (yield* encryptionAvailable)) {
              const encrypted = yield* safeStorage.encryptString(next);
              yield* writeFileStringAtomically({ filePath, contents: Base64.encode(encrypted) });
              return;
            }
            if (next !== null) {
              yield* Effect.logWarning(
                "No OS keychain is available, so the sign-in session is kept in memory only.",
              );
            }
            yield* fileSystem.remove(filePath, { force: true });
          }),
        );
      }),
    }),
  );
});

/**
 * Identity providers such as Entra refuse to redeem a code sent from the renderer's custom-scheme
 * origin, so token requests run here. Discovery runs here too, so only an issuer's own token
 * endpoint can be reached, and only with an authorization code or refresh token grant.
 */
export const requestOidcToken = DesktopIpc.makeIpcMethod({
  channel: IpcChannels.REQUEST_OIDC_TOKEN_CHANNEL,
  payload: Schema.Struct({
    issuer: Schema.String,
    tokenEndpoint: Schema.String,
    body: Schema.String,
  }),
  result: Schema.Struct({ status: Schema.Number, body: Schema.String }),
  handler: Effect.fn("desktop.ipc.oidcSession.requestToken")(function* (input) {
    const grantType = new URLSearchParams(input.body).get("grant_type");
    if (grantType === null || !TOKEN_GRANT_TYPES.has(grantType)) {
      return yield* new DesktopOidcTokenRequestError({ reason: "unsupported grant type" });
    }
    const httpClient = yield* HttpClient.HttpClient;
    const metadata = yield* HttpClientRequest.get(oidcDiscoveryUrl(input.issuer)).pipe(
      HttpClientRequest.acceptJson,
      HttpClient.filterStatusOk(httpClient).execute,
      Effect.flatMap((response) => response.json),
      Effect.flatMap((body) =>
        Effect.try({
          try: () => parseOidcMetadata(input.issuer, body),
          catch: (cause) => new DesktopOidcTokenRequestError({ reason: "discovery failed", cause }),
        }),
      ),
      Effect.timeout(TOKEN_REQUEST_TIMEOUT),
    );
    if (metadata.tokenEndpoint !== input.tokenEndpoint) {
      return yield* new DesktopOidcTokenRequestError({ reason: "not the issuer's token endpoint" });
    }
    const response = yield* HttpClientRequest.post(metadata.tokenEndpoint).pipe(
      HttpClientRequest.bodyText(input.body, "application/x-www-form-urlencoded"),
      HttpClientRequest.acceptJson,
      httpClient.execute,
      Effect.timeout(TOKEN_REQUEST_TIMEOUT),
    );
    return { status: response.status, body: yield* response.text };
  }),
});
