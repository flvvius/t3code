import { assert, describe, it } from "@effect/vitest";
import * as NodeServices from "@effect/platform-node/NodeServices";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";

import * as DesktopConfig from "../../app/DesktopConfig.ts";
import * as DesktopEnvironment from "../../app/DesktopEnvironment.ts";
import * as ElectronSafeStorage from "../../electron/ElectronSafeStorage.ts";
import * as IpcChannels from "../channels.ts";
import * as DesktopIpc from "../DesktopIpc.ts";
import { installOidcSessionStore } from "./oidcSession.ts";

const SESSION = '{"refreshToken":"refresh-1"}';
const reverse = (value: string) => Array.from(value).reverse().join("");
const sealed = (value: string) => `sealed:${reverse(value)}`;

const layerSafeStorage = (available: boolean) =>
  Layer.succeed(ElectronSafeStorage.ElectronSafeStorage, {
    isEncryptionAvailable: Effect.succeed(available),
    encryptString: (value) => Effect.succeed(new TextEncoder().encode(sealed(value))),
    decryptString: (value) =>
      Effect.sync(() => reverse(new TextDecoder().decode(value).slice("sealed:".length))),
    selectedStorageBackend: Effect.succeedNone,
  } satisfies ElectronSafeStorage.ElectronSafeStorage["Service"]);

const layerEnvironment = (baseDir: string) =>
  DesktopEnvironment.layer({
    dirname: "/repo/apps/desktop/src",
    homeDirectory: baseDir,
    platform: "darwin",
    processArch: "arm64",
    appVersion: "1.2.3",
    appPath: "/repo",
    isPackaged: true,
    resourcesPath: "/missing/resources",
    runningUnderArm64Translation: false,
  }).pipe(
    Layer.provide(
      Layer.mergeAll(NodeServices.layer, DesktopConfig.layerTest({ T3CODE_HOME: baseDir })),
    ),
  );

/** Installs the store as startup does and answers like the renderer's bridge. */
const openStore = (baseDir: string, encryptionAvailable: boolean) =>
  Effect.gen(function* () {
    const invoke = new Map<string, DesktopIpc.DesktopIpcHandleListener>();
    const sync = new Map<string, DesktopIpc.DesktopIpcSyncListener>();
    const ipcMain: DesktopIpc.DesktopIpcMain = {
      removeHandler: (channel) => void invoke.delete(channel),
      handle: (channel, listener) => void invoke.set(channel, listener),
      removeAllListeners: (channel) => void sync.delete(channel),
      on: (channel, listener) => void sync.set(channel, listener),
    };
    yield* installOidcSessionStore().pipe(
      Effect.provide(
        Layer.mergeAll(
          DesktopIpc.layerTest(ipcMain),
          layerEnvironment(baseDir),
          layerSafeStorage(encryptionAvailable),
          NodeServices.layer,
        ),
      ),
    );
    const sender = { sender: { id: 1 } };
    return {
      get: () => {
        const event = { ...sender, returnValue: undefined as unknown };
        sync.get(IpcChannels.GET_OIDC_SESSION_CHANNEL)?.(event);
        return event.returnValue;
      },
      set: (session: string | null) =>
        Effect.promise(async () =>
          invoke.get(IpcChannels.SET_OIDC_SESSION_CHANNEL)?.(sender, session),
        ),
    };
  });

const sessionFileContents = (baseDir: string) =>
  Effect.gen(function* () {
    const fileSystem = yield* FileSystem.FileSystem;
    const environment = yield* DesktopEnvironment.DesktopEnvironment;
    return yield* fileSystem
      .readFileString(environment.path.join(environment.stateDir, "oidc-session.bin"))
      .pipe(Effect.orElseSucceed(() => null));
  }).pipe(Effect.provide(layerEnvironment(baseDir)));

describe("installOidcSessionStore", () => {
  it.effect("keeps the session encrypted on disk across restarts and deletes it on sign-out", () =>
    Effect.gen(function* () {
      const fileSystem = yield* FileSystem.FileSystem;
      const baseDir = yield* fileSystem.makeTempDirectoryScoped();

      const first = yield* openStore(baseDir, true);
      yield* first.set(SESSION);
      assert.equal(first.get(), SESSION);
      const onDisk = yield* sessionFileContents(baseDir);
      assert.isNotNull(onDisk);
      assert.notInclude(onDisk ?? "", "refresh-1");

      const restarted = yield* openStore(baseDir, true);
      assert.equal(restarted.get(), SESSION);

      yield* restarted.set(null);
      assert.isNull(restarted.get());
      assert.isNull(yield* sessionFileContents(baseDir));
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );

  it.effect("keeps the session in memory only when no keychain is available", () =>
    Effect.gen(function* () {
      const fileSystem = yield* FileSystem.FileSystem;
      const baseDir = yield* fileSystem.makeTempDirectoryScoped();

      const store = yield* openStore(baseDir, false);
      yield* store.set(SESSION);

      assert.equal(store.get(), SESSION);
      assert.isNull(yield* sessionFileContents(baseDir));
      assert.isNull((yield* openStore(baseDir, false)).get());
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );
});
