import { isDesktopOidcCallbackUrl, OIDC_CALLBACK_PATH } from "@t3tools/shared/oidc";

import type { DesktopBridge } from "@t3tools/contracts";

import { resolveOidcPublicConfig } from "../publicConfig";
import {
  clearStoredOidcSessions,
  createOidcController,
  OIDC_SESSION_STORAGE_KEY,
  type KeyValueStore,
  type OidcController,
} from "@t3tools/client-runtime/relay";

// Storage throws when the browser blocks site data. Memory keeps the app from crashing, though a
// redirect sign-in cannot finish then.
const storageOrMemory = (read: () => Storage): KeyValueStore => {
  try {
    return read();
  } catch {
    const entries = new Map<string, string>();
    return {
      getItem: (key) => entries.get(key) ?? null,
      setItem: (key, value) => void entries.set(key, value),
      removeItem: (key) => void entries.delete(key),
    };
  }
};

// The main process keeps the session encrypted with the OS keychain; this mirror answers the
// controller's synchronous reads.
function desktopSessionStore(bridge: DesktopBridge): KeyValueStore {
  let session = bridge.getOidcSession();
  const write = (value: string | null) => {
    session = value;
    // Unsaved, the session still lasts until the app quits.
    void bridge.setOidcSession(value).catch(() => undefined);
  };
  return {
    getItem: (key) => (key === OIDC_SESSION_STORAGE_KEY ? session : null),
    setItem: (key, value) => {
      if (key === OIDC_SESSION_STORAGE_KEY) write(value);
    },
    removeItem: (key) => {
      if (key === OIDC_SESSION_STORAGE_KEY) write(null);
    },
  };
}

// Entra and other providers refuse to redeem a code from the renderer's t3code:// origin, so the
// main process, which sends no Origin, makes the token requests.
const desktopTokenFetch =
  (bridge: DesktopBridge, issuer: string): typeof fetch =>
  async (input, init) => {
    if (init?.method !== "POST") return fetch(input, init);
    const reply = await bridge.requestOidcToken({
      issuer,
      tokenEndpoint: String(input),
      body: String(init.body),
    });
    return new Response(reply.body, {
      status: reply.status,
      headers: { "content-type": "application/json" },
    });
  };

let controller: OidcController | null = null;

/**
 * The one controller for this page; null when the build has no OpenID Connect provider. The web
 * keeps the session in this tab's sessionStorage, so it ends with the tab and other tabs sign in
 * on their own; the desktop app keeps it encrypted in the main process.
 */
export function getBrowserOidcController(): OidcController | null {
  const config = resolveOidcPublicConfig();
  if (config === null) return null;
  if (controller !== null) return controller;
  try {
    // Drops sessions earlier builds left in long-lived localStorage.
    clearStoredOidcSessions(window.localStorage);
  } catch {}
  const bridge = window.desktopBridge;
  controller = createOidcController({
    config,
    redirectUri: `${window.location.origin}${OIDC_CALLBACK_PATH}`,
    sessions:
      bridge === undefined
        ? storageOrMemory(() => window.sessionStorage)
        : desktopSessionStore(bridge),
    pending: storageOrMemory(() => window.sessionStorage),
    navigate: (url) => window.location.assign(url),
    ...(bridge === undefined ? {} : { fetch: desktopTokenFetch(bridge, config.issuer) }),
    ...(navigator.locks === undefined
      ? {}
      : { withRefreshLock: (run) => navigator.locks.request("t3-oidc-refresh", run) }),
  });
  return controller;
}

let abandonDesktopSignIn: (() => void) | null = null;

/**
 * Electron signs in through the system browser (RFC 8252): the identity provider redirects to the
 * app's private-use scheme, and the main process hands that link back over `webLinks`.
 */
export function signInThroughDesktopBrowser(controller: OidcController): Promise<string> | null {
  const bridge = window.desktopBridge;
  if (bridge === undefined) return null;
  return controller.signInWithPrompt(async (authorizeUrl) => {
    abandonDesktopSignIn?.();
    const callback = new Promise<string>((resolve, reject) => {
      const unsubscribe = bridge.webLinks.onOpen((url) => {
        if (!isDesktopOidcCallbackUrl(url)) return;
        abandonDesktopSignIn = null;
        unsubscribe();
        resolve(url);
      });
      abandonDesktopSignIn = () => {
        unsubscribe();
        reject(new Error("A newer sign-in replaced this one."));
      };
    });
    await bridge.openExternal(authorizeUrl);
    return callback;
  });
}
