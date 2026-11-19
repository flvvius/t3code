# Running T3 Code in-house

How to run a self-hosted relay and your own T3 Code builds for an organization. Set up the relay
itself with [README.md](./README.md) first.

## What you are operating

The relay is workstation-control infrastructure. It signs the proofs that linked machines accept
before granting full access, and with relay channels it carries their traffic. Whoever controls
the relay host, its cloud-mint private key or its HTTPS endpoint can run commands on every
linked developer machine. Protect it like a CI runner that holds deploy keys.

## The relay host

- Run it on a dedicated host or VM, not next to other services. Limit shell and Docker access to
  the people who operate it; Docker access is root on the host.
- Keep the files in `secrets/` in a secret manager and restore them from there. Never put the
  cloud-mint private key in an image, a repository or a ticket.
- Allow outbound traffic only to your identity provider's discovery and key endpoints, the
  relay's own public address (relay channels check carried environments through it), your
  certificate authority for Caddy, and your package mirror.
- Do not capture or inspect its traffic, and do not turn on request logging with bodies,
  `Authorization` headers or query strings. Channel traffic includes prompts, code and session
  tokens.
- Leave `RELAY_MANUAL_ENDPOINTS=off`. Use relay channels for machines without a public address.
- Optionally restrict who can reach the relay with the `remote_ip` example in `Caddyfile`.
- Monitor disk space, Postgres health, certificate expiry and the relay's restarts. A restart
  drops every relay channel until machines reconnect.

## Entra ID hardening

Without these, every account in the tenant can sign in to the relay and link machines.

- **Assignment required.** In **Enterprise applications** for the app, set **Assignment
  required?** to **Yes** and assign the group of T3 Code users.
- **Conditional Access.** Target the app with a policy that requires MFA and a compliant or
  hybrid-joined device. Use **Sign-in frequency** to bound how long a session lasts without a
  fresh sign-in.
- **Device code flow.** It is only needed for headless CLI sign-in and is a common phishing
  route. Block it with a Conditional Access **Authentication flows** condition, excluding a small
  group that needs it. Set **Allow public client flows** to **No** when nobody does.
- **No API scope.** Do not add scopes under **Expose an API** or pre-authorized client
  applications. The relay accepts tokens whose audience is the client id, so an exposed API would
  let other applications' access tokens through.
- **Token lifetime.** ID tokens last an hour by default, and a stolen one works at the relay
  until it expires. Assign a token lifetime policy with a shorter ID token lifetime, such as 15
  minutes, to the app's service principal.
- **Platforms.** Register the web redirect under **Single-page application** and the desktop,
  mobile and CLI redirects under **Mobile and desktop applications**. Register only the redirects
  of clients you ship. Leave out `https://app.t3.codes/oidc/callback` so only your own web build
  can complete sign-in.
- **Issuer.** Use the tenant-specific v2.0 issuer, `https://login.microsoftonline.com/<tenant-id>/v2.0`,
  never `/common` or `/organizations`.

## Every linked machine

- Turn on **Require approval for new devices** in **Settings → Sharing & access** on each host,
  then review the approved devices there. Without it, anyone who signs in as the user, or who
  holds the relay's key, can connect a new device without a prompt.
- Turn off product usage data and relay tracing with a [managed policy](../../../docs/user/managed-policy.md)
  (`"telemetry": false`), or `T3CODE_TELEMETRY_ENABLED=false` for standalone servers.
- Decide whether hosts publish agent activity. It sends project and thread titles to the relay
  (**Settings → Sharing & access → Publish agent activity**).

## Offboarding

Disabling a user in the identity provider stops new sign-ins, but devices that already connected
keep their environment sessions until those expire. Run all of these, in order:

1. **Identity provider.** Disable the account or remove it from the app's group, then revoke its
   sessions (in Entra, **Revoke sessions** on the user).
2. **Relay.** Run
   `docker compose exec relay node src/node.mjs offboard --subject <sub> [--issuer <iss>]`
   with the user's `sub` claim (in Entra, the object's pairwise `sub`, not the email). In one
   transaction it revokes their environment links and credentials and deletes their device and
   push registrations; live relay channels close within seconds. `--issuer` defaults to
   `OIDC_ISSUER`.
3. **Their machines.** On each machine the user linked, run `t3 auth connect-device list` and
   `t3 auth connect-device revoke <code>` for their devices, then `t3 auth session list` and
   `t3 auth session revoke <id>` for their sessions. If the machine is being returned, wipe it.
4. **Verify.** The user's devices no longer appear in either list, and the relay shows none of
   their environments. A sign-in attempt from their account fails at the identity provider.

Test this runbook with a test account before the first real departure.

## Your own client builds

Ship builds you sign and update yourself, with your relay and identity provider baked in. Set
`T3CODE_RELAY_URL`, `T3CODE_OIDC_ISSUER` and `T3CODE_OIDC_CLIENT_ID` in the repository's `.env`
before building (see [README.md](./README.md#point-the-apps-at-this-relay)), and leave the
`*_OTLP_*` tracing variables unset.

### Desktop

Build with `node scripts/build-desktop-artifact.ts --platform <mac|win|linux> --signed` in your
own pipeline. Do not run the upstream release workflow as is: it also publishes to npm and the
hosted web app.

- **Update feed.** Set `T3CODE_DESKTOP_UPDATE_REPOSITORY=<owner>/<repo>` to your own release
  repository when packaging. Without it the build uses `GITHUB_REPOSITORY` in GitHub Actions, and
  no feed at all elsewhere. To serve updates from an internal mirror instead, set
  `updates.feedUrl` in the [managed policy](../../../docs/user/managed-policy.md#updates); set
  `updates.mode` to `off` if device management installs updates.
- **Signing.** macOS needs your Developer ID certificate (`CSC_LINK`, `CSC_KEY_PASSWORD`) and
  notarization key (`APPLE_API_KEY`, `APPLE_API_KEY_ID`, `APPLE_API_ISSUER`). Windows uses Azure
  Trusted Signing (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` and the
  `AZURE_TRUSTED_SIGNING_*` variables). Missing credentials produce unsigned artifacts, and the
  macOS CLI archive falls back to ad hoc signing, so verify signatures before publishing
  (`codesign --verify --deep --strict` and `spctl -a -t exec` on macOS, `Get-AuthenticodeSignature`
  on Windows). Check the packaged `app-update.yml` names your feed.
- **Identity.** The build keeps upstream's app id (`com.t3tools.t3code`) and `t3code://` scheme,
  which come from `scripts/build-desktop-artifact.ts`. An upstream install on the same machine
  can receive your sign-in callback. Block upstream installs with device management, or change
  the id, scheme and redirect URIs together in your fork.
- Upgrade-test each release from the previous internal version on every OS.

### Android

`apps/mobile/app.config.ts` points the app at upstream's Expo project and over-the-air update
channel. This fork turns those updates off unless the build sets `T3CODE_MOBILE_UPDATES_ENABLED=1`.
Only set it after pointing `updates.url`, `owner` and `extra.eas.projectId` at your own Expo
project; otherwise an installed build can download upstream JavaScript.

- Build locally with `eas build --profile production -p android --local`, signed with an upload
  key your organization holds. Distribute through managed Google Play or your device management,
  and check the signing certificate of the installed app.
- The package id (`com.t3tools.t3code`) and `t3code` scheme are upstream's. Change them in
  `app.config.ts` and in your redirect URIs if users may also install the store app.
- Review the production network security config: debug-friendly settings that allow cleartext
  traffic or user-installed certificates should not ship.

### Web

Host your own web build and register its `/oidc/callback` under **Single-page application**. A
browser keeps the sign-in session in its profile, so prefer the desktop app on shared or
unmanaged machines.

## Hardening settings

Defaults are the safe choice; change them only for a reason.

| Where         | Variable                                                 | Default  | Effect                                                                                                                                     |
| ------------- | -------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Relay         | `RELAY_MANUAL_ENDPOINTS`                                 | `off`    | Self-declared environment endpoints: `public` refuses private networks, `private` allows them; loopback and link-local are always refused. |
| Relay         | `RELAY_API_MAX_BODY_BYTES`                               | 1 MiB    | Largest relay API request.                                                                                                                 |
| Relay         | `RELAY_CHANNEL_MAX_BODY_BYTES`                           | 50 MiB   | Largest request carried to an environment.                                                                                                 |
| Relay         | `RELAY_MAX_ENVIRONMENTS_PER_USER`                        | 25       | Environment links per account.                                                                                                             |
| Relay         | `<NAME>_FILE`                                            | —        | Read a secret such as `DATABASE_URL` from a file.                                                                                          |
| T3 server     | `T3CODE_TELEMETRY_ENABLED`                               | off      | Product analytics and relay tracing.                                                                                                       |
| T3 server     | `T3CODE_USAGE_PRICE_FETCH`                               | on       | Model price table download from GitHub.                                                                                                    |
| T3 server     | `T3CODE_CONNECT_DEVICE_TRUST_DAYS`                       | 7        | Days a T3 Connect device stays approved (0 = forever).                                                                                     |
| T3 server     | `T3CODE_RELAY_REMOTE_CONTROL`                            | on       | Remote control through the relay channel.                                                                                                  |
| T3 server     | `T3CODE_AGENT_ACTIVITY_PUBLISHING` / `..._REDACT_TITLES` | on / off | Publish agent activity; hide thread and project titles.                                                                                    |
| T3 server     | `T3CODE_ALLOWED_HOSTS`                                   | —        | Extra host names for browser sessions behind a reverse proxy.                                                                              |
| Client build  | `T3CODE_RELAY_PINNED` / `T3CODE_RELAY_ALLOWLIST`         | off      | Lock clients to `T3CODE_RELAY_URL`, or to a list of relays.                                                                                |
| Android build | `T3CODE_ANDROID_ALLOW_CLEARTEXT` / `..._TRUST_USER_CAS`  | off      | Allow `http://` servers; trust user-installed CAs.                                                                                         |
| Android build | `T3CODE_MOBILE_UPDATES_ENABLED`                          | off      | Expo over-the-air updates.                                                                                                                 |

New devices wait for approval by default (`requireConnectDeviceApproval`), and provider update
checks are off by default (`enableProviderUpdateChecks`); both are in server settings.

## Known limitations

- **No end-to-end encryption.** The relay operator can read and change relay channel traffic, and
  can mint access to any linked machine with the cloud-mint key.
- **Custom-scheme mobile redirects.** Another Android app can register the same `t3code://`
  scheme and receive the sign-in redirect. PKCE stops it from redeeming the code alone, but
  device management should limit which apps users install.
- **Single replica.** Relay channels, queues and rate limits live in one process. A restart or
  host failure disconnects every carried environment until it is back.
- **Session lifetime.** Environment sessions outlive the identity provider session, so
  offboarding needs the steps above, not only an identity provider change.
