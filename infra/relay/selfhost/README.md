# Self-hosted T3 relay

Runs the T3 Connect control plane on your own server with Docker Compose: a relay, Postgres,
and Caddy terminating HTTPS. Sign-in comes from your own OpenID Connect provider, so no Clerk
account is needed.

Every web, desktop, mobile and CLI client signed in to the same account sees the same linked
environments, and opens their projects and threads live through them; that is how clients stay
in sync. Threads are stored on each environment, not on the relay, but the relay stores some
metadata about them, and with relay channels their live traffic passes through it (see
[What the relay stores and sees](#what-the-relay-stores-and-sees)).

Whoever controls the relay host, its signing key or its HTTPS endpoint can reach every machine
linked to it. Before running it for a team, read [Running T3 Code in-house](./OPERATING.md).

## Setup

Run these from the repository root.

1. Create the secrets (once): the cloud-mint signing keys and the database passwords.

   ```sh
   infra/relay/selfhost/gen-keys.sh
   ```

   The containers read the secret files as uid 1000 (relay) and uid 70 (Postgres). Run the
   `sudo chown` commands the script prints, or run it as root. Keep a copy of the files in your
   secret manager.

2. Configure the stack:

   ```sh
   cp infra/relay/selfhost/.env.example infra/relay/selfhost/.env
   ```

   Set `RELAY_DOMAIN` and `RELAY_PUBLIC_ORIGIN` to the host name that resolves to this server,
   and `OIDC_ISSUER` to your provider's issuer URL.

3. In your identity provider, create one public OAuth client (authorization code with PKCE, no
   secret) for the T3 Code apps, and set `OIDC_AUDIENCE` to its client id. The apps send the
   provider's **ID token** to the relay, so its `aud` is that client id and its `sub` identifies
   the user. Allow these redirect URIs:

   | Client  | Redirect URI                                                   |
   | ------- | -------------------------------------------------------------- |
   | Web     | `https://<your web app origin>/oidc/callback`                  |
   | Desktop | `t3code://app/oidc/callback` (`t3code-dev://…` for dev builds) |
   | Mobile  | `t3code://oidc` (`t3code-dev://oidc`, `t3code-preview://oidc`) |
   | CLI     | `http://127.0.0.1:34338/callback`, or enable the device flow   |

   Request the `offline_access` scope so sessions refresh without signing in again. Register
   only the clients you use.

   **Microsoft Entra ID.** Set `OIDC_ISSUER` to the tenant's v2.0 issuer,
   `https://login.microsoftonline.com/<tenant-id>/v2.0`. The `/common` and `/organizations`
   documents report a `{tenantid}` template, which the relay's exact issuer check rejects.
   In the app registration:

   - Register the web redirect URI under **Single-page application**. A **Web** URI cannot
     redeem the code from the browser.
   - Register the desktop, mobile and CLI URIs under **Mobile and desktop applications**.
   - Set **Allow public client flows** to **Yes** only if you use the CLI device flow. Without
     it the device flow's token poll fails with `AADSTS7000218`.
   - Entra limits refresh tokens issued to a single-page application to 24 hours, so web
     sessions ask for a new sign-in daily.

   Restrict who can sign in before anyone links a machine: see
   [Entra ID hardening](./OPERATING.md#entra-id-hardening).

4. Start it:

   ```sh
   docker compose -f infra/relay/selfhost/docker-compose.yml --env-file infra/relay/selfhost/.env up -d --build
   ```

5. Check it:

   ```sh
   curl https://<RELAY_DOMAIN>/health        # {"ok":true,"service":"relay"}
   ```

   Requests without a bearer token get `401`. Caddy obtains the certificate automatically when
   `RELAY_DOMAIN` is a public name that reaches this server on ports 80 and 443.

Only Caddy publishes ports. Postgres sits on a network with no route out, and the relay connects
to it as `relay`, a role that owns the relay database but is not a superuser. Containers run
with no added privileges, a read-only root filesystem, and memory and process limits. Caddy caps
request bodies at 2 MiB for the API and 64 MiB for relay channels, and sends HSTS.

## Backups and upgrades

The Postgres volume is the source of truth for relay state. Dumps contain who uses the relay,
their machines' names and addresses, and thread and project titles, so encrypt them before they
leave the host. With [age](https://age-encryption.org):

```sh
umask 077
docker compose -f infra/relay/selfhost/docker-compose.yml exec -T postgres \
  pg_dump -U relay -d relay --format=custom \
  | age -r <backup public key> > relay-$(date +%Y%m%d).dump.age
```

Keep the age private key offline, and back up the `infra/relay/selfhost/secrets` directory
separately from the dumps. A short retention, such as 7 daily and 4 weekly dumps, limits how much
history a leaked backup exposes. Rows the relay already deleted live on in older dumps.

To restore, start Postgres alone on an empty volume, load the dump, then start the rest:

```sh
docker compose -f infra/relay/selfhost/docker-compose.yml up -d --wait postgres
age -d -i <backup private key file> relay-<date>.dump.age \
  | docker compose -f infra/relay/selfhost/docker-compose.yml exec -T postgres \
    pg_restore -U relay -d relay --no-owner --no-privileges --exit-on-error
docker compose -f infra/relay/selfhost/docker-compose.yml --env-file infra/relay/selfhost/.env up -d --build
```

Test a restore on a separate host now and then. Migrations run automatically when a new relay
image starts, and the process refuses to serve if a migration fails.

The base images are pinned by digest. To update them, look up the current digests and replace
the `@sha256:` values in `Dockerfile` and `docker-compose.yml`:

```sh
docker buildx imagetools inspect node:26-alpine     | grep -m1 Digest
docker buildx imagetools inspect postgres:16-alpine | grep -m1 Digest
docker buildx imagetools inspect caddy:2-alpine     | grep -m1 Digest
```

### Moving an older deployment to the relay role

Deployments created before the relay had its own database role run it as the Postgres
superuser, with `POSTGRES_PASSWORD` in `.env`. That superuser cannot be demoted, so move the
data into a fresh volume. With this version checked out and the old stack still running:

```sh
cd infra/relay/selfhost
./gen-keys.sh                              # keeps the mint keys, adds the database secrets
umask 077
docker compose exec -T postgres pg_dump -U relay -d relay --no-owner --no-privileges > old.sql
grep -c "dump complete" old.sql          # 1: the dump finished
docker compose down
docker volume rm t3-relay_postgres-data
docker compose up -d --wait postgres
docker compose exec -T postgres psql -U relay -d relay -v ON_ERROR_STOP=1 < old.sql
docker compose up -d --build
shred -u old.sql
```

Then remove `POSTGRES_PASSWORD` from `.env`. Clients stay linked: the data and mint keys are
unchanged.

## Point the apps at this relay

In each app, open **Settings → Connections → T3 Connect service**, choose **Self-hosted relay**,
and enter `https://<RELAY_DOMAIN>`. The app reads the identity provider from the relay's
`/.well-known/t3-relay` (`OIDC_ISSUER`, and `OIDC_AUDIENCE` as the client id), so nothing else
needs typing. Check what the apps will see with:

```sh
curl https://<RELAY_DOMAIN>/.well-known/t3-relay
# {"oidc":{"issuer":"https://sso.example.com/realms/t3","clientId":"t3-code"},"managedTunnels":false}
```

The `t3` server and CLI read the relay from the environment instead:

```sh
T3CODE_RELAY_URL=https://relay.example.com
T3CODE_OIDC_ISSUER=https://sso.example.com/realms/t3
T3CODE_OIDC_CLIENT_ID=t3-code
```

A fork can also make the relay its build's default by setting the same three variables in the
repository's `.env` before building web, desktop or mobile (`scripts/lib/public-config.ts` maps
them to each app's prefix). A configured OpenID Connect provider replaces Clerk in that build.

## Reach an environment without a tunnel

**Through the relay (no address to expose).** Set `RELAY_CHANNELS=true`. An environment linked
without its own public address then keeps one outbound WebSocket open to the relay, and the relay
serves it at `RELAY_PUBLIC_ORIGIN/env/<key>/`, forwarding HTTP and WebSocket traffic over that
socket with the prefix stripped and named in `X-Forwarded-Prefix`. Nothing to open on the
environment's network and no extra DNS or certificate. All of that environment's traffic passes
through the relay host, and channels live in the relay process, so keep a single replica. Clients
need a T3 Code version that keeps an environment's path prefix. The relay also checks carried
environments through its own public address, so this host must be able to reach `RELAY_PUBLIC_ORIGIN`.

**At an address you expose.** Manual endpoints are off by default (`RELAY_MANUAL_ENDPOINTS=off`).
With `public`, an environment can publish an HTTPS address you already expose (reverse proxy,
port forward) and the relay brokers connections to it like a managed endpoint. Run
`t3 connect --publish-only`, then start the server with `T3CODE_PUBLIC_URL` set to that address:

```sh
t3 connect --publish-only
T3CODE_PUBLIC_URL=https://t3.example.com t3 serve
```

The address must serve the environment's HTTP and WebSocket traffic over HTTPS. The relay
refuses loopback, link-local and cloud metadata addresses. `private` also accepts private
network addresses (LAN, Tailscale) for relays only your own network uses. Host names are checked
as written, not resolved, so any user who can sign in can make the relay connect to a name they
choose. Turn manual endpoints on only when every user is trusted, and prefer relay channels. A
published address takes precedence over a relay channel.

## Linking a host from a browser

The browser app has no sign-in action in its "T3 Connect service" card. Link the host from its
terminal instead with `t3 connect link --publish-only`, then restart T3 Code.

## Behind another reverse proxy

Caddy is the bundled proxy. To use your own (nginx, Traefik, a cloud load balancer), drop the
`caddy` service, point your proxy at the relay's port 8080, and keep `RELAY_PUBLIC_ORIGIN` at
the public HTTPS address. The relay builds no URLs from request headers, so `X-Forwarded-*`
values are ignored. `OIDC_ISSUER` must equal the issuer your provider reports
publicly, including any path prefix your proxy adds. Carry over the body limits and headers in
`Caddyfile`, and do not add framing restrictions under `/env/`: the apps frame file previews
from carried environments.

## What the relay stores and sees

The relay database holds:

- **Users:** the identity provider's issuer and `sub` for each user. No names or email addresses.
- **Linked environments:** each environment's id, name (usually the machine name), public key,
  HTTP and WebSocket addresses, settings, the linking device's id, and hashed credentials.
- **Agent activity:** while a thread runs on a host with **Publish agent activity** on, its
  project title, thread title, model name, phase, a short status headline and detail line, and a
  deep link. Rows for finished threads are deleted after about 30 minutes; a thread that never
  reports finishing keeps its row.
- **Mobile devices:** device id, platform, OS and app version, label, notification preferences,
  and push tokens when push is enabled.
- **Short-lived records:** replay protection for signed requests and a log of push delivery
  attempts.

It does not store messages, prompts, code or files. With `RELAY_CHANNELS=true`, though, every
request to a carried environment, including prompts, code, terminal output and session tokens,
passes through the relay process unencrypted after Caddy ends TLS. Whoever runs the relay host
can read it.

## What this host does not do

- **Managed tunnels.** Cloudflare-managed endpoints are not available; use a relay channel or
  a manual endpoint (above), or reach environments directly.
- **Push notifications.** APNs and FCM need credentials tied to the mobile app's signing
  identity, so this stack turns them off. To enable them, add `APNS_ENABLED=true`, the `APNS_*`
  or `FCM_SERVICE_ACCOUNT` variables and a stable `APNS_DELIVERY_JOB_SIGNING_SECRET` (for
  example `openssl rand -hex 32`) to the `relay` service environment.
- **Held webhooks.** Webhooks are not stored while an environment is offline.
- **Clerk accounts and T3 Chat linking.** Sign-in is OIDC only. Adding `CLERK_SECRET_KEY`,
  `CLERK_PUBLISHABLE_KEY` and `CLERK_JWT_AUDIENCE` to the `relay` service also accepts Clerk.
- **Scale.** Queues and rate limits are in memory, so run one replica. Queued push jobs do not
  survive a restart.
