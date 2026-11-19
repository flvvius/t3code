#!/bin/sh
# Creates the relay's secrets: the cloud-mint signing key pair (Ed25519) and the database
# passwords. Secrets that already exist are kept.
set -eu
dir="$(dirname "$0")/secrets"
(umask 077 && mkdir -p "$dir")
chmod 700 "$dir"

private="$dir/cloud-mint-private.pem"
if [ -f "$private" ]; then
  echo "Keeping the existing $private."
else
  (umask 077 && openssl genpkey -algorithm ed25519 -out "$private")
fi
# Derived every run, so a missing or partial public key is repaired.
openssl pkey -in "$private" -pubout -out "$dir/cloud-mint-public.pem"
chmod 644 "$dir/cloud-mint-public.pem"

# Hex only: the relay password goes into DATABASE_URL as is.
for name in postgres-password relay-db-password; do
  if [ ! -f "$dir/$name" ]; then
    (umask 077 && openssl rand -hex 32 >"$dir/$name")
  fi
done
if [ ! -f "$dir/database-url" ]; then
  (umask 077 && printf 'postgres://relay:%s@postgres:5432/relay\n' \
    "$(cat "$dir/relay-db-password")" >"$dir/database-url")
fi

# Compose mounts secret files with their host owner and mode. The relay runs as uid 1000 and
# Postgres (alpine image) as uid 70.
need_chown=""
for entry in "1000:$private" "1000:$dir/database-url" "70:$dir/postgres-password" \
  "70:$dir/relay-db-password"; do
  uid="${entry%%:*}"
  file="${entry#*:}"
  if [ "$(id -u)" = 0 ]; then
    chown "$uid:$uid" "$file"
  elif [ "$(id -u)" != "$uid" ]; then
    need_chown="$need_chown\n  sudo chown $uid:$uid $file"
  fi
done
if [ -n "$need_chown" ]; then
  printf "The containers read these files as other users. Run:%b\n" "$need_chown" >&2
fi
echo "Secrets are in $dir"
