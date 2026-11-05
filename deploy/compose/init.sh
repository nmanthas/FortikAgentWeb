#!/usr/bin/env bash
# One-time setup of the Docker Compose pilot (idempotent: existing files and
# secrets are kept). Writes, next to this script:
#   .env          random passwords, the secret store's master key (chmod 600)
#   tls/          a development PKI: CA, server certificate, client certificates
#                 for the hook, interceptors and agentgateway (replace with your
#                 PKI for a real pilot: same file names)
#   data/secrets  the encrypted secret store with api_tokens, agent_tokens and
#                 the Diary signing key
#   tokens.env    the API tokens (admin, security, auditor, interceptor): shown
#                 once, keep them in your password manager (chmod 600)
# Usage: ./init.sh [public-host]   (default localhost; the server certificate
# and allowed hosts include it)
set -euo pipefail
cd "$(dirname "$0")"
HOST="${1:-localhost}"
IMAGE="${FORTIK_IMAGE:-fortik:dev}"
rand() { openssl rand -hex 24; }
sha() { printf '%s' "$1" | (sha256sum 2>/dev/null || shasum -a 256) | cut -d' ' -f1; }

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "==> building $IMAGE"
  docker build -t "$IMAGE" ../..
fi

if [ ! -s .env ]; then
  echo "==> .env (random passwords and master key)"
  umask 077
  cat > .env <<ENV
FORTIK_UID=$(id -u)
FORTIK_GID=$(id -g)
FORTIK_PUBLIC_HOST=$HOST
FORTIK_ENFORCEMENT_MODE=observe
FORTIK_MASTER_KEY=$(openssl rand -base64 32)
POSTGRES_PASSWORD=$(rand)
FORTIK_OWNER_PASSWORD=$(rand)
FORTIK_APP_PASSWORD=$(rand)
REDIS_PASSWORD=$(rand)
ENV
fi
set -a; source .env; set +a
mkdir -p data/secrets data/spool tls
chmod 700 data/secrets data/spool

RUN=(docker run --rm -i --user "$FORTIK_UID:$FORTIK_GID" -e FORTIK_MASTER_KEY -e FORTIK_APP_PASSWORD -e REDIS_PASSWORD -e FORTIK_PUBLIC_HOST
  -e FORTIK_ENFORCEMENT_MODE -v "$PWD/fortik.yaml:/etc/fortik/fortik.yaml:ro" -v "$PWD/data/secrets:/var/lib/fortik/secrets"
  -v "$PWD/tls:/tls" "$IMAGE")

echo "==> TLS (development PKI in ./tls)"
"${RUN[@]}" certs dev -out /tls -if-absent -hosts "localhost,127.0.0.1,fortik,$HOST" -clients "hook,interceptor,agentgateway,agent"

put() { "${RUN[@]}" secrets put -if-absent -config /etc/fortik/fortik.yaml -name "$1"; }
if [ ! -s tokens.env ]; then
  echo "==> API tokens and the Diary signing key"
  umask 077
  ADMIN="adm_$(rand)" SEC="sec_$(rand)" AUD="aud_$(rand)" INT="int_$(rand)"
  printf 'FORTIK_TOKEN_ADMIN=%s\nFORTIK_TOKEN_SECURITY=%s\nFORTIK_TOKEN_AUDITOR=%s\nFORTIK_TOKEN_INTERCEPTOR=%s\n' "$ADMIN" "$SEC" "$AUD" "$INT" > tokens.env
  printf '[{"name":"admin","sha256":"%s","roles":["admin"]},{"name":"security","sha256":"%s","roles":["security","auditor"]},{"name":"auditor","sha256":"%s","roles":["auditor"]},{"name":"interceptor","sha256":"%s","roles":["interceptor"]}]' \
    "$(sha "$ADMIN")" "$(sha "$SEC")" "$(sha "$AUD")" "$(sha "$INT")" | put api_tokens
  echo '{}' | put agent_tokens
  "${RUN[@]}" keygen | put diary_signing_key
fi
echo
echo "Ready. Start:   docker compose up -d"
echo "API tokens:     $PWD/tokens.env (keep secret)"
echo "Client certs:   $PWD/tls/client-*.crt (+ .key), CA: $PWD/tls/ca.crt"
