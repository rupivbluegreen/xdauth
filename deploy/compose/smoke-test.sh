#!/usr/bin/env bash
set -euo pipefail

wait_for() {
  for _ in $(seq 1 30); do
    if curl -fsS "$1" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "timed out waiting for $1" >&2
  exit 1
}

echo "waiting for services..."
wait_for http://127.0.0.1:8080/healthz
wait_for http://127.0.0.1:5556/dex/.well-known/openid-configuration

echo "checking /auth/start and /auth/poll..."
start=$(curl -fsS -X POST http://127.0.0.1:8080/auth/start \
  -H 'Content-Type: application/json' \
  -d '{"login_hint":"testuser","code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256","client_kind":"smoke-test","client_host":"ci"}')
echo "$start" | grep -q '"session_id"'
session_id=$(echo "$start" | grep -o '"session_id":"[^"]*"' | cut -d'"' -f4)

poll=$(curl -fsS -X POST http://127.0.0.1:8080/auth/poll \
  -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$session_id\",\"code_verifier\":\"dGVzdC12ZXJpZmllci1kb2VzLW5vdC1tYXR0ZXI\"}")
echo "$poll" | grep -q '"status":"pending"'

echo "checking sshd forwards the xdauth prompt over keyboard-interactive..."
output=$(timeout 10 ssh -tt -o StrictHostKeyChecking=no -o PreferredAuthentications=keyboard-interactive \
  -o PubkeyAuthentication=no -p 2222 testuser@127.0.0.1 < /dev/null 2>&1 || true)
echo "$output" | grep -q "to finish signing in"

echo "smoke test OK"
