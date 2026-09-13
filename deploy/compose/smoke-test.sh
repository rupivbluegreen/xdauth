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
wait_for http://localhost:8080/healthz
wait_for http://localhost:5556/dex/.well-known/openid-configuration

# code_challenge/code_verifier below are a real matching S256 PKCE pair; poll rejects a mismatch with 403 even while pending
echo "checking /auth/start and /auth/poll..."
start=$(curl -fsS -X POST http://localhost:8080/auth/start \
  -H 'Content-Type: application/json' \
  -d '{"login_hint":"testuser","code_challenge":"y4cdL7BG4ds6wCyjiP37mb6VvZE-cGQKIvCMhnjpHws","code_challenge_method":"S256","client_kind":"smoke-test","client_host":"ci"}')
echo "$start" | grep -q '"session_id"'
session_id=$(echo "$start" | grep -o '"session_id":"[^"]*"' | cut -d'"' -f4)

poll=$(curl -fsS -X POST http://localhost:8080/auth/poll \
  -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$session_id\",\"code_verifier\":\"WCfIhHoIVgfOP1X38azRCi9_wZ6dvIFYwvgskbmu85U\"}")
echo "$poll" | grep -q '"status":"pending"'

# xdauth-sshd (2323), not sshd/pam_exec (2222): pam_exec's helper blocks on approval before its stdout ever flushes, so within a short timeout the pam_exec path shows nothing by design (docs/ssh-demo.md "A note on prompt delivery") — xdauth-sshd delivers the same prompt live, proven by TestKeyboardInteractive_ChallengeDeliveredBeforeApproval
echo "checking xdauth-sshd forwards the xdauth prompt over keyboard-interactive..."
output=$(timeout 10 ssh -tt -o StrictHostKeyChecking=no -o PreferredAuthentications=keyboard-interactive \
  -o PubkeyAuthentication=no -p 2323 testuser@localhost < /dev/null 2>&1 || true)
echo "$output" | grep -q "to finish signing in"

echo "smoke test OK"
