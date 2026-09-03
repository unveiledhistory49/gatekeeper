#!/usr/bin/env bash
# E2E smoke test: builds the binary, uses a tmp sqlite DB, exercises the
# login -> role -> user -> api-key -> campaign -> decide -> close -> audit
# flow. No jq: JSON is parsed with python3.
# Env overrides: PORT (default 8080), PYTHON (default python3).
set -euo pipefail
PORT="${PORT:-8080}"
PYTHON="${PYTHON:-python3}"
BASE="http://127.0.0.1:$PORT"
TMP="$(mktemp -d)"; JAR="$TMP/jar"; OUT="$TMP/out"; CODE=""; EXPECT=""; PID=""
trap '[ -n "$PID" ] && kill "$PID" 2>/dev/null || true; rm -rf "$TMP"' EXIT
go build -o "$TMP/gatekeeper" ./cmd/gatekeeper
export GATEKEEPER_DATABASE_URL="sqlite://$TMP/e2e.db" GATEKEEPER_ADDR=":$PORT" GATEKEEPER_PEPPER="e2e-pepper"
"$TMP/gatekeeper" migrate >/dev/null
PROV="$("$TMP/gatekeeper" provision-org --name e2e --email admin@e2e.test --password 'admin-password-1')"
ORG="$($PYTHON -c "import json,sys; print(json.loads(sys.argv[1])['org_id'])" "$PROV")"
"$TMP/gatekeeper" serve & PID=$!
UP=0
for _ in $(seq 1 50); do
  if curl -sSf "$BASE/healthz" -o /dev/null; then UP=1; break; fi
  sleep 0.2
done
[ "$UP" = 1 ] || { echo "FAIL: server never healthy"; exit 1; }
call() { # <method> <path> [json-body] [curl args...]
  local m="$1" p="$2"; shift 2
  local d=""
  case "${1:-}" in \{*) d="$1"; shift;; esac
  if [ -n "$d" ]; then CODE=$(curl -s -o "$OUT" -w '%{http_code}' -X "$m" "$BASE$p" -b "$JAR" -c "$JAR" -H 'Content-Type: application/json' -d "$d" "$@");
  else CODE=$(curl -s -o "$OUT" -w '%{http_code}' -X "$m" "$BASE$p" -b "$JAR" -c "$JAR" "$@"); fi
  [ "$CODE" = "$EXPECT" ] || { echo "FAIL $m $p: want $EXPECT got $CODE: $(cat "$OUT")"; exit 1; }
}
val() { $PYTHON -c "import json; print(json.load(open('$OUT'))$1)"; }
pok() { $PYTHON -c "import json; d=json.load(open('$OUT')); assert ($1), d" || { echo "ASSERT FAIL: $1: $(cat "$OUT")"; exit 1; }; }
EXPECT=200; call GET /healthz
EXPECT=200; call POST /v1/login "{\"org_id\":\"$ORG\",\"email\":\"admin@e2e.test\",\"password\":\"admin-password-1\"}"; pok "d.get('token')"
EXPECT=201; call POST /v1/roles '{"name":"e2e-editor","description":"E2E","permissions":["users:read"]}'; ROLE="$(val "['id']")"
EXPECT=201; call POST /v1/users "{\"email\":\"ed@e2e.test\",\"name\":\"Ed\",\"password\":\"editor-password-1\",\"role_ids\":[\"$ROLE\"]}" -H 'Idempotency-Key: e2e-key-0001'; USER="$(val "['id']")"
EXPECT=201; call POST /v1/api-keys '{"name":"e2e"}'; KEY="$(val "['id']")"; RAW="$(val "['api_key']")"
EXPECT=200; call POST "/v1/api-keys/$KEY/revoke"
CODE=$(curl -s -o "$OUT" -w '%{http_code}' "$BASE/v1/me" -H "X-API-Key: $RAW") # no cookie jar: revoked key must 401
[ "$CODE" = 401 ] || { echo "FAIL revoked key: got $CODE: $(cat "$OUT")"; exit 1; }
EXPECT=201; call POST /v1/reviews/campaigns '{"name":"e2e review"}'; CAMP="$(val "['id']")"
EXPECT=200; call GET "/v1/reviews/campaigns/$CAMP/items"
ITEM="$($PYTHON -c "import json; its=json.load(open('$OUT'))['items']; print(next((i['id'] for i in its if i['user_id']=='$USER' and i['role_id']=='$ROLE'), its[0]['id']))")"
EXPECT=200; call POST "/v1/reviews/items/$ITEM/decide" '{"decision":"revoked"}'
EXPECT=200; call GET "/v1/users/$USER"; pok "'$ROLE' not in d.get('role_ids', [])"
EXPECT=200; call GET "/v1/reviews/campaigns/$CAMP/items"
for id in $($PYTHON -c "import json; print(' '.join(i['id'] for i in json.load(open('$OUT'))['items'] if i['decision']=='pending'))"); do
  EXPECT=200; call POST "/v1/reviews/items/$id/decide" '{"decision":"certified"}'
done
EXPECT=200; call POST "/v1/reviews/campaigns/$CAMP/close"; pok "d.get('status')=='closed'"
EXPECT=200; call GET /v1/audit/verify; pok "d.get('ok') is True"
echo "e2e OK (org=$ORG user=$USER campaign=$CAMP)"
