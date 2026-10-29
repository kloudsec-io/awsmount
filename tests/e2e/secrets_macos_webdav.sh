#!/usr/bin/env bash
# Real macOS WebDAV mount of `awsmount secrets` over a moto-backed fake
# account, exercised with plain Unix tools. Needs: awsmount + moto[server,all]
# in the active Python environment. Run from the repo root:
#   bash tests/e2e/secrets_macos_webdav.sh
set -u
[ "$(uname -s)" = "Darwin" ] || { echo "macOS only"; exit 2; }
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
PORT=${MOTO_PORT:-5597}
EP=http://127.0.0.1:$PORT
WORK=$(cd "$(mktemp -d "${TMPDIR:-/tmp}/awsmount-secrets-e2e.XXXXXX")" && pwd -P)
M=$WORK/mnt
LOG=$WORK/mount.log
PASS=0
FAIL=0
check() {
  local d="$1"; shift
  if "$@" >"$WORK/out.txt" 2>&1; then PASS=$((PASS+1)); echo "PASS  $d"
  else FAIL=$((FAIL+1)); echo "FAIL  $d"; head -5 "$WORK/out.txt"; fi
}
cleanup() {
  umount "$M" 2>/dev/null
  [ -n "${MP:-}" ] && kill "$MP" 2>/dev/null
  [ -n "${MOTO:-}" ] && kill "$MOTO" 2>/dev/null
}
trap cleanup EXIT
moto_server -H 127.0.0.1 -p "$PORT" >"$WORK/moto.log" 2>&1 &
MOTO=$!
for _ in $(seq 1 60); do curl -s "$EP/moto-api/" >/dev/null && break; sleep 0.5; done
AWS_ENDPOINT_URL=$EP python - "$WORK" <<'PY'
import sys, boto3
work = sys.argv[1]
sm = boto3.client("secretsmanager", region_name="us-east-1")
ssm = boto3.client("ssm", region_name="us-east-1")
sm.create_secret(Name="team/api", SecretString="CANARY-api-value")
sm.create_secret(Name="team/json", SecretString='{"p":"CANARY-old"}')
sm.put_secret_value(SecretId="team/json", SecretString='{"p":"CANARY-new"}')
binary = b"\x00\xff\n\x00end"
open(f"{work}/binary.bin", "wb").write(binary)
sm.create_secret(Name="team/binary", SecretBinary=binary)
ssm.put_parameter(Name="/app/db/host", Type="String", Value="CANARY-host")
ssm.put_parameter(Name="/app/db/password", Type="SecureString",
                  Value="CANARY-secure")
ssm.put_parameter(Name="/app", Type="String", Value="CANARY-app")
print("seeded")
PY
mkdir -p "$M"
awsmount secrets mount --endpoint-url "$EP" -r us-east-1 -v "$M" >"$LOG" 2>&1 &
MP=$!
for _ in $(seq 1 60); do mount | grep -q " on $M " && break; sleep 0.5; done
if ! mount | grep -q " on $M "; then echo "MOUNT FAILED"; cat "$LOG"; exit 1; fi
echo "--- mounted:"; mount | grep " on $M " | cut -c1-150
reads() { grep -c "read value" "$LOG"; }
check "mount is webdav + read-only" bash -c "mount | grep ' on $M ' | grep -q 'webdav.*read-only'"
check "warns about secret values and the macOS cache" bash -c "grep -q 'secret VALUES' $LOG && grep -q 'temporary copy' $LOG"
check "root has the two services" test "$(ls "$M")" = "$(printf 'secretsmanager\nssm')"
R0=$(reads)
check "ls -lR and find read no value" bash -c "ls -lR $M >/dev/null && find $M -type f >/dev/null && [ $R0 -eq \$(grep -c 'read value' $LOG) ]"
check "secret value is exact" bash -c "[ \"\$(cat '$M/secretsmanager/team%2Fapi/value')\" = CANARY-api-value ]"
check "no newline is added" bash -c "[ \$(wc -c < '$M/secretsmanager/team%2Fapi/value') -eq 16 ]"
check "binary secret is byte exact" cmp "$M/secretsmanager/team%2Fbinary/value" "$WORK/binary.bin"
check "versions list current and previous" bash -c "[ \"\$(ls '$M/secretsmanager/team%2Fjson/versions')\" = \"\$(printf 'AWSCURRENT\nAWSPREVIOUS')\" ]"
check "previous version is the old value" bash -c "grep -q CANARY-old '$M/secretsmanager/team%2Fjson/versions/AWSPREVIOUS'"
check "describe.json is metadata only" bash -c "python -c \"import json;d=json.load(open('$M/secretsmanager/team%2Fjson/describe.json'));assert d['Name']=='team/json' and 'CANARY' not in json.dumps(d)\""
check "parameter is nested like its path" bash -c "[ \"\$(cat $M/ssm/app/db/host)\" = CANARY-host ]"
check "SecureString is decrypted" bash -c "[ \"\$(cat $M/ssm/app/db/password)\" = CANARY-secure ]"
check "a parameter that is also a prefix has @value" bash -c "[ \"\$(cat $M/ssm/app/@value)\" = CANARY-app ]"
check "files are owner-only" bash -c "[ \"\$(stat -f %Sp '$M/secretsmanager/team%2Fapi/value' | cut -c2-4)\" = rwx ] && [ \"\$(stat -f %Sp '$M/secretsmanager/team%2Fapi/value' | cut -c5-10)\" = '------' ]"
check "grep -r finds a value" bash -c "grep -rl CANARY-secure $M/ssm | grep -q password"
check "write refused (touch)"  bash -c "! touch $M/ssm/x"
check "write refused (rm)"     bash -c "! rm -f '$M/secretsmanager/team%2Fapi/value'"
check "write refused (echo >)" bash -c "! echo x > '$M/secretsmanager/team%2Fapi/value'"
check "write refused (mkdir)"  bash -c "! mkdir $M/ssm/new"
check "the log names reads but never a value" bash -c "grep -q 'read value' $LOG && ! grep -q CANARY $LOG"
umount "$M"; sleep 1
check "unmounted cleanly" bash -c "! mount | grep -q ' on $M '"
check "the mount process exited" bash -c "! kill -0 $MP 2>/dev/null"
echo "=== RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
