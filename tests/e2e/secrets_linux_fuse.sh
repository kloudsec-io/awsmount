#!/usr/bin/env bash
# Real FUSE mount of `awsmount secrets` over a moto-backed fake account,
# exercised with plain Unix tools. Run inside tests/e2e/Dockerfile.fuse:
#   docker build -f tests/e2e/Dockerfile.fuse -t awsmount-fuse-e2e .
#   docker run --rm --device /dev/fuse --cap-add SYS_ADMIN \
#       --security-opt apparmor:unconfined \
#       --entrypoint bash awsmount-fuse-e2e tests/e2e/secrets_linux_fuse.sh
set -u
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
EP=http://127.0.0.1:5596
M=/mnt/secrets
LOG=/tmp/secrets-mount.log
PASS=0
FAIL=0
check() {  # check <description> <command...>
  local d="$1"; shift
  if "$@" >/tmp/out.txt 2>&1; then PASS=$((PASS+1)); echo "PASS  $d"
  else FAIL=$((FAIL+1)); echo "FAIL  $d"; head -5 /tmp/out.txt; fi
}
moto_server -H 127.0.0.1 -p 5596 >/tmp/moto.log 2>&1 &
for _ in $(seq 1 40); do curl -s "$EP/moto-api/" >/dev/null && break; sleep 0.5; done
AWS_ENDPOINT_URL=$EP python - <<'PY'
import boto3
sm = boto3.client("secretsmanager", region_name="us-east-1")
ssm = boto3.client("ssm", region_name="us-east-1")
sm.create_secret(Name="team/api", SecretString="CANARY-api-value")
sm.create_secret(Name="team/json", SecretString='{"p":"CANARY-old"}')
sm.put_secret_value(SecretId="team/json", SecretString='{"p":"CANARY-new"}')
binary = b"\x00\xff\n\x00end"
open("/tmp/binary.bin", "wb").write(binary)
sm.create_secret(Name="team/binary", SecretBinary=binary)
ssm.put_parameter(Name="/app/db/host", Type="String", Value="CANARY-host")
ssm.put_parameter(Name="/app/db/password", Type="SecureString",
                  Value="CANARY-secure")
ssm.put_parameter(Name="/app", Type="String", Value="CANARY-app")
print("seeded")
PY
mkdir -p $M
awsmount secrets mount --endpoint-url $EP -r us-east-1 -v $M >$LOG 2>&1 &
MP=$!
for _ in $(seq 1 60); do mountpoint -q $M && break; sleep 0.5; done
if ! mountpoint -q $M; then echo "MOUNT FAILED"; cat $LOG; exit 1; fi
echo "--- mounted:"; mount | grep $M | cut -c1-120
reads() { grep -c "read value" $LOG; }
check "warns about secret values" grep -q 'secret VALUES' $LOG
check "no macOS cache warning on Linux" bash -c "! grep -q 'temporary copy' $LOG"
check "root has the two services" test "$(ls $M)" = "$(printf 'secretsmanager\nssm')"
R0=$(reads)
check "ls -lR and find read no value" bash -c "ls -lR $M >/dev/null && find $M -type f >/dev/null && [ $R0 -eq \$(grep -c 'read value' $LOG) ]"
check "an unread value has size 0" bash -c "[ \$(stat -c %s '$M/secretsmanager/team%2Fapi/value') -eq 0 ]"
check "secret value is exact" bash -c "[ \"\$(cat '$M/secretsmanager/team%2Fapi/value')\" = CANARY-api-value ]"
check "no newline is added" bash -c "[ \$(wc -c < '$M/secretsmanager/team%2Fapi/value') -eq 16 ]"
check "binary secret is byte exact" cmp "$M/secretsmanager/team%2Fbinary/value" /tmp/binary.bin
check "versions list current and previous" bash -c "[ \"\$(ls '$M/secretsmanager/team%2Fjson/versions')\" = \"\$(printf 'AWSCURRENT\nAWSPREVIOUS')\" ]"
check "previous version is the old value" bash -c "grep -q CANARY-old '$M/secretsmanager/team%2Fjson/versions/AWSPREVIOUS'"
check "describe.json is metadata only" python -c "
import json
d = json.load(open('$M/secretsmanager/team%2Fjson/describe.json'))
assert d['Name'] == 'team/json' and 'CANARY' not in json.dumps(d)"
check "parameter is nested like its path" bash -c "[ \"\$(cat $M/ssm/app/db/host)\" = CANARY-host ]"
check "SecureString is decrypted" bash -c "[ \"\$(cat $M/ssm/app/db/password)\" = CANARY-secure ]"
check "a parameter that is also a prefix has @value" bash -c "[ \"\$(cat $M/ssm/app/@value)\" = CANARY-app ]"
# bash drops directory entries whose d_ino is 0: a glob must see every value
check "glob */value matches every secret" bash -c "
  set -- $M/secretsmanager/*/value
  [ \$# -eq 3 ] && [ -e \"\$1\" ]"
check "readdir inodes are non-zero" python -c "
import os
e = list(os.scandir('$M/secretsmanager'))
assert e and all(x.inode() != 0 for x in e)"
check "files are 0400 and dirs 0500" bash -c "
  [ \"\$(stat -c %a '$M/secretsmanager/team%2Fapi/value')\" = 400 ] &&
  [ \"\$(stat -c %a $M/ssm)\" = 500 ]"
check "another user cannot read the mount" bash -c "
  ! setpriv --reuid=65534 --regid=65534 --clear-groups cat '$M/secretsmanager/team%2Fapi/value'"
check "grep -r finds a value" bash -c "grep -rl CANARY-secure $M/ssm | grep -q password"
check "write refused (touch)"  bash -c "! touch $M/ssm/x"
check "write refused (rm)"     bash -c "! rm -f '$M/secretsmanager/team%2Fapi/value'"
check "write refused (echo >)" bash -c "! echo x > '$M/secretsmanager/team%2Fapi/value'"
check "write refused (mkdir)"  bash -c "! mkdir $M/ssm/new"
check "core dumps are off for the process" bash -c "grep -i 'core file size' /proc/$MP/limits | grep -q ' 0  *0 '"
check "the log names reads but never a value" bash -c "grep -q 'read value' $LOG && ! grep -q CANARY $LOG"
check "no value was written under /tmp" bash -c "! grep -rl CANARY-api-value /tmp --exclude=out.txt --exclude=moto.log --exclude=binary.bin 2>/dev/null | grep -v seed | grep -q ."
kill -TERM $MP
wait $MP; RC=$?
check "SIGTERM ends the mount with status 0" test "$RC" -eq 0
check "unmounted cleanly" bash -c "! mountpoint -q $M"
check "SIGTERM prints no failure" bash -c "! grep -q 'mount failed' $LOG"
check "the mount process exited" bash -c "! kill -0 $MP 2>/dev/null"
echo "=== RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
