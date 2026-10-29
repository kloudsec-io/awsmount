#!/usr/bin/env bash
# Real macOS WebDAV mount (no FUSE needed) of a moto-backed fake account,
# exercised with plain Unix tools. Needs: awsmount + moto[server,all]
# installed in the active Python environment. Run from the repo root:
#   bash tests/e2e/macos_webdav.sh
set -u
[ "$(uname -s)" = "Darwin" ] || { echo "macOS only"; exit 2; }
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
PORT=${MOTO_PORT:-5598}
EP=http://127.0.0.1:$PORT
WORK=$(cd "$(mktemp -d "${TMPDIR:-/tmp}/awsmount-e2e.XXXXXX")" && pwd -P)
M=$WORK/mnt
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
AWS_ENDPOINT_URL=$EP python - <<'PY'
import sys, boto3
sys.path.insert(0, ".")
from tests.fixtures.seed import seed_all
seed_all(boto3.Session(aws_access_key_id="test",
                       aws_secret_access_key="test",
                       region_name="us-east-1"))
print("seeded")
PY

AWS_ENDPOINT_URL=$EP python - <<'PY'
import json, boto3
cf = boto3.client("cloudformation", region_name="us-east-1")
tpl = {"Resources": {"Q": {"Type": "AWS::SQS::Queue"}},
       "Outputs": {"SecretKey": {"Value": "wJalrXUtnFEMI-LEAKTEST-KEY"},
                   "DbPass": {"Value": "hunter2-LEAKTEST-pass"},
                   "QueueName": {"Value": "ok-to-show"}}}
cf.create_stack(StackName="leaktest", TemplateBody=json.dumps(tpl))
PY
mkdir -p "$M"
awsmount --endpoint-url "$EP" -r us-east-1 mount "$M" >"$WORK/mount.log" 2>&1 &
MP=$!
for _ in $(seq 1 60); do mount | grep -q " on $M " && break; sleep 0.5; done
if ! mount | grep -q " on $M "; then echo "MOUNT FAILED"; cat "$WORK/mount.log"; exit 1; fi
echo "--- mounted:"; mount | grep " on $M " | cut -c1-150
R=$M/123456789012/us-east-1
check "mount is webdav + read-only" bash -c "mount | grep ' on $M ' | grep -q 'webdav.*read-only'"
check "ls account"            test "$(ls "$M")" = "123456789012"
check "ls region has ec2 vpc" bash -c "ls $R | grep -q ec2 && ls $R | grep -q vpc"
I=$(ls "$R/ec2/instances" | head -1)
check "describe.json is valid JSON" python -c "import json;json.load(open('$R/ec2/instances/$I/describe.json'))"
check "user-data is hidden" bash -c "grep -q '<hidden>' $R/ec2/instances/$I/user-data"
check "no secret leaks anywhere" bash -c "! grep -rq AKIA $R/ec2 2>/dev/null"
check "grep -r finds open SG" bash -c "grep -rl '0.0.0.0/0' $R/vpc/security-groups | grep -q rules.json"
check "find works" bash -c "test \$(find $R/vpc -name rules.json | wc -l) -ge 3"
check "CFN secret outputs never leak" bash -c "! grep -rq -e LEAKTEST $R/cloudformation 2>/dev/null"
check "CFN non-secret output still visible" bash -c "grep -rq ok-to-show $R/cloudformation"
check "write refused (touch)"  bash -c "! touch $R/x"
check "write refused (rm)"     bash -c "! rm -rf $R/vpc"
check "write refused (mkdir)"  bash -c "! mkdir $R/new"
check "write refused (echo >)" bash -c "! echo x > $R/ec2/instances/$I/name"
umount "$M"; sleep 1
check "unmounted cleanly" bash -c "! mount | grep -q ' on $M '"
echo "=== RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
