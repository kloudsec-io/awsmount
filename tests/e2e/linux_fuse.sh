#!/usr/bin/env bash
# Real FUSE mount of a moto-backed fake account, exercised with plain
# Unix tools. Run inside tests/e2e/Dockerfile.fuse:
#   docker build -f tests/e2e/Dockerfile.fuse -t awsmount-fuse-e2e .
#   docker run --rm --device /dev/fuse --cap-add SYS_ADMIN \
#       --security-opt apparmor:unconfined awsmount-fuse-e2e
set -u
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
EP=http://127.0.0.1:5599
M=/mnt/aws
PASS=0
FAIL=0
check() {  # check <description> <command...>
  local d="$1"; shift
  if "$@" >/tmp/out.txt 2>&1; then PASS=$((PASS+1)); echo "PASS  $d"
  else FAIL=$((FAIL+1)); echo "FAIL  $d"; head -5 /tmp/out.txt; fi
}
moto_server -H 127.0.0.1 -p 5599 >/tmp/moto.log 2>&1 &
for _ in $(seq 1 40); do curl -s "$EP/moto-api/" >/dev/null && break; sleep 0.5; done
AWS_ENDPOINT_URL=$EP python - <<'PY'
import sys, boto3
sys.path.insert(0, "/src")
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
mkdir -p $M
awsmount --endpoint-url $EP -r us-east-1 mount $M >/tmp/mount.log 2>&1 &
MP=$!
for _ in $(seq 1 60); do mountpoint -q $M && break; sleep 0.5; done
if ! mountpoint -q $M; then echo "MOUNT FAILED"; cat /tmp/mount.log; exit 1; fi
echo "--- mounted:"; mount | grep $M | cut -c1-120
R=$M/123456789012/us-east-1
check "ls account"            test "$(ls $M)" = "123456789012"
check "ls region has ec2 vpc" bash -c "ls $R | grep -q ec2 && ls $R | grep -q vpc"
I=$(ls $R/ec2/instances | head -1)
check "instance has describe.json" test -s $R/ec2/instances/$I/describe.json
check "describe.json is valid JSON" python -c "import json;json.load(open('$R/ec2/instances/$I/describe.json'))"
check "user-data is hidden" bash -c "grep -q '<hidden>' $R/ec2/instances/$I/user-data"
check "no secret leaks anywhere" bash -c "! grep -rq 'AKIA' $R/ec2 2>/dev/null"
check "grep -r finds open SG" bash -c "grep -rl '0.0.0.0/0' $R/vpc/security-groups | grep -q rules.json"
check "symlink resolves to subnet" test -d $R/ec2/instances/$I/links/subnet
check "readlink is relative" bash -c "readlink $R/ec2/instances/$I/links/subnet | grep -q '^\.\./'"
check "find works" bash -c "test \$(find $R/vpc -name rules.json | wc -l) -ge 3"
check "CFN secret outputs never leak" bash -c "! grep -rq -e LEAKTEST $R/cloudformation 2>/dev/null"
check "CFN non-secret output still visible" bash -c "grep -rq ok-to-show $R/cloudformation"
check "write refused (touch)"  bash -c "! touch $R/x"
check "write refused (rm)"     bash -c "! rm -rf $R/vpc"
check "write refused (mkdir)"  bash -c "! mkdir $R/new"
check "write refused (echo >)" bash -c "! echo x > $R/ec2/instances/$I/name"
# Shell globs: bash drops directory entries whose d_ino is 0, so a readdir
# that returns bare names makes every `*` match nothing on a FUSE mount.
check "glob */describe.json matches every instance" bash -c "
  set -- $R/ec2/instances/*/describe.json
  [ \$# -eq \$(ls $R/ec2/instances | wc -l) ] && [ -e \"\$1\" ]"
check "glob over a collection matches its entries" bash -c "
  set -- $R/vpc/security-groups/*
  [ \$# -eq \$(ls $R/vpc/security-groups | wc -l) ] && [ -e \"\$1\" ]"
check "README recipe: grep -l ... */rules.json finds the open SG" bash -c "
  cd $R/vpc/security-groups && grep -l '\"cidr\": \"0.0.0.0/0\"' */rules.json | grep -q rules.json"
check "readdir inodes are non-zero" python -c "
import os
e = list(os.scandir('$R/vpc/security-groups'))
assert e and all(x.inode() != 0 for x in e)"
check "referenced-by lists users of an SG" bash -c "ls $R/vpc/security-groups/*/referenced-by | head -1 >/dev/null"
umount $M 2>/dev/null || fusermount3 -u $M 2>/dev/null || fusermount -u $M
sleep 1
check "unmounted cleanly" bash -c "! mountpoint -q $M"
wait $MP 2>/dev/null
echo "=== RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
