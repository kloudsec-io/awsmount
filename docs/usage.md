# Using awsmount

## Commands

| Command | Purpose |
|---|---|
| `awsmount shell [-c CMD]` | Interactive shell. With `-c`, run one command line and exit with its status. |
| `awsmount ls [-l] [-a] [-R] [PATH...]` | List directories (default `/`). |
| `awsmount cat PATH...` | Print files. |
| `awsmount tree [-L N] [PATH]` | Draw a tree (default `/`); links are not followed. |
| `awsmount find [PATH...] [-name GLOB] [-type f\|d\|l] [-maxdepth N]` | Find entries (default `/`). |
| `awsmount grep [-r] [-i] [-n] [-l] PATTERN [PATH...]` | Search contents (Python regex). With `-r` and no PATH, searches `/`. |
| `awsmount get PATH EXPR` | Extract a JSON value. |
| `awsmount export PATH DEST [--links file\|keep\|skip] [--jobs N] [--clean] [--force]` | Write a subtree into a real directory. Symlinks become text files by default (`file`), which keeps `diff -r` and `grep -R` working. |
| `awsmount mount MOUNTPOINT [--method auto\|fuse\|webdav] [--webdav-links file\|follow] [--port N]` | Mount read-only (blocks). |
| `awsmount umount MOUNTPOINT` | Unmount. |
| `awsmount serve [--port N] [--webdav-links file\|follow]` | Serve WebDAV on 127.0.0.1 and print the URL and credentials (blocks). |
| `awsmount secrets mount MOUNTPOINT [--method auto\|fuse\|webdav] [--port N]`, `secrets shell [-c CMD]`, `secrets umount MOUNTPOINT` | Mount (or browse) secret **values**; the only command that reads them. One profile and one region. See [secrets.md](secrets.md). |
| `awsmount doctor [--json] [--check-credentials] [-p NAME]... [--endpoint-url URL]` | Report which mount methods work on this machine. Exits 1 when a row says `FAIL` (for example a profile that cannot be used), otherwise 0. |
| `awsmount services [--short] [--json] [--markdown]` | List supported services and resource types, with the files and links inside each resource directory (`--short`: one line per service). |
| `awsmount version`, `awsmount --version` | Print the version. |

The grep long forms `--recursive`, `--ignore-case`, `--line-number` and
`--files-with-matches` are accepted too. `doctor` makes no AWS call unless
you pass `--check-credentials`, which makes one `sts get_caller_identity`
per profile.

## Common options

These options are accepted by every AWS-touching command (`shell`, `ls`,
`cat`, `tree`, `find`, `grep`, `get`, `export`, `mount`, `serve`). They can be
given before the subcommand (`awsmount -p prod ls /`) or after it
(`awsmount ls / -p prod`); values given after the subcommand win.

| Option | Default | Meaning |
|---|---|---|
| `--profile`, `-p NAME` | default chain | AWS profile; repeat for several accounts (one top-level directory each). |
| `--region`, `-r REGION` | profile region, else `us-east-1` | Region to mount; repeatable, comma lists accepted, `all` = every enabled region. `grep` accepts only `--region`, because `-r` means recursive there. |
| `--endpoint-url URL` | none | AWS-compatible endpoint (moto, localemu). |
| `--services LIST` | all | Comma list of service directories, e.g. `vpc,ec2,iam`. Unknown names are a usage error. |
| `--reveal` | off | Disable secret masking (prints a warning). |
| `--ttl SECONDS` | 60 | Cache TTL. |
| `--max-api-calls N` | 0 | Stop after N API calls per window; 0 = unlimited. |
| `--budget-window SECONDS` | 600 | Rolling budget window; 0 = whole session. |
| `--concurrency N` | 4 | In-flight calls per AWS service. |
| `--max-attempts N` | 10 | botocore retry attempts (adaptive mode). |
| `--s3-objects N` | 0 | S3 object keys listed per bucket (0 = off). |
| `--lazy-size render\|zero` | zero | FUSE only: size reported for lazy files that are not rendered yet. |
| `--verbose`, `-v` | off | Progress counter and error lines on stderr. |
| `--no-color` | off | Disable colors (`NO_COLOR` is honoured too). |

Credentials come from the standard boto3 chain (environment variables,
`~/.aws/config` and `~/.aws/credentials`, SSO, instance or container roles).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | OK |
| 1 | Error (for `grep`: no match) |
| 2 | Usage error |
| 3 | Partial: some paths failed (`grep`, `export`), or a profile could not be used (see "Paths and names") |
| 4 | API budget exhausted |
| 130 | Interrupted |

## The interactive shell

```
awsmount -p prod -r eu-west-1 shell
```

- The prompt is `awsmount:<cwd>$ `. History is kept in
  `$XDG_STATE_HOME/awsmount/history` (default
  `~/.local/state/awsmount/history`, mode 0600).
- Tab completes command names (first word) and paths. A directory that is
  not cached yet is fetched in the background. Completion waits at most 2
  seconds; if it times out, the next Tab is instant.
- Directories are bold blue and symlinks cyan. Colors are disabled by
  `--no-color`, by `NO_COLOR`, or when output is not a terminal.

| Command | Synopsis | Notes |
|---|---|---|
| ls | `ls [-l] [-a] [-R] [PATH...]` | `-l` does not follow a final symlink and shows `name -> target`; `-R` does not follow links |
| cd | `cd [PATH\|-]` | logical cwd (`..` is lexical); no argument goes to `/`; `-` goes to the previous dir |
| pwd | `pwd` | |
| cat | `cat PATH...` | |
| head | `head [-n N] PATH...` | 10 lines by default |
| stat | `stat PATH...` | type, size, blocks, mode, links, uid/gid, inode, mtime, link target |
| get | `get PATH EXPR` | `a.b[0].c`, `["key.with.dots"]`, `[-1]`, `[*]`, `*`, optional leading `$`; strings print raw, other values as JSON |
| tree | `tree [-L N] [PATH]` | prints a dir/file count summary |
| find | `find [PATH...] [-name GLOB] [-type f\|d\|l] [-maxdepth N]` | `-name` matches the unescaped name |
| grep | `grep [-r] [-i] [-n] [-l] PATTERN PATH...` | Python `re`; binary content is reported as `Binary file X matches`; unreadable files are reported and skipped (status 3) |
| whoami | `whoami` | `identity.json` of the account under cwd, or of every account |
| refresh | `refresh [PATH]` | drops cached data for the account, region or service of PATH (everything without PATH) and resets the budget |
| cache | `cache [--clear] [--reset-budget]` | cache counters, budget use, error count |
| help | `help [CMD]` | |
| exit | `exit [STATUS]`, `quit`, Ctrl-D | |

**Host commands and pipes.**

- `CMD ... | !PIPELINE` captures a built-in's output and feeds it to
  `/bin/sh -c PIPELINE`:

  ```
  cat ec2/instances/i-0123456789abcdef0/describe.json | !jq .State
  ```

- A line starting with `!` runs a host command, with `AWSMOUNT_CWD` set to
  the shell's cwd. Host commands cannot see the virtual tree.
- Pipes between two built-ins are not supported.

**Scripting.**

```
awsmount -p prod shell -c "find / -name describe.json -maxdepth 6"
printf 'cd /acme-prod/global/iam/roles\nls\n' | awsmount -p prod shell
```

When stdin is not a terminal, the shell reads one command per line.

## Paths and names

```
/<account>/<region>/<service>/<collection>/<resource>/...
/<account>/global/<service>/<collection>/<resource>/...
/<account>/_meta/
```

- **Account.** The account directory is the first account alias, otherwise
  the account id. If identity resolution fails (a mistyped profile, an
  expired token, no credentials), the directory is `profile-<name>` and
  contains only `_meta/`. awsmount also prints
  `awsmount: profile NAME: <cause>; nothing is shown for it` on stderr, and
  the command exits 3 instead of 0 or 1, so a profile that could not be
  used is never mistaken for an empty account or for "no match". When two
  profiles resolve to
  the same account, the first one wins and a warning goes to `errors.log`.
- **Escaping.** Names are escaped so that each one is a single safe path
  component. `%` becomes `%25`, `/` becomes `%2F`, control characters
  become `%XX`, a leading `.` becomes `%2E`, and the empty name becomes
  `%00`. Escaped names longer than 255 bytes are truncated and get a hash
  suffix.
- **Collisions.** Display names that collide case-insensitively (two ACM
  certificates for one domain, for example) get `~<id>` appended.
  `find -name` matches the unescaped name:

  ```
  awsmount find /acme-prod/eu-west-1/logs/log-groups -maxdepth 1 -name '/aws/lambda/*'
  ```

`_meta/` holds:

| File | Content |
|---|---|
| `account.json` | AccountId, Aliases, Profile, Partition, Regions, GlobalRegion (and Error if resolution failed) |
| `identity.json` | `sts get_caller_identity` response |
| `errors.log` | TSV: time, account, region, service, op, kind, code, message; identical errors within 60 s collapse into one line ending `(xN)` |
| `stats.json` | API calls used, budget, window, cache counters |

## What is in each resource directory

Every resource directory has `describe.json`. It also has `arn`, `name`,
`tags.json` and `tags/<Key>` (one file per tag, holding the value) when they
apply. `*` marks a lazy file, which makes its own API call when read or
stat'ed (cached for the TTL). Unmarked files are derived from the listing
and cost nothing. `NAME/` under links is a directory of symlinks.

| Path | Directory name | Extra files | `links/` |
|---|---|---|---|
| ec2/instances | instance id | state, instance-type, private-ip, user-data (hidden; * with `--reveal`) | subnet, vpc, image, key-pair, security-groups/, volumes/, network-interfaces/ |
| ec2/volumes | volume id | state, size-gib | instances/, snapshot, kms-key |
| ec2/snapshots | snapshot id (owned) | state | volume, kms-key |
| ec2/key-pairs | key name | fingerprint, public-key | |
| ec2/elastic-ips | allocation id | public-ip | instance, network-interface |
| ec2/network-interfaces | ENI id | status, private-ip, interface-type | subnet, vpc, instance, security-groups/ |
| ec2/amis | image id (owned) | state | snapshots/ |
| vpc/vpcs | VPC id | cidr | dhcp-options |
| vpc/subnets | subnet id | cidr, availability-zone | vpc |
| vpc/security-groups | group id | rules.json, group-name, vpc-id; `referenced-by/` | vpc, references/ |
| vpc/route-tables | route table id | routes.json | vpc, subnets/, internet-gateways/, nat-gateways/, peering-connections/ |
| vpc/internet-gateways | IGW id | | vpcs/ |
| vpc/nat-gateways | NAT gateway id | state | vpc, subnet, network-interfaces/, elastic-ips/ |
| vpc/network-acls | ACL id | entries.json | vpc, subnets/ |
| vpc/endpoints | endpoint id | policy.json | vpc, subnets/, route-tables/, security-groups/, network-interfaces/ |
| vpc/peering-connections | peering id | status | requester-vpc, accepter-vpc (only if that account/region is mounted) |
| vpc/dhcp-options | options id | | |
| vpc/transit-gateways | TGW id | state | |
| vpc/flow-logs | flow log id | | resource (VPC, subnet or ENI), log-group |
| elbv2/load-balancers | name | dns-name, type, scheme, listeners.json\*, attributes.json\* | vpc, subnets/, security-groups/, target-groups/ |
| elbv2/load-balancers/\<lb\>/listeners | `PROTOCOL-port` (for example `HTTP-80`) | protocol, port | load-balancer, target-groups/, certificates/; nested `rules/` |
| elbv2/load-balancers/\<lb\>/listeners/\<l\>/rules | priority (`default` for the default rule) | priority | target-groups/ |
| elbv2/target-groups | name | protocol, port, target-type, health.json\*, attributes.json\* | vpc, load-balancers/ |
| lambda/functions | function name | runtime, policy.json\*, aliases.json\*, event-source-mappings.json\*, url-config.json\* | role, vpc, subnets/, security-groups/, kms-key, log-group |
| rds/instances | DB instance id | engine, status, endpoint | cluster, vpc, subnets/, security-groups/, kms-key |
| rds/clusters | DB cluster id | engine, status, endpoint | instances/, security-groups/, kms-key |
| rds/clusters/\<c\>/members | DB instance id | role (`writer` or `reader`), promotion-tier | instance, cluster |
| ecs/clusters | cluster name | status; nested `services/` | |
| ecs/clusters/\<c\>/services | service name | status, desired-count | cluster, task-definition, target-groups/, subnets/, security-groups/, role |
| ecs/task-definitions | `family:revision` | describe.json\* | role, execution-role |
| eks/clusters | cluster name | describe.json\*, nodegroups.json\*, addons.json\*; nested `nodegroups/`, `addons/` | role, vpc, subnets/, security-groups/ |
| eks/clusters/\<c\>/nodegroups | node group name | describe.json\* (no `arn` file: the ARN is in describe.json) | cluster, role, subnets/ |
| eks/clusters/\<c\>/addons | add-on name | describe.json\* (no `arn` file: the ARN is in describe.json) | cluster, role |
| ec2/launch-templates | template name | default-version, latest-version | |
| autoscaling/groups | group name | min-size, max-size, desired-capacity | launch-template, subnets/, target-groups/, instances/ |
| cloudwatch/alarms | alarm name | state, metric, tags.json\* | sns-topics/, instances/ |
| ecr/repositories | repository name (`/` escaped) | uri, policy.json\*, lifecycle-policy.json\*, tags.json\* | kms-key |
| stepfunctions/state-machines | state machine name | describe.json\*, definition.json\*, tags.json\* | role, lambda-functions/, log-groups/ |
| redshift/clusters | cluster id | status, node-type, endpoint | vpc, security-groups/, roles/, kms-key |
| eventbridge/event-buses | bus name | tags.json\*; nested `rules/` | |
| eventbridge/event-buses/\<b\>/rules | rule name | state, schedule, targets.json\*, tags.json\* | role |
| s3/buckets | bucket name (in its region) | region, policy.json\*, encryption.json\*, public-access-block.json\*, versioning.json\*, objects-listing.json\*, objects/ | |
| dynamodb/tables | table name | describe.json\*, ttl.json\*, continuous-backups.json\* | kms-key |
| sqs/queues | queue name | url, describe.json\*, policy.json\* | dead-letter-queue, kms-key |
| sns/topics | topic name | describe.json\*, policy.json\*, subscriptions.json\* | kms-key |
| kms/keys | key id | describe.json\*, policy.json\*, rotation.json\* | aliases/ |
| kms/aliases | alias without `alias/` | | target-key |
| logs/log-groups | log group name (escaped) | retention, stored-bytes, metric-filters.json\*, subscription-filters.json\* | kms-key |
| cloudformation/stacks | stack name | status, outputs.json, parameters.json, template (hidden; * with `--reveal`); nested `resources/` | role |
| cloudformation/stacks/\<s\>/resources | logical id | type, physical-id, status | target |
| secretsmanager/secrets | secret name (escaped) | rotation-enabled, policy.json\* | kms-key, rotation-lambda |
| ssm/parameters | parameter name (escaped) | type, version | kms-key (SecureString) |
| acm/certificates | domain name | status, details.json\* | |
| apigateway/rest-apis | API name | endpoint-type, resources.json\*, stages.json\*, deployments.json\*, authorizers.json\* | |
| global/route53/hosted-zones | zone name without trailing dot | private, record-count, records.json\* | vpcs/ |
| global/iam/users | user name | attached-policies.json\*, inline-policies/\<name\>.json\*, groups.json\*, access-keys.json\*, mfa-devices.json\* | groups/, policies/ |
| global/iam/roles | role name | trust-policy.json, attached-policies.json\*, inline-policies/\<name\>.json\*, instance-profiles.json\*, last-used.json\* | policies/, trusts/, trusts-users/ |
| global/iam/groups | group name | attached-policies.json\*, inline-policies/\<name\>.json\* | members/, policies/ |
| global/iam/policies | policy name (customer-managed) | document.json\*, versions.json\*, entities.json\* | attached-to-users/, attached-to-groups/, attached-to-roles/ |
| global/cloudfront/distributions | distribution id | domain-name, status, aliases, config.json\* | certificate, origins-s3/ |
| global/organizations/accounts | account id | account-name, status | |
| global/organizations/roots | root id | | |
| global/organizations/policies | SCP id | document.json\* | |

Tags of most services are lazy (one call when `tags.json` or `tags/` is
read). EC2, VPC, RDS, ECS clusters and services, CloudFormation stacks,
Secrets Manager and API Gateway carry their tags in the listing. When a lazy
file hits a "not configured" condition (no bucket policy, no encryption
configuration, no Lambda resource policy, ...), its content is `null`.

## Recipes

**Which instances run in a given subnet?**

```
cd ~/aws/acme-prod/eu-west-1/ec2/instances
for i in */; do
  [ "$(readlink "$i/links/subnet")" = "../../../../vpc/subnets/subnet-0abc" ] \
    && echo "${i%/}"
done
```

On a macOS WebDAV mount use `cat` instead of `readlink`.

**All IAM roles that trust another account.**

```
cd ~/aws/acme-prod/global/iam/roles
grep -l '"AWS"' */trust-policy.json
jq -r '.Statement[].Principal.AWS? // empty' */trust-policy.json | sort -u
```

**Lambda runtimes in use.**

```
cat ~/aws/acme-prod/eu-west-1/lambda/functions/*/runtime | sort | uniq -c
```

**Buckets without a public access block.**

```
cd ~/aws/acme-prod/eu-west-1/s3/buckets
for b in */; do
  [ "$(cat "$b/public-access-block.json")" = "null" ] && echo "${b%/}"
done
```

**jq over describe.json.**

```
jq -r '.InstanceType' ~/aws/acme-prod/eu-west-1/ec2/instances/*/describe.json | sort | uniq -c
awsmount -p prod get /acme-prod/eu-west-1/ec2/instances/i-0123456789abcdef0/describe.json 'SecurityGroups[*].GroupId'
```

**Snapshots for git and diff.** See the README recipes. `export` writes
files 0644 and directories 0755, and writes symlinks as text files (`--links file`,
the default, safe for `diff -r`), omits them (`skip`, which also leaves out the `links/` and
`referenced-by/` directories), or recreates real symlinks (`keep`; they form
cycles).
The destination must be empty, unless `--force` (overwrite in place, never
delete) or `--clean` (requires the `.awsmount-export` marker, then deletes
the contents first). Per-file errors are printed and give exit code 3.

**Against moto or localemu.**

```
moto_server -p 5000 &
awsmount --endpoint-url http://127.0.0.1:5000 -r us-east-1 tree -L 3 /
```

## Budget, cache and progress

- **Calls.** Each API page counts as one call; retries are not counted.
  Listing the root, account, region and service directories costs nothing
  beyond the per-profile identity calls (`sts get_caller_identity`,
  `iam list_account_aliases`, and `ec2 describe_regions` for
  `--region all`).
- **Budget exhaustion.** The first exhaustion in a window writes one line
  to stderr and one line to `errors.log`. Reads that need new calls then
  fail with EIO. In the shell, `refresh` or `cache --reset-budget` resets
  the budget.
- **Progress.** With `--verbose`, stderr shows
  `[awsmount] api calls 123 ec2:DescribeInstances`. On a terminal the
  line is rewritten in place; otherwise one line is printed every 100
  calls. Recorded errors are echoed as `[awsmount] error <TSV line>`.
