# Security model

awsmount turns AWS account metadata into files, and files are easy to read:
for you, for your tools, for your AI coding agents, and for any other process
running as your user. This document explains what awsmount does to keep the
account safe and what it deliberately does not protect against.

## 1. Read-only, enforced in three places

awsmount never mutates AWS. This is enforced at three layers.

1. **API allow-list.** Every boto3 client created by awsmount registers a
   `before-call` hook that runs before any HTTP request is sent. An
   operation is allowed only when all of these hold:
   - it is declared in the `ops` of a registered collection for the
     **same client**, or it is one of the bootstrap operations
     (`GetCallerIdentity`, `ListAccountAliases`, `DescribeRegions`);
   - its name starts with `Describe`, `List`, `Get`, `Search` or `Lookup`;
   - it is not in the deny-list below.

   Any other call raises `ForbiddenOperation` (EPERM) without reaching the
   network. The allow-list is client-scoped: `GetPolicy` declared for Lambda
   does not authorise `iam:GetPolicy`.

2. **Filesystem.** Every write syscall (`write`, `create`, `mkdir`,
   `unlink`, `rename`, `chmod`, `truncate`, `setxattr`, ...) and every
   `open` with write intent returns `EROFS`. FUSE mounts are also mounted
   with `ro`, and macOS WebDAV mounts with `-o rdonly`.

3. **WebDAV server.** Only `OPTIONS`, `GET`, `HEAD` and `PROPFIND` are
   accepted. `PUT`, `DELETE`, `MKCOL`, `COPY`, `MOVE`, `PROPPATCH`, `LOCK`,
   `UNLOCK` and `POST` get `403`. `PROPFIND` with `Depth: infinity` is
   refused as well.

### Data-plane operations are never called

The following operations are in a hard deny-list. They cannot be called,
**even with `--reveal`**:

`GetSecretValue`, `BatchGetSecretValue`, `GetParameter`, `GetParameters`,
`GetParametersByPath`, `GetParameterHistory`, `GetObject`,
`GetObjectTorrent`, `SelectObjectContent`, `GetObjectAttributes`, `Decrypt`,
`GenerateDataKey`, `GenerateDataKeyWithoutPlaintext`, `GetPasswordData`,
`GetAuthorizationToken`, `GetSessionToken`, `GetFederationToken`,
`GetFunction`, `GetLayerVersion`, `ExportCertificate`, `GetLogEvents`,
`FilterLogEvents`, `GetQueryResults`, `GetConsoleOutput`,
`GetConsoleScreenshot`, `GetLaunchTemplateData`, `GetApiKey`, `GetApiKeys`,
`GetExport`, `GetSdk`.

Some data is not read at all because it holds secrets or user data: EC2
launch template versions (user data), ECR images, Step Functions
executions and their history, and EventBridge events.

In practice this means awsmount never reads S3 object bodies, secret values,
SSM parameter values, log events, Lambda code or console output.

The one exception is the separate command `awsmount secrets`, which reads
Secrets Manager and Parameter Store **values** on purpose. It has its own
session: its client allow-list holds only `ListSecrets`, `GetSecretValue`,
`DescribeParameters` and `GetParameter` (plus the three bootstrap calls),
the two value reads are the only operations that may bypass the deny-list
and only in that session, and it contains no other service. A normal
session cannot call them whatever its flags are. See
[secrets.md](secrets.md) for its model and its limits.

## 2. Masking is on by default

Values that commonly hold secrets are replaced by `<hidden>` when a
file is rendered. The cache keeps the raw API data; masking happens at
render time, so `--reveal` does not need to refetch anything.

Rule sets applied by default:

| Rule | What is hidden |
|---|---|
| `lambda` | Lambda `Environment.Variables` values (keys are kept) |
| `user-data` | the whole EC2 `user-data` file; no API call is made |
| `template` | the whole CloudFormation `template` file; no API call is made |
| `ecs-taskdef` | ECS container `environment[].value` (secret ARNs are kept) |
| `eks-addon` | EKS add-on `configurationValues` (free-form configuration, hidden as a whole) |
| `elbv2-listener`, `elbv2-rule` | OIDC `ClientSecret` of authenticate actions (defensive) |
| `sfn` | Step Functions `definition` string in `describe.json` (`definition.json` shows it parsed, with secret-looking keys hidden) |
| `eventbridge-targets` | EventBridge target `Input` and HTTP header and query values |
| `rds` | `MasterUserPassword` (defensive) |
| `iam` | `SecretAccessKey` in `access-keys.json` (defensive) |
| `cfn-params` | CloudFormation parameter and output values whose key looks secret (`Password`, `Pass`, `Pwd`, `Psk`, `Token`, `Secret`, `...Key`, `Webhook`, ...) |
| `apigw-stages` | API Gateway stage variables |
| `sns` | HTTP/HTTPS subscription endpoints (URLs may embed credentials) |
| `cloudfront` | origin `CustomHeaders` values (shared secrets) |
| `elbv2-listeners` | OIDC `ClientSecret` (defensive) |
| `secrets` | `SecretString` / `SecretBinary` (defensive) |
| `ssm` | `Value` (defensive) |
| EKS | connector `activationCode` |

A generic heuristic then runs over **every** JSON file: any key that looks
like `password`, `passwd`, `secret`, `token`, `private_key`, `credential` or
`api_key`, holding a non-empty string that is not an ARN, is hidden. Keys
ending in `Arn`, `Id`, `Name`, `Type`, `Status`, `Enabled`, `Date`, `Time`,
`Version`, `Policy`, ... are left alone. Lists under `Environment` /
`environmentVariables` keys with `Name`/`Value` pairs have their values
hidden too.

### What is not hidden

- **Tag values are not hidden.** Tags are metadata by design; do not put
  secrets in tags.
- Resource names, ARNs, IP addresses, policies and other configuration are
  shown as returned by AWS. Treat a mounted account as sensitive data.

## 3. `--reveal` and its risk

`--reveal` disables masking. awsmount prints a warning on stderr when it is
used. With `--reveal`:

- `user-data` is fetched (one `DescribeInstanceAttribute` call) and decoded;
- CloudFormation templates are fetched (`GetTemplate`);
- environment variables, stage variables and all other hidden values are
  shown.

**Any local process running as your user can read mounted files.** That
includes AI coding agents, editor plugins, indexers and backup tools. Only use
`--reveal` when you understand who and what can read the mount, and prefer the
one-shot commands (`awsmount cat --reveal ...`) over a long-lived mount.
Data-plane operations stay denied even with `--reveal`.

`awsmount export` applies the same rules: an export made without `--reveal`
contains hidden content, and the `.awsmount-export` marker records the
`reveal` flag.

## 4. Other local users

awsmount aims to make the account readable by **you only**.

- **FUSE** is mounted without `allow_other`, so the kernel refuses access to
  every other user (root excepted).
- **WebDAV** is bound to `127.0.0.1` only; the address is hard-coded and not
  configurable. A `Host` header check (`127.0.0.1:PORT` or `localhost:PORT`,
  else `421`) defends against DNS rebinding from a browser.
- Every WebDAV session generates a fresh URL token and a fresh password with
  `secrets.token_urlsafe(32)`. Neither is ever written to disk.

### The URL token is not a secret

The token in the URL path is **not a secret**. It ends up in the mount
command line and in the system mount table (`mount`, `/proc/mounts`), which
other local users can read. It only makes URLs unguessable for casual
requests; it never grants access on its own.

Access is protected by HTTP authentication, which is always mandatory. The
password is the secret:

- it is never placed in argv, in the URL or in the environment;
- on macOS it is typed into `mount_webdav -i` through a pseudo-terminal;
- `awsmount serve` prints it once on your terminal so that you can paste it
  into Finder or davfs2;
- it is excluded from the `repr` of the credentials object, so it does not
  leak into logs or tracebacks.

A request that knows the token but has no valid credentials gets `401`.

The mount is owner-only whatever its parent directory looks like, so a
mountpoint inside your home directory needs no warning. When mounting,
awsmount warns if the mountpoint's parent directory can be modified by other
users (they could replace the mountpoint; a sticky directory such as `/tmp`
is exempt), or if it can be traversed by other users and is outside your home
directory. Prefer a mountpoint inside your home directory.

## 5. Credentials

awsmount uses the standard boto3 credential chain (`--profile`, environment
variables, SSO, instance roles, ...). It never stores credentials and never
calls `GetSessionToken` or `GetFederationToken`. Use a read-only IAM policy
(for example `ReadOnlyAccess` or `SecurityAudit` plus the specific `Get*`
calls you need) as an additional safety net: awsmount's own guard is not a
substitute for least-privilege credentials.

## 6. API budget

A recursive `grep -r` over a large account could otherwise issue thousands of
calls. awsmount offers a rolling budget (`--max-api-calls N`, off by default; window
`--budget-window`, 600 s). AWS itself only throttles per API, and boto3 backs
off, so a heavy walk is slow rather than rejected. Once it is exhausted, uncached reads fail with EIO and a clear message
is written to stderr and `_meta/errors.log`; cached data keeps being served.

## 7. Error handling

- AccessDenied on a collection gives an empty directory plus one line in
  `/<account>/_meta/errors.log`. The mount keeps serving everything else.
- AccessDenied on a lazy detail file gives `EACCES` ("Permission denied")
  plus a log line, on FUSE and on the macOS mount. The macOS mount makes
  its server answer 401 for this case, because `mount_webdav` shows 401 as
  `EACCES` but 403 as `EPERM` ("Operation not permitted"). `EPERM` is kept
  for a read-only guard refusal (a bug). `awsmount serve` answers 403 in
  both cases, so that Finder and davfs2 do not ask for credentials again.
- Other upstream failures give `EIO` plus a log line.
- "Not configured" answers (for example no bucket policy, or
  Organizations not enabled) give an empty directory or `null`, without a
  log entry.
