# awsmount architecture

This document explains how awsmount is built, for people who want to change
it. It describes the code as it is today. For using awsmount see
[usage.md](usage.md), for adding a service see [providers.md](providers.md),
for the security model see [security.md](security.md), and for secret values
see [secrets.md](secrets.md). The source cites sections of this file by
name, as `ARCHITECTURE: <section name>`.

## Overview

awsmount turns AWS API responses into a filesystem tree and serves that tree
through several adapters. The code has four layers:

| Layer | Package | Job |
|---|---|---|
| Filesystem core | `awsmount.vfs` | Nodes, names, stat, rendering, path resolution. It imports nothing from the other layers and knows nothing about AWS. |
| Session | `awsmount.session` | Configuration, AWS clients and the read-only guard, cache, budget, masking, error log. |
| Providers and tree | `awsmount.providers`, `awsmount.tree` | Providers describe services as data. The tree turns that data into directories. |
| Adapters | `awsmount.adapters` | Shell, WebDAV, FUSE and export. They all read the same tree. |

`awsmount.secrets` is a separate session and tree for secret values (see
"awsmount secrets"). `cli.py`, `config.py`, `doctor.py`, `platform.py` and
`errors.py` sit beside the layers.

A command runs like this: `cli.py` builds a `Config`, `Context.from_config`
builds the session, `tree.build_vfs(ctx)` returns a `VFS`, and an adapter
serves it. Nothing calls AWS until something reads a directory or a file.

```
/<account>/<region>/<service>/<collection>/<resource>/...
/<account>/global/<service>/<collection>/<resource>/...
/<account>/_meta/   account.json  identity.json  errors.log  stats.json
```

`<account>` is the first account alias, else the account id. Listing the root,
an account, a region or a service directory costs no API call beyond the
identity calls of each profile.

## Conventions

- Python 3.11 or newer; every module starts with
  `from __future__ import annotations`.
- flake8 with 79 columns (`.flake8`); every public function and class has a
  docstring.
- No global state: everything a session needs hangs off one `Context`, built
  from one `Config`.

## Names and escaping

Every AWS name becomes one safe path component (`vfs/path.py`). `escape_name`
writes `%` as `%25`, `/` as `%2F`, control characters (below 0x20, and 0x7F)
as `%XX`, a leading `.` as `%2E` (so `.`, `..`, `._x` and `.DS_Store` are never
names), and the empty string as `%00`. A name over 255 bytes is cut to its
first 200 bytes plus `~` and the blake2b hex digest of the raw name.
`unescape_name` inverts every rule except the cut.

`assign_names` gives each item of a listing a unique, deterministic name.
Names that collide case-insensitively (the tree must be safe on macOS) all
become `display~key`; any duplicate left gets `~2`, `~3` and so on in sorted
key order. The result does not depend on the order of the API response.

## File metadata

`vfs/stat.py` builds every `Stat`. Directories are `0555`, files `0444`,
symlinks `0777`; `nlink` is 1; uid and gid are the process's. Times are when
the backing data was fetched (the session start for static directories). The
inode is a stable 63-bit blake2b hash of the path. A file's size is the length
of its rendered bytes, a symlink's the length of its target.

A lazy file (one that needs its own API call) is rendered on first `stat` or
read, so size, ETag and content agree within one TTL. FUSE can opt out with
`--lazy-size zero` (see "FUSE").

## Nodes and rendering

`vfs/node.py` has three node types. A `DirNode` takes a loader; its children
are built under a lock and kept for the TTL (a `static` directory never
expires, and a loader may not return two children with one name). A `FileNode`
takes a render function; its bytes are produced once per TTL under a lock, so
concurrent readers share one render (a `volatile` file such as `errors.log`
renders on every read). A `SymlinkNode` holds a relative target.

`vfs/render.py` decides the bytes. Text gets a final newline. JSON is
canonical: sorted keys, indent 2, `ensure_ascii=False`, ISO 8601 datetimes,
bytes as base64, sets sorted, `ResponseMetadata` removed. A few lists that AWS
returns in a changing order (tags, security group lists, route table
associations, IP permissions) are sorted so that two exports of one account
are identical; other lists keep the API order.

## Path resolution

`vfs/resolver.py` resolves paths with POSIX physical semantics: `.` is
skipped, `..` goes to the parent, a symlink is followed when it is not the
last component or when `follow=True`, and more than 40 expansions raise
`SymlinkLoop` (ELOOP). `VFS.walk` is pre-order and sorted and does not follow
links unless asked, in which case it skips real paths already seen.
`vfs/walk.py` builds `find`, `grep` and `tree` on it; none follows links, like
the GNU tools.

## Errors

`errors.py` maps every failure to an errno, so adapters never guess:
`NotFound` is ENOENT, `NotADirectory` ENOTDIR, `IsADirectory` EISDIR,
`SymlinkLoop` ELOOP, `NotALink` EINVAL, `ReadOnly` EROFS, `PermissionDenied`
(AWS refused a lazy file) EACCES, `ForbiddenOperation` (the guard refused a
call, which is a bug) EPERM, and `UpstreamError`, `BudgetExceeded` and the base
`AwsMountError` EIO.

## Configuration

`Config` (`config.py`) is a frozen dataclass: profiles, regions,
`endpoint_url`, `reveal`, `ttl` (60 s), `negative_ttl` (10 s),
`max_api_calls` (0, unlimited), `budget_window` (600 s), `concurrency` (4 per
service), `global_concurrency` (16), `max_attempts` (10), timeouts,
`s3_objects` (0), `services`, `verbose`, `color` and `lazy_size` (`zero`).
`validate()` raises `ValueError` listing every bad setting; the CLI turns it
into a usage error. A region is `all` or a name such as `us-east-1`; `global`
and `_meta` are reserved because they are directory names.

## Context and API calls

`Context` (`session/context.py`) is the only state of a session: config,
cache, budget, limiter, client factory, masking policy, error log, progress
counter, account directory, provider registry and link resolvers. A `Scope`
is one account plus one region (or the global scope).

`ctx.call(scope, client, op, **params)` and `ctx.paginate(...)` are how
providers reach AWS. The cache key is `(profile, region, client, op,
canonical params)`; `TTLCache.get_or_load` runs the loader at most once per
key and TTL; the loader takes a concurrency slot, calls the guarded client (or
iterates its paginator) and strips `ResponseMetadata`. Exceptions become
`PermissionDenied` (access denied) or `UpstreamError`, with the AWS code. Each
page is one budget charge; retries are not charged. `call_uncached` is the
same without the cache and is used only by `awsmount secrets`.

## Accounts and regions

`AccountDirectory` (`session/accounts.py`) resolves each profile once:
`sts:GetCallerIdentity` gives the account and partition, `iam:ListAccountAliases`
the alias (access denied means none). Regions are the explicit `--region`
values, every enabled region for `all` (`ec2:DescribeRegions`), or the
profile's region, or `us-east-1`. Global services use `us-east-1`,
`cn-north-1` or `us-gov-west-1` by partition.

If a profile cannot be resolved (mistyped name, expired token, no
credentials), its directory is `profile-<name>` and holds only `_meta/`. The
failure is recorded, printed once on stderr (`awsmount: profile NAME: <cause>;
nothing is shown for it`) and kept in `failures()`; one-shot commands and
`export` then exit 3, so a failed profile is never mistaken for an empty
account. It is retried after `negative_ttl`. Two profiles for one account: the
first wins and `errors.log` gets a line.

## Read-only guard

awsmount cannot change anything in AWS. `ClientFactory` (`session/clients.py`)
creates one boto3 client per `(profile, region, service)` with a `before-call`
hook that runs before any HTTP request. A call passes only if all of these
hold: the name starts with `Describe`, `List`, `Get`, `Search` or `Lookup`; it
is not in `DENIED_OPS`; and either the pair `(client, Operation)` is in the
allow-list, which is the `ops` that providers declare for that client, or the
operation is one of three harmless bootstrap calls (`GetCallerIdentity`,
`ListAccountAliases`, `DescribeRegions`), which pass on any client. Otherwise
the hook raises `ForbiddenOperation` and nothing is sent. Because the list is
per client, an operation that is safe for one service does not pass for another
service that has one of the same name.

`DENIED_OPS` holds the operations that read data and not configuration: secret
and parameter values, S3 objects, `Decrypt` and the data-key calls, password
data, Lambda code, log events, query results, console output, certificate
export and credential-issuing calls. They stay denied even with `--reveal`.
After the checks the hook charges the budget and ticks the progress counter.

The guard is one of three places. The others: every write call on a mount
returns EROFS (see "FUSE"), and the WebDAV server answers 403 to every method
that is not a read (see "WebDAV"). Clients use adaptive retries, timeouts and
the `User-Agent` suffix `awsmount/<version>`.

## Cache

`TTLCache` (`session/cache.py`) is an LRU of at most 50,000 entries. It is
single-flight: while a key loads, other callers wait for that load and get the
same value or the same exception. `PermissionDenied` and `UpstreamError` are
cached for `negative_ttl`; `BudgetExceeded` never is. `ttl=0` stores nothing,
but identical concurrent loads still share one call. The cache keeps raw API
data; masking happens later, at render time.

## Budget and limits

`ApiBudget` (`session/budget.py`) counts calls in a rolling window (window 0 is
the whole session). With the default limit of 0 it never refuses. With
`--max-api-calls N`, call N+1 raises `BudgetExceeded` (EIO); the first refusal
in a window prints one stderr line and writes one `errors.log` line, and cached
data is still served. `Limiter` (`session/limiter.py`) holds one bounded
semaphore per boto3 service plus a global one; waiting over 120 s raises
`UpstreamError`. Throttling itself is left to botocore's adaptive retries.

## Masking

`RedactionPolicy` (`session/redact.py`) replaces values that may be secrets with
`<hidden>` when a file is rendered; keys are kept. There are three mechanisms.
Rule sets in `RULES` are path patterns per service (Lambda environment values,
ECS container environment, CloudFormation values whose key looks secret, API
Gateway stage variables, and others; `docs/security.md` lists them), and a
provider names its set in `redact`. Whole-file rules (`user-data`,
`template`) replace the file and make no API call at all unless `--reveal` is
given. The generic heuristic runs on every JSON file: a string under a key
matching `password|passwd|secret|token|private_?key|credential|api_?key` is
hidden unless the key ends in a safe suffix (`Arn`, `Id`, `Name`, `Type`, ...),
is an exact safe key (`HttpTokens`, pagination cursors), or the value is an ARN;
name and value lists under an `Environment` key are hidden too. Tag values are
never hidden. `--reveal` turns masking off and prints a warning; it cannot make
a denied operation callable.

## Error log

`ErrorLog` (`session/errorlog.py`) classifies failures into `ErrorKind`
(access denied, not found, not configured, throttled, budget, endpoint, other)
and keeps a ring buffer of 2,000 lines, shown as `_meta/errors.log` in TSV
(time, account, region, service, operation, kind, code, message). Identical
entries within 60 seconds collapse into one line ending in `(xN)`; with
`--verbose` each new line is also echoed to stderr.

How a failure reaches the user: a failed collection listing gives an empty
directory and a log line (not configured: empty, no line). A lazy file gives
`null` when not configured, `null` and a log line when not found, EACCES and a
log line when access is denied, and EIO and a log line for anything else.

## Progress counter

With `--verbose`, `Progress` (`session/progress.py`) prints
`[awsmount] api calls N <operation>`: one line rewritten in place on a
terminal (at most every 0.2 s), otherwise a line every 100 calls. Code that
writes anything else to stderr calls `clear_line()` first, so a message never
lands on the end of the counter.

## Providers

A provider describes one AWS service as data (`providers/base.py`). A
`ServiceSpec` has a directory name, a scope (`region` or `global`) and
`CollectionSpec`s. A collection says which client and list call fill it, how
to key and name resources, which `ops` it may call, and which extra files
(`FileSpec`, `SubdirSpec`), links (`LinkSpec`), referenced-by sources
(`RefSource`), tags (`TagSpec`), nested `children` and masking rule each
resource has. Each provider module exports one `SERVICE`.

`providers/__init__.py` lists the modules in `PROVIDER_MODULES`, loads them
lazily and builds `ProviderRegistry`, which indexes services and collections
(nested ones as `a/b`), derives the guard's allow-list (`allowed_pairs`),
validates every spec (unique names, non-empty `ops`, every op a read op and not
denied, link targets and referenced-by sources that exist and stay in one
scope) and produces `layouts()`, from which `awsmount services` and
`docs/coverage.md` are generated. Today there are 28 services and 63 resource
types. To add one, see [providers.md](providers.md).

## Resource directories

`tree/collection.py` builds them. `CollectionDir` calls the lister once
(through the cache), names every item with `assign_names` and creates one
`ResourceDir` per item. A `ResourceDir` contains, in order: `describe.json`
(the listed item, or lazy `spec.describe`; then masked), `arn` and `name` when
the spec gives them (`name` falls back to the `Name` tag), `tags.json` and
`tags/<Key>` (inline or lazy), the spec's files, `links/` and `referenced-by/`
(both a `LinkDir`), and nested collections. Lazy renderers go through
`guarded_render`, which applies the failure rules above. `tree/root.py` builds
the levels above the collections and `_meta`; `tree/tags.py` normalises tags
from list or map shapes.

## Links and referenced-by

A `LinkSpec` becomes a relative symlink under `links/`, for example
`subnet -> ../../../../vpc/subnets/subnet-0abc`. `LinkResolver.dirpath`
(`tree/links.py`) finds the target. An ARN value selects the account and
region from the ARN, and the link is omitted if that account or region is not
mounted. Global targets go under `/<account>/global/`. The key is the value
itself, or is found from an ARN or a name through the target's cached listing,
and the target must exist in that listing, so links are never dangling.

`ReferencedByIndex` answers "who uses this resource". It lists every source
collection once per TTL (one cached call each), maps target keys to sources
and names entries `<service>-<collection>-<dirname>`. Only security groups use
it today (network interfaces, instances, other groups' rules, load balancers,
Lambda functions, RDS instances and VPC endpoints).

## Shell

`adapters/shell` serves the interactive shell, the one-shot commands and
`shell -c`; all call the same functions in `commands.py`. The commands are
`ls`, `cd`, `pwd`, `cat`, `head`, `stat`, `get`, `tree`, `find`, `grep`,
`whoami`, `refresh`, `cache`, `help` and `exit` (alias `quit`). Unknown
commands exit 127, usage errors 2, `grep` with no match 1, partial results 3.
`grep` uses Python regular expressions; `get` evaluates `a.b[0].c`, `[*]` and
`*` (`jsonpath.py`). The working directory is logical (`..` is lexical).

`CMD | !pipeline` feeds a builtin's output to `/bin/sh -c`, and a line
starting with `!` runs a host command with `AWSMOUNT_CWD` set; host commands
cannot see the tree, and builtins cannot be piped to each other. The REPL uses
prompt_toolkit, with history in `$XDG_STATE_HOME/awsmount/history` (default
`~/.local/state/awsmount/history`, mode 0600). Completion fetches an uncached
directory on a worker thread and waits at most 2 seconds; on timeout the fetch
carries on, so the next Tab is instant.

## WebDAV

`adapters/webdav` serves the tree over HTTP on `127.0.0.1` only (the address is
fixed). `awsmount serve` runs it, and on macOS `awsmount mount` also mounts it.
The server is cheroot with 16 threads and this middleware, outermost first:
`HostCheck` (the `Host` header must be `127.0.0.1:PORT` or `localhost:PORT`,
else 421), `JunkFilter` (macOS junk names such as `.DS_Store` and `._*` get 404
without touching the tree), `TokenPrefix` (the path must start with
`/<token>/`, else 404), `MethodFilter` (only OPTIONS, GET, HEAD and PROPFIND
pass, with `Depth` 0 or 1; everything else gets 403) and wsgidav, with HTTP
authentication always required. `auth.py` generates a fresh URL token, the user
`awsmount` and a password per session, kept in memory and never in argv, URL or
environment. The token is not a secret; the password is.

`provider.py` maps the tree to DAV resources. Symlinks are served as small
files holding the relative target (`--webdav-links file`, the default) or as
their targets (`follow`, which can loop). An unrendered lazy file in a depth-1
listing reports no size and a path-based ETag, so `ls -l` and `find` over a
mount do not render every file; asking about that one file, or reading it,
renders it. Errors map to HTTP: missing is 404, a guard refusal 403, anything
else 503, and AWS access denied is 403 for `serve` but 401 for the macOS mount,
because `mount_webdav` shows a 401 as "Permission denied" and a 403 as
"Operation not permitted".

`macos.py` mounts it. `/sbin/mount_webdav` accepts no credentials on the
command line, so awsmount runs `mount_webdav -i -S -o rdonly,nobrowse -v
awsmount <url> <mountpoint>` on a pseudo-terminal and types the user name and
password at the prompts (25 s limit), aborting with advice if that fails. A loop
checks the mount table every 0.2 s, so `awsmount umount` ends the process
within a second; on exit it unmounts (`umount`, then `diskutil unmount force`),
stops the server and removes a mountpoint it created. See
[mounting-macos.md](mounting-macos.md). On Linux, `serve` only prints the URL
and credentials for a client such as davfs2.

## FUSE

`adapters/fuse` is the default mount method on Linux, and on macOS with
`--method fuse`. `AwsFuse` (`operations.py`) subclasses `mfusepy.Operations`.
Reads go to the VFS: `getattr`, `readdir` (with the type and inode of each
entry, because bash drops entries with inode 0), `readlink`, `open`, `read` and
`release`. `open` snapshots the content into a handle, so a read stays
consistent if the cache changes; a snapshot is capped at 64 MiB (EFBIG). Every
write operation (`READ_ONLY_OPS`) and any open with write intent returns EROFS;
a check at import time fails if a listed operation has no handler.

With `--lazy-size zero` (the default), `getattr` reports size 0 for a lazy file
that is not rendered yet and the file opens with `direct_io`, so the kernel
neither limits reads to that size nor caches the data. `render` reports exact
sizes at the cost of API calls on `ls -l`.

`mount.py` calls `mfusepy.FUSE` with `foreground`, `ro`, `raw_fi`, `use_ino`,
the TTL as attribute and entry timeout, and per-OS options. It never sets
`allow_other`, so only the mounting user can read the mount. libfuse 3 is
preferred over libfuse 2 (`platform.prefer_libfuse3`) because a machine can have
the libfuse 2 library without its `fusermount`. A `SIGTERM` that ends a mount
that was up is a normal exit. `mfusepy` is imported only when mounting, so the
shell and WebDAV work without libfuse.

## Export

`export()` (`adapters/export.py`) writes a subtree into a real directory for
`git` and `diff -r`. The destination must be empty, unless `--force` (overwrite
in place, never delete) or `--clean` (needs the `.awsmount-export` marker, then
deletes the contents first). The marker is JSON with the version, source, time
and `reveal` flag and is always written. Files are `0644` and directories
`0755`; content equals what is served, so masking follows `--reveal`; `--jobs`
workers render files. Links are written as text files holding the target (`file`,
the CLI default, which keeps `diff -r` and `grep -R` working), as real symlinks
(`keep`, which form cycles), or left out together with the `links/` and
`referenced-by/` directories (`skip`, using `LinkDir`). A per-path error is
printed and counted, and the exit code is then 3.

## Command line

`cli.py` is a click group: `shell`, `ls`, `cat`, `tree`, `find`, `grep`, `get`,
`export`, `mount`, `umount`, `serve`, `doctor`, `services`, `version` and the
`secrets` group. The common options (`common_options`) are `--profile`,
`--region`, `--endpoint-url`, `--services`, `--reveal`, `--ttl`,
`--max-api-calls`, `--budget-window`, `--concurrency`, `--max-attempts`,
`--s3-objects`, `--lazy-size`, `--verbose` and `--no-color`. They are accepted
before or after the subcommand, and the later value wins (`_merged`).

Exit codes: 0 ok, 1 error (for `grep`, no match), 2 usage, 3 partial (errors
recorded, or a profile could not be used), 4 budget exhausted, 130
interrupted. `--method auto` picks FUSE on Linux and WebDAV on macOS, whatever
is installed. `doctor` reports which methods work, makes no AWS call unless
`--check-credentials` is given, and exits 1 when a row says `FAIL`. `services`
prints the registry, and `--markdown` generates `docs/coverage.md`.

## awsmount secrets

Everything else in awsmount never reads a secret value, which is why a
read-only role is safe to mount. `awsmount secrets {mount,shell,umount}` is the
one exception. It reverses that contract, so it is a separate command with its
own session, allow-list and tree, not a mode of `mount`. Users read
[secrets.md](secrets.md); this section records the design.

**Separate guard.** `secrets/session.py` builds its own `Context` with an empty
provider registry, so no other service exists in the session. The allow-list is
`secretsmanager:ListSecrets`, `GetSecretValue`, `ssm:DescribeParameters` and
`GetParameter` plus the bootstrap calls. `DENIED_OPS` is not edited: the client
factory takes `value_ops`, exact `(client, Operation)` pairs that may skip the
deny list, each of which must also be on the allow-list, and only this session
passes any. `GetParameters`, `GetParametersByPath`, `BatchGetSecretValue`,
`Decrypt` and everything else stay refused. The identity is one
`sts:GetCallerIdentity` (a least-privilege role may not list aliases or
regions), and the `User-Agent` ends in `awsmount-secrets`, so CloudTrail shows
which reads are awsmount's. It mounts one profile and one region; the region is
never guessed.

**Tree** (`secrets/tree.py`):

```
secretsmanager/<escaped-name>/value  describe.json  versions/<stage>
ssm/<path>/<to>/<parameter>
ssm/<path>/<prefix>/@value      when a parameter is also a prefix
```

`AWSPENDING` is never shown. Names that differ only by case get a short tag
(`Case~5ae393`). Files are `0400` and directories `0500`. Secrets Manager is
listed with `ListSecrets` and Parameter Store with `DescribeParameters`;
neither returns a value, so a value is fetched only when its file is read, and
an unread value reports size 0. A refused read is remembered for
`negative_ttl`, because the macOS client retries ten times.

**Memory** (`secrets/store.py`). Values live in `bytearray`s in `ValueStore`,
not in the shared cache, for `--ttl` seconds (300 by default, 0 keeps
nothing). They are overwritten with zeros on expiry (a reaper thread), on
replacement, on `refresh` and on close. `RLIMIT_CORE` is 0 and nothing is
written to disk. This is best effort: Python and the kernel can hold other
copies. On macOS the system WebDAV client also keeps a temporary copy of each
file it reads in `/private/tmp/.webdavcache.*` until unmount, and re-checks a
file only about a minute after it last asked.

## Tests

`pytest` runs every directory under `tests/`, and `flake8 src tests` lints. All
of it uses the moto emulator and needs no AWS credentials.

| Directory | What it covers |
|---|---|
| `tests/unit` | names, stat, rendering, resolution, cache, budget, limiter, masking, error log, the guard, progress, mountpoint checks, the CLI |
| `tests/providers` | every provider against a seeded moto account, links, referenced-by, registry validation, access denied |
| `tests/adapters` | shell commands, completion, pipes, WebDAV over real HTTP, FUSE operations, the macOS mount loop, export |
| `tests/secrets` | the secrets session, tree, store and adapters |
| `tests/regression` | defects found in review or on a real account |
| `tests/e2e` | shell scripts that do real mounts over a moto server, on macOS and in Docker (`Dockerfile.fuse`) |

`tests/fixtures/seed.py` builds the moto account that the provider tests read.
The guard has its own tests: every operation a provider declares must be a
read operation and not denied, and every operation in `DENIED_OPS` must be
refused before any HTTP request. A gap in moto is marked `xfail(strict=True)`, so a fix is noticed. A
change to masking needs a test where the secret must stay hidden, and a change
to a mount adapter should also pass the matching end-to-end script, because
only a real mount shows some problems.
