# Changelog

All notable changes to awsmount are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-29

First release.

### Added

- **Mount an AWS account as a read-only filesystem.** 28 services and 63
  resource types, each resource a directory with a `describe.json`:
  - EC2 (with launch templates) and the VPC family;
  - ELBv2 (with nested listeners and rules);
  - Lambda;
  - RDS (with nested cluster members);
  - ECS (with nested services) and EKS (with nested node groups and
    add-ons);
  - EC2 Auto Scaling groups;
  - S3 (metadata, policy, encryption, public access block, versioning,
    optional object key listing);
  - DynamoDB, SQS, SNS, KMS and CloudWatch Logs;
  - CloudWatch alarms, ECR repositories, Step Functions state machines,
    Redshift clusters and EventBridge event buses (with nested rules);
  - CloudFormation (with nested stack resources);
  - Secrets Manager and SSM Parameter Store (metadata only);
  - ACM and API Gateway (REST);
  - Route 53, IAM, CloudFront and Organizations (global).
- **Mounting on macOS and Linux.**
  - macOS: a zero-install, read-only mount through the built-in
    `/sbin/mount_webdav`, driven over a pseudo-terminal so that the password
    never appears in argv. `--method auto` always picks it, even when FUSE-T
    or macFUSE is installed.
  - Linux: a read-only FUSE mount (mfusepy, libfuse 3 preferred) with real
    symlinks, no `allow_other` and `--lazy-size zero`. It is also available
    on macOS with `--method fuse` (FUSE-T or macFUSE, optional).
  - `awsmount serve` serves the tree over WebDAV on 127.0.0.1 only, with a
    Host check, a per-session URL token plus HTTP auth, read-only methods,
    finite PROPFIND depth and a macOS junk-name filter. Access denied by AWS
    gives "Permission denied" on the mounts and HTTP 403 on `serve`.
- **Relationships.**
  - `links/` symlinks between resources (plain text files over WebDAV).
  - `referenced-by/` for security groups, covering ENIs, instances,
    security group rules, load balancers, Lambda functions, RDS instances
    and VPC endpoints.
- **Read-only guard.** A strict operation allow-list derived from the
  providers, a read-prefix check and a deny-list of data-plane and
  credential operations, all enforced in a botocore `before-call` hook
  before any HTTP request.
- **Masking by default.**
  - Per-service rule sets.
  - Whole-file masking of EC2 user data and CloudFormation templates;
    neither is fetched unless `--reveal` is given.
  - Generic secret-key and environment-list heuristics on every JSON file.
  - `--reveal` opt-in, which prints a warning.
- **Light on the AWS API.**
  - Nothing is fetched until it is looked at; a WebDAV directory listing
    does not render lazy files.
  - A thread-safe TTL cache with single-flight loading and negative caching.
  - An optional rolling call budget (`--max-api-calls`, `--budget-window`),
    off by default. `_meta/stats.json` shows the use.
  - Per-service and global concurrency limits, botocore adaptive retries and
    a `--verbose` progress counter.
- **Stable output.** Canonical JSON (sorted keys, indent 2, ISO-8601
  datetimes, `ResponseMetadata` removed), AWS lists with an unstable order
  sorted, and deterministic `%XX` name escaping with case-insensitive
  collision suffixes (`~<id>`). Two exports of an unchanged account are
  byte-identical.
- **Error handling.** Errors are classified, and `_meta/errors.log` holds
  them as TSV with collapsing of repeated entries. AccessDenied degrades to
  an empty directory, or to EACCES on lazy files. A profile that cannot be
  used (mistyped, expired token) is reported on stderr and makes the command
  exit 3, so it is never mistaken for an empty account. Resources that AWS still
  reports after deletion (terminated EC2 instances, deleted NAT gateways,
  Transit Gateways, VPC endpoints and peering connections) are not listed.
- **Multi-account and multi-region.** `--profile` and `--region` are
  repeatable, and `--region all` is supported. `--endpoint-url` works with
  moto, localemu and other AWS-compatible endpoints.
- **Interactive shell** (`awsmount shell`).
  - Commands: `ls`, `cd`, `pwd`, `cat`, `head`, `stat`, `get`, `tree`,
    `find`, `grep`, `whoami`, `refresh`, `cache`, `help`, `exit`.
  - Tab completion, history (mode 0600) and colors.
  - `| !cmd` pipes to host commands.
  - `-c` for one command line.
- **One-shot commands:** `awsmount ls`, `cat`, `tree`, `find`, `grep` and
  `get`.
- **Export.** `awsmount export` materialises a subtree into a real
  directory for `git` snapshots and `diff -r`. Symlinks are written as text
  files by default (`--links file`), because real symlinks form cycles that
  make macOS `diff -r` fail. Options: `--links`, `--jobs`, `--clean`,
  `--force`.
- **Secret values: `awsmount secrets {mount,shell,umount}`.** The values of
  Secrets Manager secrets and Parameter Store parameters as read-only files,
  in a separate session that is the only one allowed to call
  `GetSecretValue` and `GetParameter` (see `docs/secrets.md`). Values are
  fetched when a file is read, held in memory for `--ttl` seconds (default
  300) and overwritten when they expire. Parameter Store is nested by path;
  `AWSPENDING` is never shown.
- **Diagnostics.**
  - `awsmount doctor` reports the mount methods that work on the machine;
    `--check-credentials` also checks the profiles and exits 1 when one of
    them fails. FUSE-T and macFUSE are reported as `optional` on macOS.
  - `awsmount services` lists coverage from the registry, with the files
    and links inside each resource directory (`--short` for one line per
    service, `--json`, `--markdown`).
- **Documentation.** Usage, security, secrets, macOS and Linux mounting, a
  provider guide, an architecture guide and a generated coverage page.
