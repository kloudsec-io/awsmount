# Secret values: `awsmount secrets`

Everything else in awsmount **never reads a secret value** (see
[security.md](security.md)). `awsmount secrets` is the one exception: it
mounts the **values** of AWS Secrets Manager secrets and Systems Manager
Parameter Store parameters as read-only files.

It is a separate command with its own session. `awsmount mount`, `shell`,
`serve` and `export` still cannot call `GetSecretValue` or `GetParameter`,
even with `--reveal`.

```
awsmount secrets mount ~/secrets -p prod -r eu-west-1     # Linux, macOS
awsmount secrets shell -p prod -r eu-west-1               # no mount needed
awsmount secrets umount ~/secrets
```

One profile and one region per mount. Without `--region` the region of the
profile or of `AWS_DEFAULT_REGION` is used; if there is none, the command
stops instead of guessing (a wrong region would show the wrong secrets). On
an EC2 instance the region is not set by default, so pass `--region`.

At start it prints a warning with the profile, account and region, and how
long values stay in memory.

## What you see

```
~/secrets/
  secretsmanager/
    <secret name>/            "/" in a name is escaped: team%2Fapi
      value                   the secret value, byte for byte
      describe.json           metadata from ListSecrets (never a value)
      versions/
        AWSCURRENT            the current value
        AWSPREVIOUS           only when it exists
  ssm/
    <path>/<to>/<parameter>   nested like the parameter path
```

- `value` is exactly `SecretString` (UTF-8) or `SecretBinary`. No newline is
  added, so `cat value` equals `aws secretsmanager get-secret-value`.
- `versions/` lists the staging labels that exist. `AWSPENDING` is never
  shown, because it can be an in-flight rotation value.
- Parameter Store is nested by path, like the console. `SecureString`
  values are decrypted, `StringList` values are the comma-separated text.
- A name that is both a parameter and the start of other paths (`/app` and
  `/app/db/host`) is a directory with the parameter's own value in `@value`.
  AWS allows this.
- Names that differ only by case (`/Case`, `/case`; `a/CaseX`, `a/casex`)
  get a short tag so both stay reachable, also on a case-insensitive Mac:
  `Case~5ae393`, `case~8ffc37`.
- Files are `0400` and directories `0500`.

## What is read, and when

Listing never reads a value. A directory is listed with `ListSecrets` and
`DescribeParameters`, which return no values, and `ls -l`, `find` and
`stat` show a size of 0 for a value that has not been read yet.

A value is fetched the first time its file is read, with
`secretsmanager:GetSecretValue` or `ssm:GetParameter` (with decryption), and
kept in memory for `--ttl` seconds (default 300, the default of the AWS
Parameters and Secrets Lambda extension). `--ttl 0` keeps nothing and
fetches on every read.

These are the only operations the session may call, apart from the three
harmless bootstrap calls every awsmount session has (`GetCallerIdentity`,
`ListAccountAliases`, `DescribeRegions`). `BatchGetSecretValue`,
`GetParameters`, `GetParametersByPath`, `GetParameterHistory`, `Decrypt` and
every other service are refused by the guard.

Every read is a CloudTrail event, and reading a `SecureString` or a secret
with a customer-managed key also costs a KMS decrypt. A recursive tool such
as `grep -r` over the mount reads every value it can. Use `-v` to log which
value is read (the name, never the value), and `--max-api-calls` to cap the
calls.

## Permissions

Whatever your identity already has. Minimum for the whole mount:

```json
{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow", "Action": ["secretsmanager:ListSecrets",
                                 "ssm:DescribeParameters"], "Resource": "*"},
  {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue",
   "Resource": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:PREFIX/*"},
  {"Effect": "Allow", "Action": "ssm:GetParameter",
   "Resource": "arn:aws:ssm:REGION:ACCOUNT:parameter/PREFIX/*"},
  {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "KEY_ARN"}]}
```

On an EC2 instance, do not rely on the instance role being narrow if it also
carries the AWS managed policy `AmazonSSMManagedInstanceCore` (the one the SSM
agent needs): that policy allows `ssm:GetParameter` on every parameter in the
account, so the `ssm/` tree will show all of them. Use a policy with only the
SSM agent's own actions instead.

A value you may not read fails with "Permission denied" (`EACCES`); the rest
of the mount keeps working. A refusal is remembered for 10 seconds, so a
program that retries (the macOS WebDAV client retries ten times) costs one
AWS call and one CloudTrail event, and the next read after that asks AWS
again.

## What awsmount does to protect values

- Values are held in `bytearray` objects in the awsmount process only, and
  overwritten with zeros when they expire (a background thread checks every
  few seconds), when they are replaced, and when the mount ends.
- They do not go through the shared response cache, which keeps immutable
  objects that cannot be wiped.
- Core dumps of the process are switched off (`RLIMIT_CORE` 0).
- awsmount writes no value to disk. `awsmount export` cannot see this tree.
- The mount is private to your user: no `allow_other`, files `0400`.

## What it cannot promise

**Overwriting memory is best effort.** Python can leave other copies (the
AWS response, JSON parsing), and the kernel's page cache and every process
that reads the file keep their own copies. This was measured on Linux by
scanning the memory of the awsmount process for one value (`--ttl 20`): 0
copies before the read, 6 right after it, and still 4 after the TTL had
passed and the buffer had been overwritten. Those are freed objects that
Python has not reused yet, not references; awsmount cannot zero them. Do not
read the mount with a tool you do not trust.

**On macOS the system's WebDAV client writes a copy to disk.** The Mac mount
uses the built-in WebDAV client (`webdavfs`). It keeps a temporary copy of
every file it reads in `/private/tmp/.webdavcache.<pid>.<random>/`. The files
are owner-only and already unlinked, and the directory is removed when you
unmount, but the bytes are on the disk meanwhile. This was measured: the open
temporary files had exactly the sizes of the secrets that had been read.
`awsmount` itself writes nothing, and cannot change this behaviour. Keep
**FileVault** on, and unmount when you are done.

The same client also delays changes: it re-checks a file only about a minute
after it last asked, whatever `--ttl` says. A secret rotated while the mount
is up shows its new value on macOS after up to about 60 seconds (measured:
the old value at 26, 36 and 46 seconds with `--ttl 20`, the new one at about
60), and `--ttl 0` does not stop the client's own copy. `awsmount secrets mount`
prints this warning on macOS. On Linux the FUSE mount has no such copy.

**Anything that can read your files can read the mount.** That includes
other programs running as you, and AI agents. Do not give an agent access to
this mount.

## Troubleshooting

| You see | Meaning |
|---|---|
| `no region: pass --region` | The profile and environment have no region. |
| `cannot use these credentials` | The `GetCallerIdentity` check failed. |
| `Permission denied` on `value` | AWS refused that read (IAM or KMS). |
| `No such file or directory` on a listed `value` | The secret was deleted after the listing. |
| `Input/output error` | Upstream failure (a throttle, expired credentials), or `--max-api-calls` reached. |
| A new secret is missing | Listings are cached for `--ttl`; wait or remount. |
