# Security Policy

## Reporting a vulnerability

Do not open a public issue. Email **tarek@kloudsec.io** with a description, the affected version, and steps to reproduce.

You can expect an acknowledgement within 5 business days.

Reports we are especially interested in:

- a way to make awsmount send a write call to AWS (a bypass of the read-only guard);
- a secret that is shown although masking is on (see the [list of masked values](docs/security.md#2-masking-is-on-by-default));
- a way for another local user, or a web page in a browser, to read a mounted account or reach the WebDAV server;
- a way to read a secret or parameter **value** through anything other than `awsmount secrets` (`mount`, `shell`, `serve` and `export` must never call `GetSecretValue` or `GetParameter`), or to make `awsmount secrets` call any other operation;
- a secret value that `awsmount secrets` writes to disk, logs, or keeps in memory after its TTL or after the mount ends.

## Supported versions

Only the latest release receives security fixes.

## Scope

awsmount only calls read-only AWS APIs, and the guard refuses anything else before a request is sent. See [docs/security.md](docs/security.md) for the read-only model, masking, `--reveal` and what awsmount deliberately does not protect against (for example tag values and other local processes running as your user).

`awsmount secrets` is the one command that reads secret values. Its limits are documented in [docs/secrets.md](docs/secrets.md): overwriting memory is best effort, and on macOS the system WebDAV client keeps a temporary copy of each file it reads until unmount.
