# Contributing

Bug reports and pull requests are welcome.

- **Wrong or missing data?** Open an issue with the path (for example `ec2/instances/<id>/describe.json`), a sanitized copy of what you saw (replace account IDs, names and anything sensitive), and what you expected. This is the most useful contribution.
- **Want another service?** Open an issue with the service and the resources you need. [docs/providers.md](docs/providers.md) explains how a provider is written.
- **Security problem?** Do not open an issue. See [SECURITY.md](SECURITY.md).

## Pull requests

```bash
git clone https://github.com/kloudsec-io/awsmount && cd awsmount
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q && flake8 src tests
```

To see how the code is organised before you change it, read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

Keep changes small, add a test (including a case where a secret must **stay hidden**), and make sure the commands above pass. Python 3.11 or higher is required. The tests use the moto AWS emulator and need no AWS credentials.

A change to the FUSE or WebDAV code should also pass the end-to-end scripts: `tests/e2e/linux_fuse.sh` (inside `tests/e2e/Dockerfile.fuse`) and `tests/e2e/macos_webdav.sh`. A change to `awsmount secrets` should also pass `tests/e2e/secrets_linux_fuse.sh` (in the same image) and `tests/e2e/secrets_macos_webdav.sh`. Unit tests alone cannot catch problems that only a real mount shows.

By contributing, you agree that your work is released under the [MIT License](LICENSE).
