# Mounting on Linux

On Linux the real mount uses FUSE, through mfusepy and libfuse 2 or 3. The
shell and the one-shot commands need no native library.

## Install

```
sudo apt install fuse3        # Debian/Ubuntu (Fedora: sudo dnf install fuse3)
pipx install awsmount         # or: python3 -m pip install awsmount
awsmount doctor
```

When everything is in place, `doctor` prints something like:

```
method                 | status | detail
python                 | OK     | 3.12.3
package:boto3          | OK     | installed
package:click          | OK     | installed
package:prompt_toolkit | OK     | installed
package:wsgidav        | OK     | installed
package:cheroot        | OK     | installed
package:mfusepy        | OK     | loads
libfuse                | OK     | libfuse3.so.3
/dev/fuse              | OK     | read/write
fusermount             | OK     | /usr/bin/fusermount3

shell: OK · webdav-serve: OK · webdav-mount: N/A (use fuse, or 'awsmount serve' + davfs2) · fuse: OK
```

`doctor` checks three things:

- the libfuse shared library (`fuse3` is preferred, `fuse` is the fallback);
- read/write access to `/dev/fuse`;
- `fusermount3` or `fusermount` on `PATH`.

## Mount

```
$ awsmount -p prod -r eu-west-1 mount ~/aws
awsmount: mounted read-only at /home/me/aws (FUSE). Press Ctrl-C or run 'awsmount umount /home/me/aws' to unmount.
```

The command blocks. On Linux, `--method auto` always means FUSE.

- **Mountpoint.** It must be an empty directory. A missing directory is
  created (mode 0700) if its parent exists, and removed after unmount.
- **Mount options.** `ro`, `fsname=awsmount`, `subtype=awsmount`,
  `use_ino`, and attribute/entry timeouts equal to `--ttl` (negative
  timeout `min(ttl, 10)`).
- **Access.** `allow_other` is **never** set, so only your user (and root)
  can read the mount. You do not need `user_allow_other` in
  `/etc/fuse.conf`.
- **Writes.** Every write operation returns EROFS ("Read-only file
  system").
- **Symlinks.** They are real relative symlinks: `readlink`, `ls -l`,
  `cd links/vpc` and `realpath` work. GNU `grep -r`, `find` and `tree` do
  not follow them by default, so recursive searches do not loop. Do not use
  `grep -R` or `find -L` on the mount root.
- **Large files.** Each open file keeps a snapshot of its content, capped
  at 64 MiB (EFBIG beyond).

### Unmount

Press Ctrl-C in the mounting terminal, or run:

```
awsmount umount ~/aws
```

It tries `fusermount3 -u`, then `fusermount -u`, then `umount`.

### File sizes and `--lazy-size`

By default (`--lazy-size zero`), unrendered lazy files report size 0 and are
opened with direct I/O. Readers still get the full content, and `ls -l` costs
no API call. With `--lazy-size render`, a lazy file is rendered the first time
it is stat'ed, so its size is exact. This means `ls -l` in a resource
directory makes that resource's lazy API calls, cached for the TTL.

```
awsmount -p prod mount ~/aws --lazy-size render
```

## Docker and containers

FUSE inside a container needs the device and the `SYS_ADMIN` capability:

```
docker run --rm -it --device /dev/fuse --cap-add SYS_ADMIN \
  -v ~/.aws:/root/.aws:ro python:3.12-slim bash
# inside:
apt-get update && apt-get install -y fuse3
pip install awsmount
awsmount mount /mnt/aws
```

On hosts with AppArmor (Ubuntu), you may also need
`--security-opt apparmor:unconfined`. If FUSE is not available in your
container, use `awsmount shell` or `awsmount export` instead; neither needs
FUSE.

## WebDAV on Linux

awsmount does not automate WebDAV mounts on Linux. `awsmount mount
--method webdav` refuses on Linux, but `awsmount serve` works and prints the
URL and credentials:

```
$ awsmount -p prod serve --port 8765
URL:      http://127.0.0.1:8765/3f1c.../
User:     awsmount
Password: Qm9...
Read-only WebDAV on 127.0.0.1 only. Press Ctrl-C to stop.
```

Connect any WebDAV client. For example:

- GNOME Files: "Other Locations", then enter `dav://127.0.0.1:8765/<token>/`;
- davfs2: `sudo mount -t davfs -o ro http://127.0.0.1:8765/<token>/ /mnt/aws`,
  and enter the user and password when prompted.

davfs2 caches file contents on disk (`/var/cache/davfs2` or
`~/.davfs2/cache`); see [security.md](security.md). Symlinks are served as
text files containing their target unless you pass `--webdav-links follow`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `FUSE is not available: ...` | `sudo apt install fuse3`, `pip install mfusepy`; run `awsmount doctor` |
| `fuse: failed to exec fusermount` | The libfuse 2 library is installed without its `fusermount` helper (Amazon Linux 2023 ships `fuse-libs` next to `fuse3`). awsmount prefers libfuse 3 when it is present. Otherwise install `fuse3`, or set `FUSE_LIBRARY_NAME=fuse3` |
| `/dev/fuse` missing or not accessible | Load the module (`sudo modprobe fuse`); in Docker add `--device /dev/fuse --cap-add SYS_ADMIN` |
| `fusermount: ... Permission denied` | Check that `fusermount3` is installed setuid (it is with the distribution package) |
| Stale mount after a crash ("Transport endpoint is not connected") | `awsmount umount ~/aws`, or `fusermount3 -u ~/aws` |
| Empty directories | Read `~/aws/<account>/_meta/errors.log` |
| `Input/output error` during `grep -r` | API budget exhausted (see stderr); raise `--max-api-calls`, narrow `--services`/`--region` |
