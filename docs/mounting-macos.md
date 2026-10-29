# Mounting on macOS

awsmount offers two real mount methods on macOS:

- **WebDAV** through the built-in `/sbin/mount_webdav`. Nothing to install.
- **FUSE** through FUSE-T or macFUSE: optional, untested by the awsmount
  project, and **not recommended** (see the license notes below).

`awsmount doctor` tells you which of them work on your machine. The
interactive shell (`awsmount shell`) works everywhere and needs neither.

## WebDAV (default, zero install)

```sh
mkdir -p ~/aws
awsmount mount ~/aws --method webdav --profile prod
```

`--method auto` (the default) always picks WebDAV on macOS, even if FUSE-T
or macFUSE is installed. FUSE is used on macOS only with `--method fuse`.

What happens:

1. awsmount starts a WebDAV server on `127.0.0.1` with a random port, a
   fresh URL token and a fresh password.
2. It checks the mountpoint: it must be an empty directory. A missing
   mountpoint is created when its parent exists, and removed again on exit.
   awsmount warns if other users can modify the parent directory, or can
   traverse it and it is outside your home directory.
3. It runs:

   ```sh
   /sbin/mount_webdav -i -S -o rdonly,nobrowse -v awsmount \
       http://127.0.0.1:PORT/<token>/ ~/aws
   ```

   `-i` makes `mount_webdav` prompt for a username and password. awsmount
   drives those prompts through a pseudo-terminal, so the password never
   appears in argv, in the URL or in the environment. `-S` suppresses
   dialogs, `-o rdonly` makes the mount read-only and `nobrowse` hides it
   from the Finder sidebar.
4. It runs `mdutil -i off ~/aws` (best effort) so that Spotlight does not
   index the account.
5. On Ctrl-C (SIGINT) or SIGTERM it runs `umount ~/aws`, falling back to
   `diskutil unmount force ~/aws`, then stops the server.

The `-r` and `-a <fd>` options and credentials embedded in the URL do not
work with current `mount_webdav` releases, which is why the pty handshake is
used. If the handshake fails (no prompt within 25 s, or a non-zero exit),
awsmount aborts and suggests `awsmount serve` or FUSE. It never falls back to
weaker authentication.

### About the URL token

The token in the mount URL is **not a secret**. It is visible in the mount
command line and in the output of `mount`, which every local user can read.
Access is protected by HTTP authentication, which is always required: the
password is generated per session, typed into `mount_webdav` through the pty,
and never stored. Knowing the token without the password gives `401`.

### Symlinks over WebDAV

WebDAV has no symbolic links. By default (`--webdav-links file`) each link is
served as a small regular file containing the relative target followed by a
newline, like git with `core.symlinks=false`. This keeps `grep -r`, Finder and
Spotlight away from link cycles. `--webdav-links follow` serves links as their
targets instead; loops are then possible and awsmount prints a warning.

### Finder junk

macOS probes every WebDAV volume for `.DS_Store`, `._*` AppleDouble files,
`.metadata_never_index`, `.Spotlight-V100`, `.Trashes`, `.fseventsd`,
`.hidden`, `.localized`, `.VolumeIcon.icns`, `.TemporaryItems` and similar
names. awsmount answers all of them with a fast `404` before touching the
virtual filesystem, so they never cost an API call. No real awsmount entry
can start with a dot (leading dots are escaped as `%2E`), so these names
never clash with account data.

### Using Finder directly

```sh
awsmount serve --profile prod
```

prints the URL, the username (`awsmount`) and the password, then blocks. In
Finder choose **Go > Connect to Server** (⌘K), paste the URL and enter the
credentials when asked. Stop the server with Ctrl-C.

## FUSE (FUSE-T or macFUSE): optional, and think before you install

You do not need FUSE on macOS. The WebDAV mount above is built in, needs no
administrator password, and is the path the awsmount project tests. Both
FUSE layers are third-party software with terms you should read first:

- **FUSE-T** is a closed-source binary. Its GitHub repository publishes
  only a README, `License.txt` and `Attributions.txt`, not its source code.
  Its license is "free for non-commercial use"; commercial use, or bundling
  it with commercial software, requires a commercial license from its
  authors (only its bundled libfuse fork is LGPL). Its installer asks for an
  administrator password. awsmount does not bundle it and has not tested
  against it.
- **macFUSE** open-sourced less of itself over time: since version 3.9 some
  components, such as the kernel extension, are not open source, and
  bundling it with commercial software requires a paid license. Installing
  it requires approving a system extension.

If you still want FUSE on macOS (for real symlinks), install one of them
yourself and then:

```sh
awsmount mount ~/aws --method fuse --profile prod
```

FUSE mounts support real symlinks, `readlink`, and the `--lazy-size zero`
option (lazy files report size 0 until read, avoiding API calls on `ls -l`).
The volume is mounted read-only, without `allow_other`, with
`noappledouble` and `noapplexattr` on macFUSE.

## What the macOS client caches

The built-in WebDAV client keeps its own copy of directory listings, file
attributes and file contents for about a minute, whatever `--ttl` says. That
has three visible effects:

- A change in AWS shows up on the mount after up to about a minute even when
  awsmount's own cache (`--ttl`, 60 s by default) has already expired.
- `_meta/stats.json` and `_meta/errors.log`, which awsmount always renders
  fresh, can be that old when read through the mount. For the live call
  counter use `--verbose` (the `[awsmount] api calls N` line in the terminal
  that runs `awsmount mount`), or read the files in `awsmount shell`.
- A second walk over the same directories right after the first one makes no
  AWS call and takes milliseconds, because the client answers it.

## Unmounting

```sh
awsmount umount ~/aws
```

or Ctrl-C in the terminal running `awsmount mount`. If a mount is stuck:

```sh
umount ~/aws || diskutil unmount force ~/aws
```

## Troubleshooting

- `awsmount doctor` lists `/sbin/mount_webdav`, FUSE-T
  (`/usr/local/lib/libfuse-t.dylib`) and macFUSE
  (`/Library/Filesystems/macfuse.fs`). The last two show `optional` when
  they are absent, which is normal and needs no action.
- Writes such as `touch ~/aws/x` fail with "Read-only file system"; this is
  expected.
- Large recursive reads may hit the API budget (`--max-api-calls`). Use
  `--verbose` to see a progress counter and check
  `~/aws/<account>/_meta/errors.log`.
