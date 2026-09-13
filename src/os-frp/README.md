# frp for OPNsense

`os-frp` integrates [frp](https://github.com/fatedier/frp) into OPNsense. frp is
two daemons that share nothing but a wire protocol, so the plugin gives each one
a page of its own under the **Services > frp** heading:

- **Services > frp > Server (frps)** — the server that accepts tunnels and
  publishes remote ports
- **Services > frp > Client (frpc)** — the client that exposes a local service
  through a remote `frps`

Each page carries that daemon's service controls, its settings, its raw TOML
document and its log, and nothing of the other one. The client page also holds
the proxy editor, which is where the plugin's whole risk lives: every row states
in the row what it makes reachable from outside. The form covers the fields that
matter; the raw TOML editor stays available as an advanced fallback for anything
the form does not model.

| | |
| --- | --- |
| Plugin version | `1.0.0` |
| Bundled frp | `0.71.0` |
| Target | OPNsense 26.7, `FreeBSD:15:amd64`, Python 3.13 |

The build script accepts the FreeBSD 15 amd64 ABI only. Do not force-install the
package on another architecture or FreeBSD major release.

## What the settings are

The settings **are** the TOML document. `manage.py` reads the live file with
`tomllib` and hands it to the GUI as JSON; saving writes TOML back. There is no
second schema that can drift away from what the daemons read.

Both daemons run with `--strict_config` at its default, so a single unknown or
misspelled key is `exit(1)` rather than a warning. Everything the plugin writes
comes from a known field table, never from a guessed key name.

Credentials — `auth.token`, `webServer.password` and any proxy `secretKey` or
plugin password — never leave the router. They are replaced on the way out by
the literal string `__KEEP__`, and a field that still carries `__KEEP__` on the
way in keeps the stored value. A `__KEEP__` arriving at a path that held no
credential before is rejected, so the placeholder cannot be moved somewhere else
to smuggle a value out.

## What the plugin refuses to start

Three `frps` settings have no safe default, and the plugin will not start the
server without them:

- `auth.token` — an empty token authenticates every client that sends an empty
  token
- `webServer.user` **and** `webServer.password` — with both empty, the admin API
  middleware is bypassed entirely and anyone who reaches the dashboard port can
  delete proxies
- `allowPorts` — unset, clients may bind any remote port on the firewall

For the same reason the installer starts nothing. A fresh installation lands
with the sample configuration in place and both services stopped.

## Layout

```text
Makefile                                                 make package / pin-checksum / test / clean
build.sh                                                 builds dist/os-frp-1.0.0.pkg on FreeBSD 15
vendor/frp_0.71.0_freebsd_amd64.tar.gz                   upstream release archive, digest pinned
vendor/frp_sha256_checksums.txt                          the release's published checksums
packaging/freebsd/                                       pkg metadata and the four lifecycle hooks
src/etc/rc.conf.d/frps.sample                            rc.conf defaults, server
src/etc/rc.conf.d/frpc.sample                            rc.conf defaults, client
src/usr/local/etc/frp/frps.toml.sample                   sample server configuration
src/usr/local/etc/frp/frpc.toml.sample                   sample client configuration
src/usr/local/etc/rc.d/frps                              rc.d service, server
src/usr/local/etc/rc.d/frpc                              rc.d service, client
src/usr/local/etc/inc/plugins.inc.d/frp.inc              OPNsense service registration
src/usr/local/opnsense/service/conf/actions.d/            configd actions, one file per side
src/usr/local/opnsense/scripts/frp/manage.py             the backend both sides call
src/usr/local/opnsense/mvc/app/controllers/OPNsense/Frp/ index and API controllers
src/usr/local/opnsense/mvc/app/views/OPNsense/Frp/server.volt  the frps page
src/usr/local/opnsense/mvc/app/views/OPNsense/Frp/client.volt  the frpc page
src/usr/local/opnsense/mvc/app/views/OPNsense/Frp/common.volt  the script both pages share
src/usr/local/opnsense/mvc/app/models/OPNsense/Frp/      menu and ACL
tests/                                                   plugin tests
```

The two binaries are not in `src/`. `build.sh` extracts them from the vendored
upstream archive into the stage at `/usr/local/sbin/frps` and
`/usr/local/sbin/frpc`; the archive itself is never packaged.

## Build

Build on a native FreeBSD 15 amd64 or OPNsense host with `pkg` available.

Put the upstream release archive in `vendor/`:

```text
vendor/frp_0.71.0_freebsd_amd64.tar.gz
```

Pin its digest once, after checking it against the checksum published with the
frp release:

```sh
make pin-checksum
```

That writes `vendor/frp_0.71.0_freebsd_amd64.tar.gz.sha256`. Without it the build
falls back to `vendor/frp_sha256_checksums.txt`, the checksum file published with
the frp release, and uses the line for this archive. From then on the
build compares the archive against the recorded digest and stops on a mismatch,
so a swapped or re-fetched artifact fails the build instead of shipping
unreviewed binaries. `FRP_DIST_SHA256` overrides the recorded value for a
one-off build.

Then:

```sh
make package
```

The result is `dist/os-frp-1.0.0.pkg`. `build.sh` can also be called directly:

```sh
ABI=native sh build.sh
OUTPUT_NAME=os-frp.pkg sh build.sh
```

The build refuses to produce a package when:

- the vendored archive is missing, has no recorded digest, or fails it
- `frps` or `frpc` is absent from the archive, ambiguous, or not an ELF binary
- any contracted source file is missing
- `src/usr/local/opnsense/version/frp` disagrees with the package version
- the target ABI is not FreeBSD 15 amd64
- a live runtime path is staged — `/usr/local/etc/frp/frp{s,c}.toml`,
  `/etc/rc.conf.d/frp{s,c}`, the pidfiles, the logs or `/var/db/os-frp`. This
  matters more here than in most plugins: the server configuration holds the
  authentication token and the dashboard password, so a packaged copy would
  publish one installation's secret to every other one. Only the `.sample`
  files ship.
- the vendored archive or Python bytecode reaches the stage or the final archive

## Install

```sh
pkg add -f os-frp-1.0.0.pkg
```

Refresh the web interface. The menu gains a **Services > frp** heading with
**Server (frps)** and **Client (frpc)** under it.

## Runtime paths

| Path | Mode | Owner |
| --- | --- | --- |
| `/usr/local/sbin/frps`, `/usr/local/sbin/frpc` | `0755` | package |
| `/usr/local/etc/frp/frps.toml`, `frpc.toml` | `0600 root:wheel` | first install, then yours |
| `/etc/rc.conf.d/frps`, `/etc/rc.conf.d/frpc` | `0644` | first install, then yours |
| `/var/run/frps.pid`, `/var/run/frpc.pid` | | runtime |
| `/var/log/frps.log`, `/var/log/frpc.log` | `0600` | runtime |
| `/var/db/os-frp/` | `0700` | plugin state |

The live configurations, the rc.conf fragments and the logs are not owned by the
package. They are created only when absent and are never overwritten.

## Service control

The GUI is the intended entry point. The same verbs are available from a shell:

```sh
configctl frps status
configctl frpc restart
/usr/local/bin/python3 /usr/local/opnsense/scripts/frp/manage.py --json frps status
```

`manage.py` prints `{"ok": true, "result": ...}` or `{"ok": false, "error": ...}`
and exits 0 either way, so a refusal is a result rather than a crash.

## Upgrade

An upgrade keeps both TOML files, both rc.conf fragments and both logs. The
pre-deinstall hook stops each daemon with a bounded wait — a slow shutdown must
not hold the package operation open — and records which side was running. The
post-install hook restarts exactly those sides, through `manage.py`, which still
refuses a configuration that is not safe to start.

## Uninstall

```sh
pkg delete os-frp
```

The removal stops both daemons, clears both pidfiles and drops the cached menu
and ACL models so the VPN entry disappears at once. `/usr/local/etc/frp` and the
logs are left in place: they hold the tunnel definitions and the credentials a
reinstall would otherwise ask for again. Remove them by hand if the intent is to
discard the configuration.

## Notes

- `frps` publishes ports on the firewall itself. Keep `allowPorts` as narrow as
  the deployment allows, and do not expose `webServer` beyond a management
  network.
- Do not add a second start path for either daemon through Cron or Shellcmd.
  The rc.d services and the configd actions are the only supported ones.
- This is an unofficial community plugin. It is not supported by Deciso,
  OPNsense or the frp project.

## Related

- [frp](https://github.com/fatedier/frp)
