# ttyd for OPNsense

[![OPNsense](https://img.shields.io/badge/OPNsense-Plugin-orange)](https://opnsense.org/)
[![FreeBSD 15](https://img.shields.io/badge/FreeBSD-15-red)](https://www.freebsd.org/)
[![ttyd](https://img.shields.io/badge/ttyd-Web%20Terminal-blue)](https://github.com/tsl0922/ttyd)
[![amd64](https://img.shields.io/badge/Architecture-amd64-success)](#)

This project adds a ttyd browser terminal to OPNsense under:

```text
System > Diagnostics > ttyd
```

## Native configuration backup and restore

The plugin mirrors the exact bytes, permissions and presence of
`/etc/rc.conf.d/ttyd`, the `/usr/local/etc/lighttpd_webgui/conf.d/ttyd.conf`
proxy configuration, and optional legacy `/usr/local/etc/ttyd.crt` and
`ttyd.key` files into `OPNsense/Ttyd/backup` in `config.xml`. Full OPNsense
configuration backups include custom commands, listener overrides and the
disabled service setting. Global SSH settings remain in the native OPNsense
configuration. Logs, PID files and locks are excluded.

After configuration restoration, files are restored before the terminal
service starts. An independent background process checks external edits every
second, including while ttyd is stopped. Successful WebGUI service operations
also update the mirror synchronously. Resolve any backup warning before
exporting a configuration backup. The existing rc and TLS upgrade backups
remain available during package replacement.

Compression and Base64 encoding do not encrypt the archived files. Use the
OPNsense backup encryption option to protect custom commands or TLS private
keys. Plugin reinstallation remains part of the OPNsense plugin restore flow.

The web terminal starts a real TTY through `ttyd`, then prompts for a login name and connects to the local firewall through SSH:

```sh
printf "login: "; read -r user; ssh -tt "$user@127.0.0.1"
```

Authentication, permissions, auditing, and the shell environment remain controlled by OPNsense OpenSSH.

Tested and verified in the following environments:

- OPNsense 26.1.9

![](image/ttyd.png)

## Compatibility

The current package targets OPNsense 26.7 on FreeBSD 15 amd64. The build verifies the committed checksums for the three bundled runtime packages under `vendor/freebsd15-amd64`, then stages an explicit file and license inventory under `/usr/local/os-ttyd`. Shared-library aliases contain regular copies of the pinned ELF files. The FreeBSD 14 archives and checksums remain available for legacy work; this version rejects FreeBSD 14 builds until their own inventory and native validation are provided.

## Files

- `src/usr/local/opnsense/mvc/app/views/OPNsense/Ttyd/index.volt`: OPNsense web page.
- `src/usr/local/etc/lighttpd_webgui/conf.d/ttyd.conf`: same-origin reverse proxy for the embedded terminal.
- `src/usr/local/opnsense/mvc/app/models/OPNsense/Ttyd/Menu/Menu.xml`: OPNsense menu entry.
- `src/usr/local/opnsense/mvc/app/models/OPNsense/Ttyd/ACL/ACL.xml`: OPNsense page ACL entry.
- `src/usr/local/opnsense/service/conf/actions.d/actions_ttyd.conf`: configd service actions.
- `src/usr/local/etc/rc.d/os-ttyd`: rc.d service script.
- `src/etc/rc.conf.d/ttyd.sample`: default service configuration.
- `vendor/freebsd15-amd64/*.pkg`: pinned current FreeBSD 15 amd64 runtime packages.
- `vendor/freebsd14-amd64/*.pkg`: retained legacy FreeBSD 14 runtime packages.
- `build.sh`: builds `dist/os-ttyd.pkg` on FreeBSD/OPNsense. The package uses a private runtime under `/usr/local/os-ttyd`.

## Install

Upload the package installer to the firewall and run the following command in the OPNsnese shell to install it：

```sh
pkg add -f os-ttyd.pkg
```

Refresh the OPNsense web interface and open `System > Diagnostics > ttyd`.

## Uninstall

```sh
pkg delete os-ttyd
```
## Requirements

1. Enable Secure Shell under `System > Settings > Administration`. The default terminal command needs SSH password or keyboard-interactive authentication.
2. Allow the management workstation to reach the OPNsense WebGUI HTTPS port. HTTP and WebSocket traffic use the same `/ttyd/` proxy path.
3. Keep the backend listener on its default loopback address.

## Usage

Open `System > Diagnostics > ttyd`. The page embeds the terminal through the OPNsense WebGUI path:

```text
https://<OPNsense-address>/ttyd/
```

The terminal first displays `login:`. Enter the OPNsense SSH username, then enter the SSH password when prompted. With public-key-only SSH authentication, configure a custom `ttyd_command` using an available key; the default command disables public-key authentication.

## Configuration

The default command follows the configured OPNsense SSH port (22 when unset):

```text
127.0.0.1:<configured-SSH-port>
```

The default ttyd listen address is `127.0.0.1`, and the default backend port is `7681`. OPNsense lighttpd proxies `/ttyd/` to that local backend. Edit `src/etc/rc.conf.d/ttyd.sample` before installation, or `/etc/rc.conf.d/ttyd` after installation, then restart the service:

```sh
service os-ttyd restart
```

## Security Notes

- Do not expose the ttyd listener to WAN.
- Use strong OPNsense administrator credentials or SSH keys.
- Remove the project or restrict management access when the terminal is not needed.

## Disclaimer
This is an unofficial plugin and is not supported by the OPNsense team; use at your own risk.
