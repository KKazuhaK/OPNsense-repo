[中文](README.md) · English

# Mihomo for OPNsense

This independent fork targets **OPNsense 26.7 / FreeBSD:15:amd64**. Installations run local proxy ports without changing LAN routing or DNS. TUN and Unbound forwarding are enabled together by an explicit administrator action.

## Configure

1. Install `os-mihomo` from the signed Kazuha repository using **System → Firmware → Plugins**.
2. Open **VPN → Proxy Suite → Mihomo Subscribe**. Save a complete Mihomo YAML subscription URL, a device label, and this router's dashboard IPv4 address and port. The default is `192.168.8.1:9090`; change it for routers with a different LAN address.
3. Fetch and apply the subscription. No third-party converter receives its URL. The subscription's proxies, groups, and rules are retained. YAML is parsed structurally, so escaped emoji, key order, flow mappings, and zero-indent lists work.
4. Verify connectivity through the local mixed proxy at `127.0.0.1:7890` or SOCKS5 at `127.0.0.1:7891` before enabling transparent routing. A fresh installation without a subscription uses `MATCH,DIRECT`.
5. Open **VPN → Proxy Suite → Mihomo** and select **Enable transparent routing**. This starts the TUN configuration and then enables the DNS forwarder after the core and its DNS listener are ready. Use **Disable transparent routing** to return to proxy ports only.

The plugin owns local listener settings (`allow-lan`, bind address, proxy ports, dashboard, TUN and DNS enable/listen). Additional subscription inbound listeners are removed. Proxy listeners remain on loopback. TUN uses `tun_mihomo`, with gVisor, automatic routes, and DNS hijack only while transparent routing is enabled. The dashboard is bound to a specific IPv4 address with a persistent secret. Blank secret input preserves the existing secret.

The four installation-specific settings are DNS at `127.0.0.1:1053`, the dashboard address, UI path plus persistent secret, and TUN device `tun_mihomo`. Subscription proxy, group, and rule semantics remain unchanged. Fake-IP ranges outside `198.18.0.0/15` are rejected before enabling TUN to keep Unbound rebinding protection consistent.

## Failures and updates

Runtime state lives under `/var/db/os-mihomo/`, outside the package file list:

- `settings.json`: subscription URL, secret, controller address, device label, and policies; mode `0600`.
- `subscription.yaml`: complete provider configuration; mode `0600`.
- `config.yaml`: generated and validated effective configuration; mode `0600`.
- `dns-state.json`, `tun-state.json`: the original DNS values and ownership records needed for restoration.

Failed parsing or core validation does not replace these files or restart the running service. A failed restart restores the previous configuration and secret; if the old service cannot restart either, direct DNS remains restored and status reports the failure. State transitions are serialized by an OS file lock, including UI edits, update application, WAN hooks, and the watchdog. Downloads hold a separate update lock, allowing crash recovery during network waits. Configd queues updates; the UI displays their separate completion status.

DNS fallback defaults to enabled and is configurable per router. On a core crash, Unbound permits fallback and a watchdog restores the original DNS configuration, including existing DNS-over-TLS entries, within its five-second polling interval plus service reload time. Explicit Stop always restores original DNS before stopping the core. No script edits `/etc/resolv.conf` or deletes OPNsense's `dot.conf`.

Stop persists the administrative service state, so WAN events and reboot do not undo it. WAN events only restart an already-running service. Package upgrades preserve configuration, secret, service state, and transparent-routing policy. A new pre-install hook saves legacy package-owned configuration before the old removal hook runs. Known local workaround scripts are archived in `migrate/` and their old entry points are retired. Uninstall restores DNS and removes only plugin-created interface and firewall entries; state is retained for recovery, and a later fresh installation resets transparent routing to off.

Subscription HTTP 4xx responses stop immediately, including 408 and 429. Only timeouts and HTTP 5xx permit retry and SOCKS5 fallback, with at most four requests per run. TLS, DNS lookup, and other failures are not retried. The URL is supplied through a mode-0600 curl configuration file rather than process arguments. Diagnostics never include the subscription URL, response body, or dashboard secret. An unwritable log does not prevent an update. Historical subscription logs are discarded during initial migration because older versions logged credentials.

The User-Agent is `OPNsense-Mihomo/1 (device-label)`. Its format version stays fixed across software upgrades. Passwall-Sub-Panel uses case-insensitive substring matching in rule order; a dedicated `OPNsense-Mihomo/1` rule must precede its generic `mihomo` rule if separate fleet permissions are wanted. See [design and verification](DESIGN.md).

Schedule updates under **System → Settings → Cron**, selecting **Renew mihomo Subscription**. UI, configd, `/usr/bin/mihomo_sub`, and `sub/sub.sh` all reach the same manager.

## Build and inspect

On FreeBSD 15 / OPNsense with `pkg`, `tar`, `xz`, `sha256`, `curl`, Python 3.13, and `py313-pyyaml` installed:

```sh
cd src/os-mihomo
make package
pkg info -F dist/os-mihomo-1.1.0.pkg
```

The bundled archive is `src/usr/local/bin/clash-meta-freebsd-amd64.xz`, from [Vincent-Loeng/clash-meta](https://github.com/Vincent-Loeng/clash-meta). The build uses that exact asset and performs no compilation or download. FreeBSD 14 and universal ABI packages are deliberately unsupported.

Run failure and lifecycle tests without changing host services:

```sh
python3 -m unittest discover -s tests -v
```

See the root [deployment guide](../../DEPLOYMENT.md) for signing, Pages publication, and the production installation window.

## Credits

Based on [Opnwall/OPNsense-repo](https://github.com/Opnwall/OPNsense-repo), [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo), and the FreeBSD binary from [Vincent-Loeng](https://github.com/Vincent-Loeng/clash-meta). This plugin is maintained independently and is not an official OPNsense plugin.
