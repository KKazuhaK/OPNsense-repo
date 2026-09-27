# WAN Guard for OPNsense

`os-wanguard` watches the DHCP interfaces you select and re-requests their IPv4
lease while they hold an address you do not want. It is meant for ISP gateways
in IP passthrough or bridge mode that first hand the router a **private** lease
from their own LAN and only later the public one, typically after the gateway
reboots. Left alone, the router keeps the private lease for its whole lease
time, and inbound access, dynamic DNS and IPv6 stay broken until it expires.

| | |
| --- | --- |
| Plugin version | `1.0.0` |
| Target | OPNsense 26.7, `FreeBSD:15:amd64`, Python 3.13 |
| Menu | **Services > WAN Guard > Settings**, **Services > WAN Guard > Log File** |

The package contains no native executable, so one build serves every amd64
ABI; the install hook still refuses anything but FreeBSD 14, 15 or 16 on amd64.

## Why not "Reject Leases From"

The interface option **Reject Leases From** becomes a `reject` statement in
`dhclient.conf`, and that statement matches the DHCP **server identifier**, not
the offered address. Some gateways send both leases with the same identifier.
An AT&T BGW whose LAN was moved to `172.31.254.254/24` hands out its private
lease and the public passthrough lease both from `172.31.254.254`, so rejecting
that server rejects the public lease as well. FreeBSD's `dhclient.conf` has no
statement that rejects an offered address, so the choice has to be made after
the lease is bound.

## What it does

- It looks at every watched interface about every 30 seconds, and within a
  second or two of that interface's `newwanip` event.
- An address is **unwanted** when it falls inside one of the configured
  networks, or, when **Private ranges are unwanted** is on, inside any private
  (RFC 1918), shared (`100.64.0.0/10`) or link-local range.
- It acts only after two unwanted observations at least 20 seconds and at most
  about a minute apart; after a longer pause, such as a service restart, the
  confirmation starts over.
- Acting means restarting the IPv4 DHCP client of that one interface through
  core's own `interface_dhcp_configure()` after setting the client's lease
  memory aside, so the new client starts with a DHCPDISCOVER and the gateway
  chooses the address. Kept, the memory would make the client ask for the same
  private lease again. The discarded copy is kept in `/var/db/os-wanguard/` for
  diagnosis.
- While the address stays unwanted, retries wait at least 1, 2 and 5 minutes,
  then 15 minutes each. Any two actions on one interface are at least a minute
  apart, and no interface sees more than eight in an hour, even when its
  settings change in between. A wanted address resets the schedule.
- DHCPv6, `rtsold`, prefix delegation and every other interface are left
  alone: the call that restarts the IPv4 client touches nothing else, unlike
  **Interfaces > Overview > Reload**, which flushes and rebuilds both address
  families.

**What each retry costs.** The old address stays on the interface until the
new lease binds, so traffic keeps flowing while the new client negotiates, as
long as nothing rebuilds the routing table in those seconds: the new client
clears the interface's DHCP router when it starts and sets it again when the
lease binds. Every retry ends in a new binding, even when the gateway hands
back the same private address, and each binding runs core's normal
new-address handling: the firewall rules and routes are reloaded, and every
service that reacts to a new WAN address, such as Unbound, OpenVPN, WireGuard
or os-mihomo, is reloaded or restarted. While the gateway keeps handing out
the private address, that happens up to seven times in the first hour and
four times an hour after that.

## Settings

| Setting | Default | Meaning |
| --- | --- | --- |
| Enable | off | A disabled plugin runs nothing and never acts. |
| Interfaces | `wan` | Only enabled interfaces whose IPv4 type is DHCP can be chosen, and never the LAN. If WAN is not DHCP, deselect it before saving. |
| Unwanted networks | empty | IPv4 networks with a prefix of `/8` or longer, at most 32. Host bits are rejected. |
| Private ranges are unwanted | off | See the warning below. |

With nothing listed and the switch off, nothing is unwanted and the page says
so. Apply saves the settings and starts, stops or wakes the service; a running
service picks up new settings at its next observation, within about a second,
and keeps its rate limits.

For the AT&T case above:

- **Interfaces**: `WAN`
- **Unwanted networks**: `172.31.254.0/24`
- **Private ranges are unwanted**: off

**Leave Private ranges are unwanted off behind CGNAT.** An ISP that hands out
`100.64.0.0/10` addresses would make the plugin retry every 15 minutes forever.
Turn it on only where the router normally gets a public address.

Settings live in `config.xml` under `OPNsense/wanguard/general`, so every
configuration backup and history revision carries them.

## Status and log

The page lists each watched interface with its current address, a state, the
number of attempts since the last reset, the last action with its time, trigger,
reason and result, and when the next retry may happen. It refreshes every ten
seconds.

| State | Meaning |
| --- | --- |
| OK | The address is wanted. |
| No IPv4 address | Nothing to judge. |
| Unwanted, confirming | Seen once; waiting for the second observation. |
| Unwanted, waiting to retry | Acted; the next retry waits for the backoff. |
| Unwanted, hourly limit reached | Eight actions in the last hour. |
| Unwanted, no carrier | The link is down; nothing is done until it returns. |
| Unwanted, no DHCP client | No IPv4 DHCP client is running. The plugin restarts one only if its own action stopped it; otherwise it waits. |
| Ignored | The interface is the LAN or not an enabled DHCP interface. |
| Waiting for boot to finish | Observations only while the system boots. |
| Disabled | The plugin is disabled. |
| Service stopped | The plugin is enabled but its service is not running. |

**Retry now** asks for an immediate re-request on an interface whose address is
unwanted. It skips the confirmation and the backoff but never the one-minute gap
or the hourly cap.

The first unwanted observation, every action (one line before it and one with
its result), every reset, every manual retry and every refusal are written to
`/var/log/wanguard/`, shown under **Services > WAN Guard > Log File**.

## Safety

- The plugin never acts on a wanted address, a missing address, the LAN, an
  interface that is not an enabled DHCP interface, or one whose DHCP client is
  not running. The daemon checks this and
  the helper that performs the action checks it again, together with the
  address the decision was based on: if the address changed in between, it
  does nothing.
- Nothing is done while the system boots or while the link has no carrier.
- If the old DHCP client does not stop within ten seconds, nothing else is
  changed. If the new one does not start, it is started once more, and after
  that a repair is attempted at most every five minutes. The plugin never
  repairs a client it did not stop.
- Stopping the service (Apply with Enable off, an upgrade, an uninstall)
  starts no new action; one already under way finishes first, within a minute.
- Only the daemon performs actions. The `newwanip` hook and **Retry now** only
  leave a request for it; no API endpoint or configd action reaches the helper
  directly.
- Its state, including the rate limits, survives a daemon restart and a
  package upgrade in `/var/db/os-wanguard/state.json`. It is discarded at
  reboot. A damaged state file is set aside and holds automatic actions for
  five minutes.
- Uninstalling stops the daemon and leaves the DHCP clients running. The
  settings stay in `config.xml`, so a reinstall finds them.

If the watched WAN belongs to a gateway group, a retry that briefly rebinds the
lease can trigger gateway monitoring or a failover; the backoff limits how often.

## Build and test

Build on FreeBSD or OPNsense:

```sh
./build.sh
pkg add -f dist/os-wanguard.pkg
```

From the repository root:

```sh
python3 -B tests/run.py --package os-wanguard
```

On an OPNsense 26.7 test host, `--native` also runs the real model validation,
the parity of the private ranges with core's `is_private_ipv4()`, the check
that every function the helper and the plugin hook call exists, and a
read-only check that the helper sees each interface exactly as core does:

```sh
python3 -B tests/run.py --native --package os-wanguard
```

Do not enable the plugin on a test host whose own uplink is DHCP.
