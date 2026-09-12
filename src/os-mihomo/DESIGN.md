# Runtime contract and verification

## Configuration and installation

The independent fork targets FreeBSD 15 amd64. One manager controls package boot, rc service actions, configd, UI, subscription cron, WAN changes and watchdog recovery. Root-only state lives in `/var/db/os-mihomo/`, including the generated config, original subscription, settings, merge YAML and runtime home. Packaged GeoIP data and mode presets live in `/usr/local/share/mihomo/`. No new package file or runtime dependency lives under the legacy asynchronous deletion target `/usr/local/etc/mihomo/`.

Every installation and upgrade resets transparent activation to false and starts ordinary proxy ports. Legacy subscription YAML, URL, dashboard secret and known cron timing survive. Migration extracts only known cron fields from the master configuration, then deletes its temporary migration data. It never creates another master secret-store copy.

Candidates pass through subscription → optional four-key router DNS overlay → local merge YAML → activation gate and enforced invariants → actual core validation. Nonempty mappings deep-merge, empty mappings clear, plain lists/scalars replace, and six prepend/append extensions modify rules, proxies and groups. No script layer executes. Presets select full, TUN-only and proxy-only defaults; per-router controller addresses belong in the merge. Code owns `tun_mihomo`, the stored secret and exclusion of port 53 from every supported listener.

Configuration mutations and watchdog transitions share an advisory lock. Subscription network waits release that lock. A downloaded response is discarded if its URL or device changed during the fetch; other policy changes use their latest values. The core validates private candidates before applying them. Hard-link backups restore source, config, merge and settings on restart failure. Validator diagnostics are captured because they may contain credentials.

## Routing, DNS and recovery

Start checks the proxy port, actual TUN and installed route before DNS takeover. TUN failure causes startup rejection and rollback. Full mode forwards Unbound to the private Mihomo DNS listener after readiness. TUN-only leaves DNS integration disabled. The router DNS switch instead keeps Unbound on its original upstreams and never forwards Unbound back into Mihomo.

The switch supplies exactly nameserver, proxy-server-nameserver, default-nameserver and empty nameserver-policy before the administrator merge. Literal IPv4/IPv6 upstream addresses come from generated DoT configuration, with ownership snapshots recovering temporarily disabled original entries. Host CIDR DIRECT rules and port 853 DIRECT precede administrator and provider rules. A watchdog detects upstream changes and refreshes these pins. A required resolver failure rejects startup; provider fallback must be explicitly removed. Enhanced mode, hijacking and Unbound AAAA policy are not changed by the switch.

The supported client scope is IPv4. An enabled RA/DHCPv6 service with disabled Mihomo IPv6 blocks router DNS activation and causes a visible warning if configured later. Full IPv6 validation is a separate deployment task. No global AAAA suppression is performed.

Auto-route also captures router-originated traffic, including firmware checks, NTP, monitoring and subscription traffic. Review provider rules for their effect on the whole LAN, and scope router exceptions in merge YAML. Preset TUN MTU is 1420 and remains configurable. The bundled FreeBSD core uses FIB 2022; the deployment must provide enough FIBs and gateway reachability in that table. Startup refuses to proceed when the actual TUN route is absent rather than modifying system tunables silently.

Every core crash destroys TUN and its routes, independently of DNS policy. Original Unbound DNS restoration defaults on and is configurable per router. Explicit Stop persists administrative disablement first, stops the core/TUN even if DNS restoration fails, and leaves pending restoration available for retries. WAN events cannot undo Stop. Native Unbound configuration lock/save APIs and configd reload actions are used; ownership records restrict removal to plugin-created interfaces, firewall rules and forwarding entries.

## Subscription host source review

Reviewed Passwall-Sub-Panel `main` at commit `4c7b488a8b36ce98579a34624249ec68ac7d60fd`, without sending requests to the live subscription endpoint:

- [Client detection](https://github.com/KazuhaHub/Passwall-Sub-Panel/blob/4c7b488a8b36ce98579a34624249ec68ac7d60fd/internal/pkg/clientdetect/detect.go) lowercases UA and keywords and matches substrings. Families are evaluated in order; the first match wins. Whitelist mode requires a matched, enabled family.
- [Defaults](https://github.com/KazuhaHub/Passwall-Sub-Panel/blob/4c7b488a8b36ce98579a34624249ec68ac7d60fd/internal/adapters/sqlstore/settings_kv_repo.go) put `Clash / mihomo` first, with `clash`, `mihomo`, and `meta` keywords. The proposed UA matches `mihomo`. A dedicated `OPNsense-Mihomo/1` keyword must be ordered before this family to give the fleet separate permissions; a device-specific substring is only needed for per-device policy.
- [Request handling](https://github.com/KazuhaHub/Passwall-Sub-Panel/blob/4c7b488a8b36ce98579a34624249ec68ac7d60fd/internal/transport/http/handler/sub.go) advances blocked-client violations for a valid, accessible user, with a ten-minute deduplication window. Default threshold is 3, configurable globally and by group; reaching it suspends service only when automatic disabling is enabled. Initial blocked-client requests return 403; disabled service and invalid/unavailable tokens return opaque 404.
- [Counter persistence](https://github.com/KazuhaHub/Passwall-Sub-Panel/blob/4c7b488a8b36ce98579a34624249ec68ac7d60fd/internal/adapters/sqlstore/user_repo.go) increments the stored counter without time decay. [Service restoration](https://github.com/KazuhaHub/Passwall-Sub-Panel/blob/4c7b488a8b36ce98579a34624249ec68ac7d60fd/internal/service/user/user.go) clears it when restoring a blocked-client suspension. An allowed request does not reset it.

These are source-level conclusions; deployed panel settings and deployed revision were not probed. The UA's `/1` is a stable format version, independent of package version. Requests retry only timeout/5xx and never 4xx; even 408 and 429 stop immediately. Curl configuration holds the private URL outside process arguments, and no response body or URL is logged.

## Verification boundaries

Python regression tests cover merge semantics, all modes, upgrade policy, Unicode subscription preservation, D1 exact-endpoint and log privacy, bounded HTTP retries, concurrent updates, rollback, native command errors, PID reuse, port collisions and DNS/TUN teardown. PHP syntax validation includes both `.php` and shipped `.inc` files. Tests using PHP fixtures run on the FreeBSD build host without skips.

The tracked VNET jail harness executes real `pkg upgrade` from the unmodified published 1.0.2 package, its old hooks and delayed deletion, the bundled core validator/daemon, real TUN and split routes, a real Unbound resolver, SIGKILL watchdog recovery, failed configd Stop, disabled-mode cleanup and fresh package installation. Its synthetic configuration adapter saves only jail-local XML. Filter/template/configd calls use jail-local adapters: host PF, the production GUI and LAN clients are outside this test's scope.

A successful run writes a package-bound test report. The local signer refuses a package changed after that test, then signs the report with its source commit. Pages verifies the signed report, reruns tests against that commit and compares archived runtime files and lifecycle hooks with the source. Protected main requires the source `validate` status. Legacy packages are retained and catalog-signed but do not inherit the new release's test claim.

Production installation, dashboard authentication, real OPNsense filter/template output and LAN connectivity require a maintenance window. A jail test is evidence for the exercised lifecycle, not certification of those remaining paths. See [deployment](../../DEPLOYMENT.md).

## Completed release checks, 2026-09-12

The FreeBSD host passed 39 Mihomo regression tests without skips and the Sing-box direct-subscription regression. Twelve real VNET lifecycle checks passed; SIGKILL to DNS restoration and TUN removal measured 3.666 seconds inside the jail. Twelve candidates from the existing provider configuration passed native core validation with nodes, groups and original rules retained.

[Source validation](https://github.com/KKazuhaK/OPNsense-repo/actions/runs/34698294252) and [Pages validation/deployment](https://github.com/KKazuhaK/OPNsense-repo/actions/runs/34698388713) passed for the published source revision `3137bbdd34f15f65de69589e75f7b3bfcf3caf20`. The [signed release report](https://kkazuhak.github.io/OPNsense-repo/release.json) identifies Mihomo 1.1.1 SHA-256 `0b969f1fae6670a05a69766bd9fd43bc6ba5aa85ab838599fd5e7f2421d6040a` and Sing-box 1.0.3 SHA-256 `b12ae1666e7f720461f9c666256595e3a27720d8e015a701cf1157283641fac5`.

All 27 catalog-listed packages downloaded from public Pages passed independent signature/digest verification; 29 legacy package/catalog URLs remained accessible. A separate FreeBSD pkg configuration/database/cache accepted the signed HTTPS catalog and fetched both current packages with the same digests using IPv4. Production remained on Mihomo 1.0.2 with its original process and TUN. Real GUI, PF and LAN checks still require the maintenance window.
