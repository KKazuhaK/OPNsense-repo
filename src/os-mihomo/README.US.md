# os-mihomo
Native OPNsense configuration backups include Mihomo settings and credentials, the original subscription and merge YAML, local `type:file` rule and proxy-provider files, proxy-group choices, and interface/DNS ownership journals. Restore preserves the service enabled state and turns transparent routing and consent off; the operator explicitly enables transparent routing again. See [configuration backup and restore](../../CONFIG-BACKUP.md).


An independently maintained Mihomo integration for OPNsense CE, currently validated on 26.7 / FreeBSD 15 amd64. Committed recipes parameterize future targets.

Fresh installation and unrecognized legacy migration run ordinary local proxy ports only. A validated subscription and explicit activation are required for TUN. Once 1.1.2 establishes managed state, subsequent upgrade/reinstall preserves explicit TUN consent and administrative Stop. Legacy migration preserves the subscription URL, full YAML, secret and cron timing, but never inherits transparent enablement.

Use **VPN → Proxy Suite** for service controls, subscription settings and the local merge editor. Runtime state is root-only under `/var/db/os-mihomo/`; static GeoIP data and presets are under `/usr/local/share/mihomo/`. Nothing depends on `/usr/local/etc/mihomo/`, which legacy packages delete asynchronously.

## Configuration

The configuration pipeline is:

```text
complete subscription YAML
  → router DNS overlay, if selected
  → /var/db/os-mihomo/merge.yaml
  → enforced invariants and activation gate
  → mihomo -t validation
  → transactional application
```

Mappings deep-merge; scalars and plain lists replace. Empty mappings clear the existing mapping. `prepend-rules` / `append-rules`, `prepend-proxy-groups` / `append-proxy-groups` and `prepend-proxies` / `append-proxies` extend lists. Appending after a provider `MATCH` rule will not change its priority. No JavaScript/script execution layer is supported.

Three YAML presets are shipped: `full.yaml` (TUN and real-address DNS), `tun-only.yaml` (TUN without Mihomo DNS interception), and `proxy-only.yaml`. Loading a preset replaces the entire merge file; preserve custom content first. The initial merge uses full-mode defaults, with activation gated off. The authenticated dashboard initially binds all interfaces; its settings switch can restrict it to loopback. Default TUN MTU is 1420; adjust it to the smallest effective node transport MTU.

TUN activation with the currently bundled FreeBSD core supports only `gvisor`. Its `system` and `mixed` TCP paths incorrectly classify traffic as broadcast, so the plugin rejects transparent routing with either stack; select gVisor before enabling it. This restriction applies to the bundled core and requires fresh validation for a future core.

The gVisor stack keeps at most 20 KB of each TCP connection in flight, so a single connection runs at about 20 KB per round trip: a few tens of Mbps for a Wi-Fi client even when the rule is `DIRECT`. **Fast TCP path** (off by default) sends new IPv4 TCP from the selected sources to a core listener on `127.0.0.1:7894` through a PF redirect instead, so the kernel's TCP stack carries it; on a test bench a single connection at 18 ms went from 8 Mbps through the TUN to about 1 Gbps. The core still sees the original destination, so rules, the sniffer and node selection are unchanged; its connections show the inbound `opnsense-transparent-tcp` instead of TUN. UDP including QUIC, TCP to port 53 (for the DNS hijack) and IPv6 stay on the TUN. The redirect is used only while the running core owns that listener and the filter has loaded the plugin's `rdr-anchor`; otherwise TCP stays on the TUN, and the status shows why. Stopping the service or losing the core removes the redirect and its connections. Firewall rules see redirected TCP as addressed to `127.0.0.1` port 7894. Rules that block a destination host or port no longer act on captured TCP; pass rules limited to destination hosts or ports no longer match it, so it falls to the default block; a rule blocking access to the firewall itself blocks it. A LAN rule that sets a gateway still matches and routes the redirected connection toward that gateway, where it is lost. Before enabling the fast path, place a rule without a gateway that passes TCP from the captured sources to `127.0.0.1` port 7894 above any such rules, or keep those sources out of capture.

Device policy selects TCP/UDP by LAN source address before traffic enters TUN. A blacklist bypasses the listed sources; a whitelist sends only the listed sources' TCP/UDP through TUN. Off or an empty list sends all eligible LAN sources' TCP/UDP through TUN. ICMP and other control traffic use ordinary routing. Bypassed devices keep their existing routing without using Mihomo's `DIRECT` transport. Traffic selected for TUN then follows subscription and merge rules. Existing firewall pass/block rules and user routing policies still apply. Router-originated traffic and incoming WAN traffic are excluded. With normal stateful firewall/NAT rules, replies for established DNAT connections follow their existing state and correctly configured return routes. Device selection does not restrict clients configured to use HTTP/SOCKS proxy ports explicitly. **Capture interfaces** limits transparent routing to the selected internal interfaces; leaving it empty keeps the earlier behaviour of using every one. An interface counts as WAN-like, and is never captured or offered, when it is the WAN or OPNsense resolves a gateway for it, which covers every uplink of a multi-WAN setup, PPPoE links and VPN exits with a gateway. Select a bridge rather than its member ports, and assign a VPN server's tunnel as an interface before selecting it. The device policy then applies within the selected interfaces, and traffic to any local network still bypasses TUN.

The plugin disables the core's `auto-route` and selects LAN traffic with a separate source policy, avoiding TUN routes that take over public destinations in the normal routing table. Its private routing table retains the system's WAN and VPN routes. Gateway routes explicitly retain their outgoing interface, including WireGuard routes whose gateway is not directly reachable in a fresh routing table. Selection follows IP addresses: use stable addresses or DHCP reservations and cover every address a device actually uses. IPv4 remains the supported client scope; IPv6 needs separate end-to-end validation, and private-jail IPv6 checks do not establish end-to-end client support. Before deployment, exercise blacklist, whitelist, empty lists, user block rules and custom routing policies. The fix still requires acceptance on the target native system.

Multi-WAN DNAT return routing remains administrator-maintained and requires correctly configured system WAN return routes. The plugin does not rewrite NAT, WAN gateways or `reply-to`, and does not repair an existing incorrect return path. Connections requiring a fixed return WAN need the correct stateful WAN rule and `reply-to`. Inline NAT **Pass** skips subsequent filter rules; **Register rule** needs a correctly configured WAN gateway and `reply-to` enabled globally and on the rule for its default return binding. See the official [NAT association](https://docs.opnsense.org/manual/nat.html#filter-rule-association), [WAN reply routing](https://docs.opnsense.org/manual/firewall.html) and [Disable reply-to](https://docs.opnsense.org/manual/firewall_settings.html#disable-reply-to) documentation. Inspect routes, effective PF rules and states, and capture new connections on WAN, LAN and TUN. Existing connections may retain old states after a policy change; remove only affected states if necessary, never the complete state table. Commands and examples are in [DEPLOYMENT.md](../../DEPLOYMENT.md).

Transparent routing requires DNS answers with real addresses. `redir-host` is the default and recommended mode; `normal` is also supported. Devices bypassing TUN cannot rely on Mihomo to handle fake-IP placeholders. Legacy `fake-ip` may remain saved while transparent routing is off. Enabling transparent routing or applying configuration while it is active converts an effective `fake-ip` mode, including a merge override, to `redir-host` and saves that choice in settings. Bypassed devices keep their existing DNS path; shared resolvers must also return real addresses. Existing fake-IP caches may need clearing or time to expire.

The code enforces `tun.device: tun_mihomo`, the stored dashboard secret and valid listener ports excluding 53, including extra listeners and the controller. Merge YAML cannot bypass the TUN activation gate or the real-address DNS requirement. DNS forwarding integration is provided for `127.0.0.1:1053` when Mihomo DNS is enabled; custom listeners remain administrator-managed.

## Resolve through router DNS

This switch defaults off. It supplies exactly these DNS keys before the local merge:

```yaml
dns:
  nameserver: [127.0.0.1]
  proxy-server-nameserver: [127.0.0.1]
  default-nameserver: [127.0.0.1]
  nameserver-policy: {}
```

The switch itself leaves `dns-hijack` and Unbound AAAA policy unchanged; transparent routing separately enforces real-address DNS. Other merge overrides remain explicit administrator choices. Provider fallback servers must be removed before activation; an unavailable local resolver fails startup rather than reverting to provider DNS. Unbound is never redirected back into Mihomo when this switch is selected.

Manual DNS fields accept Mihomo URLs. The **Override subscription DNS** switch controls whether their nonempty values replace the matching fields in the generated runtime configuration; switching it off keeps the values for later use and restores subscription DNS immediately. The stored subscription YAML is never rewritten, and router DNS takes priority while selected. Mihomo uses the first token after `#` as a proxy or interface, while Unbound uses `IP@port#hostname` for a TLS verification name. To keep copied Unbound endpoints from failing later with `interface not found`, the plugin normalizes `tls://IP#long.hostname` in Nameservers and Proxy node servers to `tls://long.hostname`; short interface selectors such as `#vtnet1` and `#RULES` remain unchanged. Bootstrap servers still require a literal IP, so the same copied form is stored there as its IP endpoint and the normalized hostname field performs the encrypted queries without a dependency loop.

IPv4 and IPv6 forwarding addresses are read from the router's generated DoT configuration; saved ownership state recovers original upstreams during a transition out of Mihomo DNS forwarding. Host routes and `DST-PORT,853,DIRECT` precede subscription and merge rules. The watchdog refreshes them when upstream addresses change. This avoids routing Unbound's own DNS transport through a node whose hostname it must resolve.

Startup records a local fingerprint of system DNS written by the core. After a crash, native OPNsense DNS regeneration restores system resolution and retries on failure. Later operator edits or explicitly configured DNS are preserved. This temporary recovery record is excluded from XML backups.

The current supported deployment scope is IPv4 clients. When resolve-through-router-DNS is selected, RA or DHCPv6 advertisement with disabled Mihomo IPv6 causes activation refusal and a visible runtime warning if enabled later. The plugin does not suppress AAAA or configure RA/DHCPv6. With Mihomo IPv6 disabled, native IPv6 traffic bypasses TUN. Validate IPv6 end to end before enabling IPv6 proxying for clients.

## Recovery and subscriptions

Every core crash removes the plugin's transparent capture policy and TUN routes. Automatic restoration of original Unbound DNS is enabled by default and configurable per router. Disabling DNS recovery leaves proxy DNS forwarding in place after a crash, while capture is still removed. Explicit Stop always stops the core and removes transparent capture even if DNS restoration fails; its pending restoration is retried, and a WAN event never revives an administratively stopped service. The service starts at boot unless it was stopped; OPNsense never runs `rc.d/mihomo` itself, so a start hook does it. Only address changes on WAN-like interfaces restart the core, and IPv6 renewals are ignored while Mihomo IPv6 is off, so DHCPv6 renewals no longer reset proxied connections. Disabling removes only plugin-created interfaces, policies and routes, without flushing the firewall state table.

Subscriptions are fetched directly with `OPNsense-Mihomo/1 (device)`. HTTP 4xx never retry or use fallback; only timeout/5xx permit at most two direct and two proxy attempts. The URL stays in a private curl file, outside command arguments and logs. The UI does not send the stored URL back as HTML. Updates preserve proxy/group/rule semantics and dashboard credentials. CLI `/usr/bin/mihomo_sub`, configd and cron use the same manager.

## Build and publish

Run `sh build.sh` on the recipe's native FreeBSD / OPNsense target with matching Python, PyYAML and curl. Current 26.7 uses `python3.13` / `python313` and produces `dist/FreeBSD:15:amd64/os-mihomo-1.3.0.pkg`. `TARGET_ABI`, `TARGET_PRODUCT_ABI` and `TARGET_PYTHON` can be explicit; the actual kernel, userland, dependencies and interpreter must match. Runtime Python entry points and product annotations follow the target. Bytecode is excluded and rejected in staging and archives. See [deployment](../../DEPLOYMENT.md) for per-target native tests, signed dependency setup and publication. Pages reruns the signed report's source tests and compares package content with that revision.
