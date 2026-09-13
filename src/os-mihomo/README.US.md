# os-mihomo

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

Three YAML presets are shipped: `full.yaml` (TUN and fake-IP DNS), `tun-only.yaml` (TUN without Mihomo DNS interception), and `proxy-only.yaml`. Loading a preset replaces the entire merge file; preserve custom content first. The initial merge uses full-mode defaults, with activation gated off. The dashboard initially binds loopback; configure this router's dashboard address in merge YAML. Default TUN MTU is 1420; adjust it to the smallest effective node transport MTU.

The code enforces `tun.device: tun_mihomo`, the stored dashboard secret and valid listener ports excluding 53, including extra listeners and the controller. Merge YAML cannot bypass disabled TUN activation. DNS forwarding integration is provided for `127.0.0.1:1053` when Mihomo DNS is enabled; custom listeners remain administrator-managed.

## Resolve through router DNS

This switch defaults off. It supplies exactly these DNS keys before the local merge:

```yaml
dns:
  nameserver: [127.0.0.1]
  proxy-server-nameserver: [127.0.0.1]
  default-nameserver: [127.0.0.1]
  nameserver-policy: {}
```

The switch leaves `dns-hijack`, enhanced mode and Unbound AAAA policy unchanged. Merge overrides remain explicit administrator choices. Provider fallback servers must be removed before activation; an unavailable local resolver fails startup rather than reverting to provider DNS. Unbound is never redirected back into Mihomo when this switch is selected.

IPv4 and IPv6 forwarding addresses are read from the router's generated DoT configuration; saved ownership state recovers original upstreams during a transition out of Mihomo DNS forwarding. Host routes and `DST-PORT,853,DIRECT` precede subscription and merge rules. The watchdog refreshes them when upstream addresses change. This avoids routing Unbound's own DNS transport through a node whose hostname it must resolve.

The current supported deployment scope is IPv4 clients. RA or DHCPv6 advertisement with disabled Mihomo IPv6 causes activation refusal and a visible runtime warning if enabled later. It does not suppress AAAA or configure RA/DHCPv6. Validate IPv6 end to end before enabling IPv6 for clients.

## Recovery and subscriptions

Every core crash removes runtime TUN routes. Automatic restoration of original Unbound DNS is enabled by default and configurable per router. Disabling DNS recovery leaves proxy forwarding in place after a crash, while routes still revert. Explicit Stop always stops the core and removes TUN even if DNS restoration fails; its pending restoration is retried, and a WAN event never revives an administratively stopped service. Disabling removes only plugin-created interface/firewall entries.

Subscriptions are fetched directly with `OPNsense-Mihomo/1 (device)`. HTTP 4xx never retry or use fallback; only timeout/5xx permit at most two direct and two proxy attempts. The URL stays in a private curl file, outside command arguments and logs. The UI does not send the stored URL back as HTML. Updates preserve proxy/group/rule semantics and dashboard credentials. CLI `/usr/bin/mihomo_sub`, configd and cron use the same manager.

## Build and publish

Run `sh build.sh` on the recipe's native FreeBSD / OPNsense target with matching Python, PyYAML and curl. Current 26.7 uses `python3.13` / `python313` and produces `dist/FreeBSD:15:amd64/os-mihomo-1.1.3.pkg`. `TARGET_ABI`, `TARGET_PRODUCT_ABI` and `TARGET_PYTHON` can be explicit; the actual kernel, userland, dependencies and interpreter must match. Runtime Python entry points and product annotations follow the target. Bytecode is excluded and rejected in staging and archives. See [deployment](../../DEPLOYMENT.md) for per-target native tests, signed dependency setup and publication. Pages reruns the signed report's source tests and compares package content with that revision.
