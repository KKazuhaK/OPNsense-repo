# Build, sign, and publish

Only **FreeBSD:15:amd64** and `os-mihomo` are published. The source branch does not track `repo/`, package output, or catalogs. Existing binary history is left intact; newly generated artifacts live on a replaceable `gh-pages` branch and are deployed through the Pages workflow.

The RSA private key remains on the local signing router at `/root/pkgsign/kazuha-repo.key`, mode `0600`. GitHub receives signed catalogs, public key, packages, and static assets. No private-key GitHub Secret is required.

## Build on FreeBSD

Copy the source checkout to a FreeBSD 15 / OPNsense build host, excluding `.git`, local AI files, private material, previous build output, and repository artifacts. The build requires the bundled binary archive, Python 3.13, `py313-pyyaml`, `curl`, `pkg`, `tar`, `xz`, and `sha256`.

```sh
cd src/os-mihomo
sh build.sh
cd ../..
SIGNING_KEY=/root/pkgsign/kazuha-repo.key \
  sh build-repo.sh src/os-mihomo/dist/os-mihomo-1.1.0.pkg
python3 verify-repo.py .site
```

`build-repo.sh` generates this independent deployment tree:

```text
.site/
  index.html
  kazuha.pub
  kazuha.conf
  opnwall.conf
  SHA256SUMS.txt
  repo/FreeBSD:15:amd64/
    meta.conf
    data.pkg
    packagesite.pkg
    All/os-mihomo-1.1.0.pkg
```

`opnwall.conf` is a compatibility download name; its content configures the signed `kazuha` repository. No unsigned upstream repo is deployed by this fork.

`verify-repo.py` checks the pinned public-key fingerprint, the primary and compatibility catalog RSA signatures, the package name/ABI/path, and its SHA-256 digest. Do not use `pkg update` exit status alone as proof of signature acceptance: pkg 2.3.1 can return zero while reporting an invalid signature and removing the catalog.

## Publish from the Mac

Copy only `.site/` back from the signing host. Do not copy the private key. Then run:

```sh
python3 verify-repo.py .site
sh publish-repo.sh
```

The publisher uses the existing Git user identity. It creates a new orphan `gh-pages` commit containing generated artifacts, the verification script, and the Pages workflow. A force-with-lease replaces that generated branch so successive package binaries do not form a growing branch history. `main` is never force-pushed. GitHub garbage collection determines when unreachable prior deployment objects are removed.

Enable GitHub Pages with **GitHub Actions** as its build source. The workflow rechecks signatures and digests and uploads an explicit static asset list. The URL is:

[https://kkazuhak.github.io/OPNsense-repo/](https://kkazuhak.github.io/OPNsense-repo/)

The repository is privately maintained and signed; Pages downloads remain publicly accessible. Client `pkg` requires the complete Pages directory tree, rather than flat Release attachment URLs.

## Add the trust anchor to a router

Follow the fingerprint-checked installation commands on the [repository front page](index.html). The repo configuration uses `signature_type: "pubkey"`, `/usr/local/etc/pkg/keys/kazuha.pub`, and priority 10. Remove the old unsigned `opnwall.conf` client configuration before selecting the new repository.

Installing a repo configuration and querying its catalog does not require installing or restarting the plugin. Install or upgrade `os-mihomo` from **System → Firmware → Plugins** during the router's maintenance window.

## Production installation window

The designated test router is the household's only gateway. A package upgrade stops the old core and temporarily changes DNS and routes. The final live install requires a scheduled window even after isolated checks have passed.

Before installation, keep an offline copy of the old package, configuration backup, subscription YAML, subscription settings, and local workaround scripts. The new pre-install hook migrates legacy package-owned config before the old pre-deinstall hook removes it. Do not run the archived old repair script after upgrading; the new state manager replaces its purpose.

Within the window, verify:

1. The existing configuration, secret, rules, and transparent-routing policy survive the upgrade.
2. Proxy-only mode has no TUN routes or DNS takeover; Start and WAN changes keep that policy.
3. Transparent enablement starts the core/DNS listener before redirecting Unbound. Test connectivity from both the router and LAN clients.
4. Explicit Stop restores original DNS-over-TLS configuration and removes runtime TUN routing. WAN events do not undo Stop.
5. A controlled core crash follows the router's selected fallback policy, with DNS recovery measured from a LAN client.
6. A successful subscription update preserves node/group/rule semantics and dashboard authentication; an invalid candidate leaves the previous active config intact.

If the test fails, `pkg delete os-mihomo` restores plugin-managed DNS and removes plugin-created interface/firewall configuration. User state is retained in `/var/db/os-mihomo/` for recovery. Restore the offline legacy package and its archived local scripts only if returning to the old version is required. Never remove `/var/unbound/etc/dot.conf` as part of recovery.

The local isolated checks do not certify LAN connectivity through a secondary router or its DNS rebinding protection. Those checks remain part of the scheduled window.
