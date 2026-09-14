# Build, sign and publish

Maintained packages use committed OPNsense CE target recipes in `src/os-mihomo/packaging/targets.json`. The enabled target is **26.7 / FreeBSD:15:amd64 / Python 3.13**. The unannounced 27.1 target remains disabled. Source main excludes generated packages and catalogs; signed output lives on a replaceable gh-pages branch and Pages serves the full pkg repository tree. Legacy FreeBSD 14/15 downloads and Mihomo 1.0.2 remain available for compatibility and rollback. Unsafe Mihomo 1.1.0 is withdrawn.

The existing RSA signing key stays on the local signing host with mode 0600. GitHub receives signed catalogs, packages, a public key and a signed test report. No private key is uploaded or stored in GitHub Secrets.

## Build and exercise the real upgrade

Copy the clean source revision to the recipe's native build host, excluding local instructions, secrets, Git metadata and build output. Current 26.7 requirements include Python 3.13, PyYAML, PHP with DOM and SimpleXML enabled, curl, pkg, xz and the bundled assets. `MIHOMO_PYTHON` selects the build interpreter; its minor and patch must match the target and installed dependency. Python cache directories and `.pyc`/`.pyo` files are excluded and rejected in the final archive.

```sh
(cd src/os-mihomo && sh build.sh)
(cd src/os-sing-box && sh build.sh)
(cd src/os-kazuha-repo && sh build.sh)
python3.13 -B -m unittest discover -s src/os-mihomo/tests -v
python3.13 -B -m unittest discover -s src/os-sing-box/tests -v
sh src/os-mihomo/tests/jail/run.sh \
  src/os-mihomo/dist/FreeBSD:15:amd64/os-mihomo-1.2.3.pkg legacy-1.0.2.pkg
```

The harness requires root, VIMAGE, TUN and enough disk for its disposable filesystem. It creates an isolated VNET with synthetic upstreams and its own FIBs. It does not connect the jail to production interfaces. Its report identifies the exact package SHA-256 and executed checks. Test adapters replace OPNsense configd/filter/template/GUI infrastructure; actual package hooks, core, daemon, TUN, routes and Unbound are exercised. Remaining production checks are listed below.

## Sign the tested candidate

Preserve a local legacy repo tree for compatibility downloads. Use the exact clean tested source commit and package filenames:

```sh
SOURCE_COMMIT=<tested-40-character-commit> \
  LEGACY_REPO=/path/to/legacy/repo \
  sh build-repo.sh src/os-mihomo/dist/FreeBSD:15:amd64/os-mihomo-1.2.3.pkg \
    src/os-sing-box/dist/os-sing-box-1.1.1.pkg \
    src/os-kazuha-repo/dist/os-kazuha-repo-1.0.1.pkg
python3 verify-repo.py .site --source .
```

Each Mihomo package reads its adjacent `test-report.json`; `TEST_REPORT` remains an optional override for the first candidate. Supply every enabled target in one signing run. Reports bind the native kernel/userland ABI, native OPNsense series, Python, executed lifecycle checks and exact archive digest to the source commit. The signer rejects disabled, missing, duplicate and mismatched targets. Additional updated packages are digest-bound and source-checked. `os-kazuha-repo` contains only a shell hook, public key and metadata; its ABI-independent archive has no Python dependency. Legacy downloads have no new lifecycle attestation.

## Publishing any other plugin

Every plugin except Mihomo -- which keeps its own committed recipe in `src/os-mihomo/packaging/target.py` -- is published through a committed staging record in `packaging/plugins.json`. The record says which committed directory is staged where, which vendored artifact may be unpacked and under which pinned SHA-256, which files the build generates, the dependencies the manifest must declare, and the version this source publishes. `verify-repo.py` rebuilds the package from those records and compares inventory, per-file SHA-256, the bytes in the archive and all four lifecycle hooks. A plugin with no record, or a record marked `unsupported`, is refused; so is a vendored artifact whose committed digest no longer matches. Bumping a version means editing the record, the product version file and `build.sh` together. That product version file must be the JSON object OPNsense registers: `register.php` decodes every file under `/usr/local/opnsense/version` and skips any that does not decode or carries no `product_id`, which installs the package and then leaves it out of the configuration's plugin list for good -- never reinstalled by a firmware sync, never offered in the web interface. The verifier accepts no other format.

A version that is already published may never be republished with different content. `python3 verify-repo.py .site --audit --source .` lists every recorded plugin as unpublished, unchanged, rejected, or changed without a version bump, and `build-repo.sh` refuses the last of those.

What a package may contain is narrower than what a build can produce. A package is refused when its archive carries anything but plain files -- a symbolic or hard link has no per-file digest to compare -- when a member carries a setuid, setgid or sticky bit, when the manifest repeats a key (libpkg parses manifests with UCL, which need not resolve a repeated key the way this verifier does), when the manifest carries `lua_scripts`, `directories`, `config`, `users` or `groups`, which are machinery no staging record describes, or when `+COMPACT_MANIFEST` disagrees with `+MANIFEST`, since `pkg repo` copies the compact manifest into the signed catalog clients resolve from. Lifecycle hooks must be committed regular files under `src/<plugin>/packaging/freebsd/`; a symlinked hook is refused because its bytes are not in the repository. Staged file names are held to the same characters as install paths. A build may name its output file anything -- several `build.sh` scripts rename it -- because the release is published under the identity the manifest carries, not under the file name it arrives with.

Catalog creation scans an isolated `All/` tree for each target. This prevents recursive `pkg repo` scans from mixing nested series. Current 26.7 retains `repo/FreeBSD:15:amd64`; other series use `repo/ABI/SERIES` when dependencies differ. The repository hook selects these addresses using `opnsense-version -x`, rather than an unsupported pkg series placeholder.

Do not treat pkg update exit status alone as signature acceptance. Check that the expected usable catalog exists; some pkg versions return zero after rejecting a signature.

## Publish from a clean checkout

Copy only .site back from the signer, never the private key, and run:

```sh
python3 verify-repo.py .site --source .
sh publish-repo.sh
```

The publisher requires the report's source revision to equal the clean checkout, reruns regression tests and refuses private files. It uses the existing user Git identity, creates an orphan gh-pages artifact commit and replaces that branch with force-with-lease. Pages reruns tests from the signed source revision, PHP syntax including .inc, shell checks and package/source comparisons before deployment. Main requires a successful validate check. One authorized historical cleanup removed old package trees, local handoff files and AI trailers; ordinary source updates use protected main. GitHub caches, forks and unreferenced objects may retain earlier public material until separately purged.

Configure Pages to deploy with GitHub Actions. The [public endpoint](https://kkazuhak.github.io/OPNsense-repo/) supplies the hierarchy required by pkg, including legacy URLs. Flat Release attachments are not used as the pkg endpoint. opnwall.conf is not published; clients use the fingerprint-checked kazuha configuration on the front page.

## Production maintenance window

Keep an offline copy of the signed trust anchor, legacy package, configuration backup, source subscription, settings and local workaround scripts. The gateway's package upgrade stops its old core. It must be performed in a scheduled window even after the isolated lifecycle checks pass.

1. First migration from unrecognized legacy state starts proxy ports with TUN activation off; subscription, secret and cron are retained. Wait beyond the old delayed deletion before proceeding. Once managed state exists, ordinary upgrade/reinstall preserves explicit TUN consent and administrative Stop.
2. Check proxy-only behavior, controller login and WAN behavior. Configure this router's merge and validate it.
3. Explicitly enable the desired preset. Confirm native interface/firewall/template output and DNS readiness from router and LAN clients. Transparent mode requires real DNS answers: `redir-host` is the default, `normal` is supported, and effective legacy `fake-ip` is converted to `redir-host` and saved back to settings. Include merge overrides and shared resolvers in this check; clear or expire old fake-IP caches before testing bypass.
4. Exercise router DNS only after confirming its resolver and DIRECT transport. IPv6 client enablement requires separate end-to-end validation; do not suppress AAAA as a workaround.
5. Controlled core failure must remove the plugin's transparent capture policy and TUN routes and follow the local DNS policy. Measure recovery from a LAN client.
6. Stop must restore DNS and stop TUN; WAN must not revive it. Successful subscription update preserves credentials; invalid input preserves the prior service.
7. Verify TCP/UDP device selection before TUN entry with real LAN clients: blacklist-listed sources must stay outside TUN; a whitelist must capture only listed sources; off or an empty list must capture all eligible LAN sources. ICMP and other control traffic must use ordinary routing. Confirm bypassed clients use their existing routes and DNS rather than Mihomo `DIRECT`. Preserve and exercise user pass/block rules and explicit gateway policies. The core's `auto-route` is disabled; the plugin's source policy must leave public destinations in the normal routing table unchanged. Check the separate routing table's LAN, static and VPN return routes, including route changes. Router-originated traffic and incoming WAN traffic are excluded. With normal stateful firewall/NAT rules, replies for established DNAT connections must follow their existing state and correctly configured return routes. Native client acceptance remains scoped to IPv4; private-jail IPv6 checks do not establish end-to-end IPv6 client support. These are native acceptance checks, not claims established by source tests alone.
8. Multi-WAN DNAT return routing still requires correctly configured system WAN return routes and a stateful return binding where applicable. The plugin does not rewrite NAT or `reply-to` and cannot repair an existing incorrect return path. Inline NAT **Pass** skips subsequent filter rules; **Register rule** needs the correct gateway and `reply-to` enabled globally and per rule for its default return binding. For an example remote client `198.51.100.10` and DNAT target `192.0.2.10`, inspect `route -n get 198.51.100.10`, `pfctl -sr` and `pfctl -ss -vv`, and capture SYN/SYN-ACK on WAN2, LAN and `tun_mihomo`. Use new connections after rule or device-policy changes; if needed, remove only affected old states, never the complete state table. See [NAT association](https://docs.opnsense.org/manual/nat.html#filter-rule-association), [WAN reply routing](https://docs.opnsense.org/manual/firewall.html) and the [Mihomo configuration notes](src/os-mihomo/README.US.md).

On failure, delete the new plugin to restore owned DNS and remove owned configuration, then restore the offline legacy package and settings if necessary. User state remains in /var/db/os-mihomo. Do not run archived old repair scripts against the new manager, and do not delete generated Unbound dot.conf as a recovery action. Real PF policy routing, secondary-router rebinding protection and LAN connectivity remain production checks.

## Firmware release checklist

1. Read the official target release/build configuration. Update product ABI, native FreeBSD release, Python and repository together; do not guess the next ABI. Same-ABI dependency changes need a separate series directory.
2. Enable the complete target recipe, including the matching official OPNsense dependency repository and committed public signing fingerprint, bump the plugin package version or revision, and run **Build native firmware targets**. The default FreeBSD package flavor may lack the target Python/PyYAML pair; the isolated builder uses only the target firmware's signed dependency source. Its per-target FreeBSD VM artifacts are unsigned candidates, not publication authorization or proof of OPNsense API compatibility. The private key remains local.
3. Exercise each candidate on its matching native OPNsense target, including the real VNET lifecycle harness and native PF/template/configd behavior. Collect each adjacent report and sign all enabled targets together, retaining the current target during transition.
4. Publish before upgrading clients. Verify every target with `python3 check-upgrade.py --abi FreeBSD:15:amd64 --product-abi 26.7`, substituting the officially announced target values. The command verifies the trust anchor, report/catalog signatures, catalog membership, package digest and native attestation; unavailable or untested targets exit nonzero.
5. In a maintenance window, run the front-page repository bootstrap to install `os-kazuha-repo`, then install/upgrade Mihomo. Its post-install registers only `os-mihomo`; use `/usr/local/opnsense/scripts/firmware/register.php install os-mihomo` to register an already installed package without reinstalling or restarting it. Do not run blanket `resync`.
6. Test the complete firmware upgrade before rollout. The official `<plugins>` list restores missing names using enabled repositories; it does not force reinstall present packages. True pkg upgrade/reinstall preserves policy, but a major upgrade solver that removes the package as a genuine uninstall revokes it. Verify that boundary on the actual target image before claiming end-to-end transparent resumption.

Existing deployments must verify that the signed repository and Mihomo registration are present before relying on automatic package recovery after a firmware upgrade. Building or publishing an archive does not upgrade a running router; repository setup and gateway migration remain separate maintenance steps.
