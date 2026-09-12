# Build, sign and publish

New maintained packages target **FreeBSD:15:amd64**. Source main excludes generated packages and catalogs; signed output lives on a replaceable gh-pages branch and Pages serves the full pkg repository tree. Legacy FreeBSD 14/15 downloads and Mihomo 1.0.2 remain available for compatibility and rollback. Unsafe Mihomo 1.1.0 is withdrawn.

The existing RSA signing key stays on the local signing host with mode 0600. GitHub receives signed catalogs, packages, a public key and a signed test report. No private key is uploaded or stored in GitHub Secrets.

## Build and exercise the real upgrade

Copy the clean source revision to a FreeBSD 15 build host, excluding local instructions, secrets, Git metadata and build output. Requirements include Python 3.13, PyYAML, PHP with SimpleXML, curl, pkg, xz and the bundled assets. Mihomo builds use `python3.13` explicitly; an alternative path supplied through `MIHOMO_PYTHON` must still be Python 3.13 with the same patch version as the installed `python313` package. Python cache directories and `.pyc`/`.pyo` files are excluded and rejected in the final archive.

```sh
(cd src/os-mihomo && sh build.sh)
(cd src/os-sing-box && sh build.sh)
python3.13 -B -m unittest discover -s src/os-mihomo/tests -v
python3.13 -B -m unittest discover -s src/os-sing-box/tests -v
sh src/os-mihomo/tests/jail/run.sh \
  src/os-mihomo/dist/os-mihomo-1.1.1.pkg legacy-1.0.2.pkg
```

The harness requires root, VIMAGE, TUN and enough disk for its disposable filesystem. It creates an isolated VNET with synthetic upstreams and its own FIBs. It does not connect the jail to production interfaces. Its report identifies the exact package SHA-256 and executed checks. Test adapters replace OPNsense configd/filter/template/GUI infrastructure; actual package hooks, core, daemon, TUN, routes and Unbound are exercised. Remaining production checks are listed below.

## Sign the tested candidate

Preserve a local legacy repo tree for compatibility downloads. Use the exact clean tested source commit and package filenames:

```sh
SOURCE_COMMIT=<tested-40-character-commit> \
  LEGACY_REPO=/path/to/legacy/repo \
  TEST_REPORT=src/os-mihomo/dist/test-report.json \
  sh build-repo.sh src/os-mihomo/dist/os-mihomo-1.1.1.pkg \
    src/os-sing-box/dist/os-sing-box-1.0.3.pkg
python3 verify-repo.py .site --source .
```

Output contains index.html, kazuha.conf, kazuha.pub, SHA256SUMS.txt, release.json/release.sig and complete repo/FreeBSD:14:amd64 and repo/FreeBSD:15:amd64 trees with meta.conf, data.pkg, packagesite.pkg and All/*.pkg. The release report binds the tested package digest to a source commit; additional updated packages are digest-bound too. Every current package is compared with its source, including complete archive inventory checks that reject duplicate or unmanifested files and Python bytecode. Legacy downloads are retained but have no new lifecycle-test attestation.

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

1. Upgrade starts proxy ports with TUN activation off; subscription, secret and cron are retained. Wait beyond the old delayed deletion before proceeding.
2. Check proxy-only behavior, controller login and WAN behavior. Configure this router's merge and validate it.
3. Explicitly enable the desired preset. Confirm native interface/firewall/template output and DNS readiness from router and LAN clients.
4. Exercise router DNS only after confirming its resolver and DIRECT transport. IPv6 client enablement requires separate end-to-end validation; do not suppress AAAA as a workaround.
5. Controlled core failure must remove TUN routes and follow the local DNS policy. Measure recovery from a LAN client.
6. Stop must restore DNS and stop TUN; WAN must not revive it. Successful subscription update preserves credentials; invalid input preserves the prior service.

On failure, delete the new plugin to restore owned DNS and remove owned configuration, then restore the offline legacy package and settings if necessary. User state remains in /var/db/os-mihomo. Do not run archived old repair scripts against the new manager, and do not delete generated Unbound dot.conf as a recovery action. Real PF policy routing, secondary-router rebinding protection and LAN connectivity remain production checks.
