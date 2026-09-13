# Kazuha OPNsense repository

An independent `os-mihomo` fork for **OPNsense 26.7 / FreeBSD:15:amd64**, distributed through a signed package repository.

Fresh installation and unrecognized legacy migration run loopback proxy ports without taking over LAN routing or DNS. After 1.1.2 establishes managed state, upgrades and reinstalls preserve explicit transparent consent and administrative Stop. Older unmarked state requires one explicit re-enable. Complete subscription YAML is fetched directly, keeping nodes, groups, rules and dashboard credentials. The settings changed most often are switches on the page: IPv6, DNS mode, whether client DNS is captured, which rule database is downloaded, and the three sets of DNS upstreams, each inheriting the subscription's own value when left empty. Hand-written YAML still wins and is reported where it does. Local merge YAML and full/tun-only/proxy-only presets control the rest of routing and DNS; automatic recovery is configurable per router.

- [Plugin configuration and build guide](src/os-mihomo/README.US.md)
- [Design and verification](src/os-mihomo/DESIGN.md)
- [Signing and deployment](DEPLOYMENT.md)
- [Signed repository](https://kkazuhak.github.io/OPNsense-repo/)
- [中文](README.md)

`main` contains source and bundled runtime assets; generated `repo/`, package output, and catalogs are ignored. Signed artifacts are published on a replaceable `gh-pages` branch and deployed by GitHub Actions. The signing private key stays on the local router and is never uploaded to GitHub.

Legacy FreeBSD 14/15 downloads and the `os-mihomo` 1.0.2 rollback package remain available. Current Mihomo maintenance targets FreeBSD 15. `os-sing-box` 1.0.3 also removes third-party subscription conversion and accepts complete JSON only. Legacy packages retained from [Opnwall/OPNsense-repo](https://github.com/Opnwall/OPNsense-repo) are compatibility downloads, without current test certification.

The optional router DNS switch pins upstream transport DIRECT to prevent node-hostname resolution deadlock. IPv4 clients are supported; enabled RA/DHCPv6 with disabled Mihomo IPv6 blocks activation, without changing Unbound AAAA policy. Publication requires a signed FreeBSD test report, reruns the referenced source tests and compares package bytes with that source.

OPNsense CE build recipes define FreeBSD ABI, firmware series, Python and repository directory together. CI builds each enabled native target; publication requires its own native lifecycle report. Different dependencies under the same FreeBSD ABI use separate series directories. `os-kazuha-repo` installs the signed source and selects the effective firmware series during configure; Mihomo installation registers through the official firmware interface. The 27.1 base is not yet announced, so its recipe remains disabled. FreeBSD 16 is an example, not a supported release. See [DEPLOYMENT.md](DEPLOYMENT.md) for readiness checks and the release checklist.

[License](LICENSE)
