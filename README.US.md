# Kazuha OPNsense repository

An independent `os-mihomo` fork for **OPNsense 26.7 / FreeBSD:15:amd64**, distributed through a signed package repository.

Fresh installation and every upgrade run loopback proxy ports without taking over LAN routing or DNS. Complete subscription YAML is fetched directly, keeping the provider's nodes, groups and rules. Persistent configuration and dashboard credentials survive upgrades. Transparent routing requires explicit enablement, with local merge YAML and full/tun-only/proxy-only presets controlling its mode; automatic DNS recovery is configurable per router.

- [Plugin configuration and build guide](src/os-mihomo/README.US.md)
- [Design and verification](src/os-mihomo/DESIGN.md)
- [Signing and deployment](DEPLOYMENT.md)
- [Signed repository](https://kkazuhak.github.io/OPNsense-repo/)
- [中文](README.md)

`main` contains source and bundled runtime assets; generated `repo/`, package output, and catalogs are ignored. Signed artifacts are published on a replaceable `gh-pages` branch and deployed by GitHub Actions. The signing private key stays on the local router and is never uploaded to GitHub.

Legacy FreeBSD 14/15 downloads and the `os-mihomo` 1.0.2 rollback package remain available. Current Mihomo maintenance targets FreeBSD 15. `os-sing-box` 1.0.3 also removes third-party subscription conversion and accepts complete JSON only. Legacy packages retained from [Opnwall/OPNsense-repo](https://github.com/Opnwall/OPNsense-repo) are compatibility downloads, without current test certification.

The optional router DNS switch pins upstream transport DIRECT to prevent node-hostname resolution deadlock. IPv4 clients are supported; enabled RA/DHCPv6 with disabled Mihomo IPv6 blocks activation, without changing Unbound AAAA policy. Publication requires a signed FreeBSD test report, reruns the referenced source tests and compares package bytes with that source.

[License](LICENSE)
