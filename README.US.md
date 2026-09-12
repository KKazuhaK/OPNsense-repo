# Kazuha OPNsense repository

An independent `os-mihomo` fork for **OPNsense 26.7 / FreeBSD:15:amd64**, distributed through a signed package repository.

Fresh installation runs loopback proxy ports without taking over LAN routing or DNS. Complete subscription YAML is fetched directly, keeping the provider's nodes, groups and rules. Persistent configuration and dashboard credentials survive upgrades. Transparent TUN and DNS forwarding require explicit enablement; automatic DNS recovery is configurable per router.

- [Plugin configuration and build guide](src/os-mihomo/README.US.md)
- [Design and verification](src/os-mihomo/DESIGN.md)
- [Signing and deployment](DEPLOYMENT.md)
- [Signed repository](https://kkazuhak.github.io/OPNsense-repo/)
- [中文](README.md)

`main` contains source and bundled runtime assets; generated `repo/`, package output, and catalogs are ignored. Signed artifacts are published on a replaceable `gh-pages` branch and deployed by GitHub Actions. The signing private key stays on the local router and is never uploaded to GitHub.

Sibling plugin sources are retained from [Opnwall/OPNsense-repo](https://github.com/Opnwall/OPNsense-repo) and are unchanged. This fork's repository publishes only `os-mihomo` for FreeBSD 15.

[License](LICENSE)
