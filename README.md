# Kazuha OPNsense 仓库

独立维护的 `os-mihomo` fork，面向 **OPNsense 26.7 / FreeBSD:15:amd64**，通过签名 pkg 仓库分发。

首次安装只运行本机代理端口，不接管 LAN 路由和 DNS。直接拉取完整 YAML 订阅，保留服务商的节点、分组和规则；配置与仪表盘密钥在升级时保留。透明代理需要显式同时启用 TUN 与 DNS，故障时的自动 DNS 回退可按每台路由器配置。

- [插件配置与构建](src/os-mihomo/README.md)
- [架构与验证](src/os-mihomo/DESIGN.md)
- [签名与部署](DEPLOYMENT.md)
- [签名仓库](https://kkazuhak.github.io/OPNsense-repo/)
- [English](README.US.md)

`main` 保留源码与已有运行资产，生成的 `repo/`、构建包与目录元数据已忽略。签名产物发布到可替换的 `gh-pages` 分支，再由 GitHub Actions 部署到 Pages。签名私钥始终留在本地路由器，不上传 GitHub。

其他插件源码保留自 [Opnwall/OPNsense-repo](https://github.com/Opnwall/OPNsense-repo)，不作修改。此 fork 的 pkg 仓库仅发布 FreeBSD 15 的 `os-mihomo`。

[许可证](LICENSE)
