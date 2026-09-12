# Kazuha OPNsense 仓库

独立维护的 `os-mihomo` fork，面向 **OPNsense 26.7 / FreeBSD:15:amd64**，通过签名 pkg 仓库分发。

首次安装或旧版迁移只运行本机代理端口，不接管 LAN 路由和 DNS。1.1.2 建立受管理的状态后，后续升级及重装保留显式开启的透明代理和手动 Stop；未标记的旧状态仍需重新启用一次。直接拉取完整 YAML 订阅，保留节点、分组、规则、配置与仪表盘密钥。本机 merge YAML 和 full、tun-only、proxy-only 预设控制路由与 DNS 模式，故障时的 DNS 回退可按每台路由器配置。

- [插件配置与构建](src/os-mihomo/README.md)
- [架构与验证](src/os-mihomo/DESIGN.md)
- [签名与部署](DEPLOYMENT.md)
- [签名仓库](https://kkazuhak.github.io/OPNsense-repo/)
- [English](README.US.md)

`main` 保留源码与已有运行资产，生成的 `repo/`、构建包与目录元数据已忽略。签名产物发布到可替换的 `gh-pages` 分支，再由 GitHub Actions 部署到 Pages。签名私钥始终留在本地路由器，不上传 GitHub。

保留 [Opnwall/OPNsense-repo](https://github.com/Opnwall/OPNsense-repo) 的旧版 FreeBSD 14/15 下载及 `os-mihomo` 1.0.2 回滚包。当前维护目标是 FreeBSD 15 的 `os-mihomo`；`os-sing-box` 1.0.3 同时修复订阅向第三方转换器泄露的问题，仅接受完整 JSON 订阅。旧包作为兼容下载保留，不代表通过当前验证。

路由器 DNS 开关默认关闭，启用后将 DNS 上游传输固定为 DIRECT，避免代理节点域名解析死锁。IPv4 客户端可使用；检测到 RA/DHCPv6 下发而 mihomo IPv6 关闭时拒绝启用，不修改 Unbound AAAA 策略。发布需要签名的 FreeBSD 实测报告，Pages 对报告所指源码重新运行测试并核对包内容。

无感升级面向 OPNsense CE：目标配方同时定义 FreeBSD ABI、OPNsense series、Python 和仓库目录，CI 按已启用配方构建。每个发布目标必须提供对应原生环境的生命周期报告；同 ABI 但依赖不同的系列使用独立目录。`os-kazuha-repo` 安装签名源并在 firmware configure 时切换系列，Mihomo 安装后通过官方接口登记到插件列表。下一版 27.1 的基础系统尚未公布，配方保持禁用；不能把示例 FreeBSD 16 当作已支持目标。升级前检查与发布清单见 [DEPLOYMENT.md](DEPLOYMENT.md)。

[许可证](LICENSE)
