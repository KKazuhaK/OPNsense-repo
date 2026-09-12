中文 · [English](README.US.md)

# OPNsense 的 Mihomo 插件

此独立 fork 面向 **OPNsense 26.7 / FreeBSD:15:amd64**。首次安装只启动本机代理端口，不接管 LAN 路由或 DNS。透明代理必须由管理员显式启用，TUN 与 Unbound DNS 转发作为一个整体开启。

## 配置

1. 在 **System → Firmware → Plugins** 从 Kazuha 签名仓库安装 `os-mihomo`。
2. 打开 **VPN → Proxy Suite → Mihomo Subscribe**，保存完整 Mihomo YAML 订阅地址、设备标签与本机仪表盘的 IPv4 地址及端口。默认地址为 `192.168.8.1:9090`；其他 LAN 地址的路由器需要修改。
3. 拉取并应用订阅。不会调用第三方转换器；订阅中的节点、分组和规则保持原有含义。YAML 解析支持 emoji 转义、任意顶层键顺序、行内映射及零缩进列表。
4. 先验证本机代理端口是否可用：混合代理 `127.0.0.1:7890`，SOCKS5 `127.0.0.1:7891`。尚未配置订阅时使用 `MATCH,DIRECT`。
5. 在 **VPN → Proxy Suite → Mihomo** 点击 **Enable transparent routing**。核心和 DNS 监听就绪后才启用 Unbound 转发。点击 **Disable transparent routing** 可退回普通代理端口模式。

插件统一管理本机监听地址、代理端口、仪表盘、TUN 和 DNS 的启用状态及监听地址。代理端口只监听 loopback，订阅额外声明的入站监听会移除。TUN 设备固定为 `tun_mihomo`，仅在启用透明代理时开启自动路由与 DNS 劫持。仪表盘绑定指定 IPv4 地址，secret 在刷新和升级时保留；密钥输入留空代表保留原值。

DNS 固定监听 `127.0.0.1:1053`，UI 目录为 `/usr/local/etc/mihomo/ui`。启用透明代理时，超出 `198.18.0.0/15` 的 fake-IP 网段会被拒绝，避免与 Unbound 的重绑定保护不一致。

## 故障、升级与卸载

订阅地址、secret、原始订阅、生成配置和恢复状态保存在 `/var/db/os-mihomo/`，不会被包升级覆盖；包含凭据的文件权限为 `0600`。候选配置通过解析与核心验证后才替换正式文件；启动失败会恢复旧配置与旧 secret。若旧服务也无法启动，会保留直连 DNS 并报告错误。

核心意外退出后，默认自动恢复原有 DNS，包括 DNS-over-TLS 配置；可按每台路由器关闭该回退策略。watchdog 每五秒检查一次，随后执行恢复与服务重载。显式停止服务始终先恢复 DNS；WAN 事件和重启不会撤销管理员的停止操作。插件不修改 `/etc/resolv.conf`，也不删除 OPNsense 的 `dot.conf`。

升级会保留服务与透明代理状态。首次从旧版升级时，pre-install 会在旧卸载钩子执行前备份配置与本地补丁脚本。已知 workaround 的旧入口会停用，备份保存在 `migrate/`。卸载仅恢复插件修改的 DNS，以及移除插件创建的接口和防火墙规则；用户状态留作恢复，重新全新安装时透明代理仍默认关闭。

HTTP 4xx（包括 408、429）立即失败，不重试、不走代理回退。只有超时与 HTTP 5xx 允许有限重试及 SOCKS5 回退，每次更新最多四个请求。日志不包含订阅 URL、响应正文或 secret；日志无法写入时仍可执行更新。首次迁移时会清理旧订阅日志，因为旧版会把凭据写入日志。

UA 固定格式为 `OPNsense-Mihomo/1 (device-label)`，软件升级不会改变格式版本。面板使用按规则顺序、不区分大小写的子串匹配；若要单独控制路由器权限，`OPNsense-Mihomo/1` 规则必须放在通用 `mihomo` 规则之前。

定时更新入口为 **System → Settings → Cron → Renew mihomo Subscription**。UI、configd、`/usr/bin/mihomo_sub` 和 `sub/sub.sh` 使用同一更新实现。

## 构建

在 FreeBSD 15 / OPNsense 上安装 `pkg`、`tar`、`xz`、`sha256`、`curl`、Python 3.13 和 `py313-pyyaml`，然后执行：

```sh
cd src/os-mihomo
make package
pkg info -F dist/os-mihomo-1.1.0.pkg
python3 -m unittest discover -s tests -v
```

构建直接使用仓库的 `src/usr/local/bin/clash-meta-freebsd-amd64.xz`，不会编译或下载。仅支持 `FreeBSD:15:amd64`。

签名和 Pages 发布步骤见根目录的 [DEPLOYMENT.md](../../DEPLOYMENT.md)，测试与架构说明见 [DESIGN.md](DESIGN.md)。

此插件基于 [Opnwall/OPNsense-repo](https://github.com/Opnwall/OPNsense-repo)、[MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) 及 [Vincent-Loeng](https://github.com/Vincent-Loeng/clash-meta) 的 FreeBSD 构建，独立维护，并非 OPNsense 官方插件。
