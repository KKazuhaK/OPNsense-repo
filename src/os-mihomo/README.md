# os-mihomo
原生 OPNsense 配置备份现在包含 Mihomo 设置与凭据、原始订阅和合并 YAML、本地 `type:file` 规则及节点文件、代理组选择和接口/DNS 所有权记录。恢复保留服务启停状态，并关闭透明代理和接管确认；重新接管流量需要在页面明确开启。详见[配置备份与恢复](../../CONFIG-BACKUP.md)。


独立维护的 OPNsense CE Mihomo 插件，当前已验证目标为 26.7 / FreeBSD 15 amd64；构建目标通过配方参数化。

首次安装或未知旧状态迁移只运行普通代理端口，不继承旧包的透明模式。完整订阅 YAML 验证通过后，必须显式启用 TUN；1.1.2 受管理状态建立后的升级及重装保留这一选择和手动 Stop。订阅、secret、定时任务和每台路由器的配置保留在 `/var/db/os-mihomo/`，静态资源与预设位于 `/usr/local/share/mihomo/`，不依赖旧包会延迟删除的目录。

在 **VPN → Proxy Suite** 管理服务、订阅与本地 YAML 合并配置。配置顺序为：完整订阅 → 路由器 DNS 开关覆盖 → 本地 `merge.yaml` → 代码约束与启用守卫 → mihomo 验证 → 事务应用。

映射深度合并，普通值和列表替换；空映射清除已有映射。支持规则、代理组、代理的 `prepend-` / `append-` 六种列表扩展，不执行 JavaScript。三份预设为 `full.yaml`、`tun-only.yaml`、`proxy-only.yaml`。加载预设会替换整个合并文件，先保存自定义内容。初始合并采用完整模式默认值，透明代理仍需显式启用。需凭据访问的 Dashboard 初始绑定所有接口，可在设置中限制为回环地址。TUN 默认 MTU 1420，可按节点传输路径调整。

当前内置 FreeBSD 核心的 TUN 仅支持 `gvisor`。`system` 和 `mixed` 的 TCP 路径会错误地将流量判为广播，因此插件拒绝用这两种栈启用透明代理；启用前选择 gVisor。此限制针对当前内置核心，后续核心需重新验证。

启用 `auto-route` 的 TUN 也可能接走 WAN 端口转发（DNAT）按普通路由返回的流量。多 WAN 部署须验证入站连接的 PF 状态将回包通过 `reply-to` 送回正确 WAN 网关。NAT 的内联 **Pass** 会跳过后续过滤规则，不能依靠 LAN 源设备策略保证回程。**Register rule** 创建关联 WAN 过滤规则；只有正确配置该 WAN 网关、且未全局或单条禁用 `reply-to` 时，才能依赖其默认回程绑定。若禁用了 `reply-to`，须由管理员配置并确认具有状态及正确回程绑定的 WAN 规则。详见官方 [NAT 规则关联](https://docs.opnsense.org/manual/nat.html#filter-rule-association)、[WAN 回程规则](https://docs.opnsense.org/manual/firewall.html)和 [Disable reply-to](https://docs.opnsense.org/manual/firewall_settings.html#disable-reply-to)。

NAT 与 WAN 网关由管理员维护，插件不自动重写；1.2.2 未修复或改变上述回程策略。排查时查看路由、有效 PF 规则和状态，并同时抓取 WAN、LAN、TUN 的新连接；必要时仅清除受影响的旧状态。命令与示例见 [DEPLOYMENT.md](../../DEPLOYMENT.md)。

合并文件不能改变 `tun_mihomo` 设备名、覆盖持久化 secret、让任何监听器占用 53，或绕过未启用的 TUN 守卫。DNS 集成支持 `127.0.0.1:1053`，自定义监听器由管理员管理。

“通过路由器 DNS 解析”默认关闭。开启时仅覆盖 nameserver、proxy-server-nameserver、default-nameserver、nameserver-policy 四项；不改变 DNS 劫持、增强模式和 Unbound 的 AAAA 策略。根据本机 DoT 配置为 IPv4/IPv6 上游地址和 853 端口注入优先 DIRECT 规则，上游改变时自动刷新，避免节点解析死锁。该模式不把 Unbound 再转发给 Mihomo；必须移除订阅的 DNS fallback，上游不可用时明确失败。

当前发布范围是 IPv4 客户端。若 RA/DHCPv6 已向客户端提供 IPv6，而 Mihomo IPv6 关闭，插件拒绝启用；运行中出现这种变化会提示。未来启用客户端 IPv6 应作为独立项目完成端到端验证。

核心异常退出后总会清除 TUN 路由；默认自动恢复原有直连 DNS，每台可配置。显式 Stop 即使 DNS 恢复失败也停止核心和 TUN，随后重试 DNS 恢复。WAN 事件不会重新启动手动停止的服务。关闭透明模式仅清除插件创建的接口和规则。

启动时在本机记录核心写入的系统 DNS 指纹。异常退出后通过 OPNsense 原生 DNS 重载恢复系统解析，失败会重试；用户后来修改的解析文件或显式配置的 DNS 不会被覆盖。这份临时恢复记录不进入 XML 备份。

订阅直连下载，UA 格式固定为 `OPNsense-Mihomo/1 (device)`。4xx 不重试、不回退；仅 timeout/5xx 有最多四次请求。URL 不进入进程参数、日志或页面的已保存值。CLI、configd 和 cron 使用同一入口。

构建使用目标 Python minor，并核对实际版本与声明的依赖一致；当前为 `python3.13` / `python313`。排除 `__pycache__`、`.pyc`、`.pyo`，且在暂存区和最终归档再次检查。

在目标原生环境运行 `sh build.sh`，当前生成 `dist/FreeBSD:15:amd64/os-mihomo-1.2.2.pkg`。`TARGET_ABI`、`TARGET_PRODUCT_ABI`、`TARGET_PYTHON` 可显式指定，实际内核、用户空间、Python 和依赖必须匹配；不能在 FreeBSD 15 上给包换标签冒充 16。已启用配方定义发布目录，未公布的下一版保持禁用。发布必须具备每个目标与包摘要匹配的真实 VNET jail 报告，Pages 再验证源码、测试和包内容。安装后调用官方窄范围插件登记。1.1.2 管理状态建立后的重装保留显式 TUN 选择和行政 Stop；未知旧状态仍安全关闭 TUN。构建、签名、回退和生产维护检查见 [DEPLOYMENT.md](../../DEPLOYMENT.md)。
