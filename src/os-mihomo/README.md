# os-mihomo
原生 OPNsense 配置备份现在包含 Mihomo 设置与凭据、原始订阅和合并 YAML、本地 `type:file` 规则及节点文件、代理组选择和接口/DNS 所有权记录。恢复保留服务启停状态，并关闭透明代理和接管确认；重新接管流量需要在页面明确开启。详见[配置备份与恢复](../../CONFIG-BACKUP.md)。


独立维护的 OPNsense CE Mihomo 插件，当前已验证目标为 26.7 / FreeBSD 15 amd64；构建目标通过配方参数化。

首次安装或未知旧状态迁移只运行普通代理端口，不继承旧包的透明模式。完整订阅 YAML 验证通过后，必须显式启用 TUN；1.1.2 受管理状态建立后的升级及重装保留这一选择和手动 Stop。订阅、secret、定时任务和每台路由器的配置保留在 `/var/db/os-mihomo/`，静态资源与预设位于 `/usr/local/share/mihomo/`，不依赖旧包会延迟删除的目录。

在 **VPN → Proxy Suite** 管理服务、订阅与本地 YAML 合并配置。配置顺序为：完整订阅 → 路由器 DNS 开关覆盖 → 本地 `merge.yaml` → 代码约束与启用守卫 → mihomo 验证 → 事务应用。

映射深度合并，普通值和列表替换；空映射清除已有映射。支持规则、代理组、代理的 `prepend-` / `append-` 六种列表扩展，不执行 JavaScript。三份预设为 `full.yaml`、`tun-only.yaml`、`proxy-only.yaml`。加载预设会替换整个合并文件，先保存自定义内容。初始合并采用完整模式默认值，透明代理仍需显式启用。需凭据访问的 Dashboard 初始绑定所有接口，可在设置中限制为回环地址。TUN 默认 MTU 1420，可按节点传输路径调整。

当前内置 FreeBSD 核心的 TUN 仅支持 `gvisor`。`system` 和 `mixed` 的 TCP 路径会错误地将流量判为广播，因此插件拒绝用这两种栈启用透明代理；启用前选择 gVisor。此限制针对当前内置核心，后续核心需重新验证。

设备策略在流量进入 TUN 前按 LAN 源地址选择 TCP/UDP：黑名单中的地址绕过 TUN，白名单只有列出的地址进入 TUN；关闭设备筛选或列表为空时，所有符合接管条件的 LAN 源的 TCP/UDP 进入 TUN。ICMP 及其他控制流量沿用普通路由。绕过的设备沿用现有路由，不经过 Mihomo 的 `DIRECT` 转发。进入 TUN 的流量再遵循订阅和合并规则。用户已有防火墙允许/阻止规则及路由策略仍生效；路由器自身流量和 WAN 入站流量不接管。正常有状态防火墙/NAT 规则下，已建立 DNAT 连接的回包沿用既有状态和正确配置的回程路由。手动配置 HTTP/SOCKS 代理的客户端不受此设备筛选限制。

插件关闭核心 `auto-route`，通过独立的源策略选择 LAN 流量，避免用 TUN 路由接管普通路由表中的公网目的地址。独立路由表保留系统的 WAN 和 VPN 路由；复制网关路由时明确保留出接口，支持网关在新路由表中尚不可直接到达的 WireGuard 路由。设备识别依据 IP 地址；请使用稳定地址或 DHCP 保留，并覆盖设备实际使用的全部地址。当前支持范围仍为 IPv4 客户端，IPv6 需要独立端到端验证；私有 jail 的 IPv6 检查不代表客户端端到端支持。部署前验证黑名单、白名单、空列表、用户阻止规则及自定义路由策略；这项修复不代替目标原生环境的验收。

多 WAN 的 DNAT 回程仍由管理员维护，系统中的 WAN 回程路由需正确。插件不重写 NAT、WAN 网关或 `reply-to`；不会修复原本错误的回程配置。需要固定回程 WAN 的连接应有正确的有状态 WAN 规则及 `reply-to`。NAT 内联 **Pass** 跳过后续过滤规则；**Register rule** 的默认回程绑定要求正确的 WAN 网关，且未全局或单条禁用 `reply-to`。详见官方 [NAT 规则关联](https://docs.opnsense.org/manual/nat.html#filter-rule-association)、[WAN 回程规则](https://docs.opnsense.org/manual/firewall.html)和 [Disable reply-to](https://docs.opnsense.org/manual/firewall_settings.html#disable-reply-to)。排查时查看路由、有效 PF 规则和状态，并抓取 WAN、LAN、TUN 的新连接。策略变更后已有连接可继续使用旧状态；必要时仅清除受影响的旧状态，不清空整个状态表。命令与示例见 [DEPLOYMENT.md](../../DEPLOYMENT.md)。

透明模式必须使用返回真实地址的 DNS。默认并推荐 `redir-host`，也支持 `normal`；绕过 TUN 的设备无法依赖 Mihomo 处理 fake-IP 占位地址。透明模式关闭时可以保留旧的 `fake-ip` 选择；启用透明模式或在透明模式下应用配置时，最终生效的 `fake-ip`（包括合并文件覆盖）会自动转换为 `redir-host`，并将该选择保存回设置。绕过设备继续使用原有 DNS 路径，共享解析器也必须返回真实地址；已有 fake-IP 缓存可能需要清除或等待过期。

合并文件不能改变 `tun_mihomo` 设备名、覆盖持久化 secret、让任何监听器占用 53，或绕过透明模式的启用守卫与真实 DNS 约束。DNS 集成支持 `127.0.0.1:1053`，自定义监听器由管理员管理。

“通过路由器 DNS 解析”默认关闭。开关本身仅覆盖 nameserver、proxy-server-nameserver、default-nameserver、nameserver-policy 四项，不改变 DNS 劫持或 Unbound 的 AAAA 策略；透明模式另行强制真实 DNS。根据本机 DoT 配置为 IPv4/IPv6 上游地址和 853 端口注入优先 DIRECT 规则，上游改变时自动刷新，避免节点解析死锁。该模式不把 Unbound 再转发给 Mihomo；必须移除订阅的 DNS fallback，上游不可用时明确失败。

手动 DNS 字段使用 Mihomo URL 语法。“覆盖订阅 DNS”开关明确控制非空手动字段是否替换运行配置中的对应项目；关闭后立即恢复订阅 DNS，同时保留手动值供以后启用。订阅 YAML 原文件始终不会被改写，启用路由器 DNS 时则以路由器 DNS 为优先。Mihomo 把 `#` 后的第一个值解释为代理或接口，而 Unbound 的 `IP@端口#主机名` 用它表示 TLS 校验名。为避免复制后直到运行时才出现 `interface not found`，插件会把 Nameservers 和节点 DNS 中的 `tls://IP#长主机名` 规范化为 `tls://长主机名`；`#vtnet1`、`#RULES` 等接口或规则选择保持原样。Bootstrap 仍必须是字面 IP，因此复制来的同类写法会在该字段保存为其中的 IP，由规范化后的主机名字段执行加密查询，避免形成解析依赖环。

当前发布范围是 IPv4 客户端。选择“通过路由器 DNS 解析”时，若 RA/DHCPv6 已向客户端提供 IPv6，而 Mihomo IPv6 关闭，插件拒绝启用；运行中出现这种变化会提示。插件不抑制 AAAA 或修改 RA/DHCPv6；Mihomo IPv6 关闭时，原生 IPv6 流量绕过 TUN。未来启用客户端 IPv6 代理应完成独立端到端验证。

核心异常退出后清除插件的透明接管策略和 TUN 路由；默认自动恢复原有直连 DNS，每台可配置。显式 Stop 即使 DNS 恢复失败也停止核心和透明接管，随后重试 DNS 恢复。WAN 事件不会重新启动手动停止的服务。关闭透明模式仅清除插件创建的接口、策略和路由，不清空防火墙状态表。

启动时在本机记录核心写入的系统 DNS 指纹。异常退出后通过 OPNsense 原生 DNS 重载恢复系统解析，失败会重试；用户后来修改的解析文件或显式配置的 DNS 不会被覆盖。这份临时恢复记录不进入 XML 备份。

订阅直连下载，UA 格式固定为 `OPNsense-Mihomo/1 (device)`。4xx 不重试、不回退；仅 timeout/5xx 有最多四次请求。URL 不进入进程参数、日志或页面的已保存值。CLI、configd 和 cron 使用同一入口。

构建使用目标 Python minor，并核对实际版本与声明的依赖一致；当前为 `python3.13` / `python313`。排除 `__pycache__`、`.pyc`、`.pyo`，且在暂存区和最终归档再次检查。

在目标原生环境运行 `sh build.sh`，当前生成 `dist/FreeBSD:15:amd64/os-mihomo-1.2.9.pkg`。`TARGET_ABI`、`TARGET_PRODUCT_ABI`、`TARGET_PYTHON` 可显式指定，实际内核、用户空间、Python 和依赖必须匹配；不能在 FreeBSD 15 上给包换标签冒充 16。已启用配方定义发布目录，未公布的下一版保持禁用。发布必须具备每个目标与包摘要匹配的真实 VNET jail 报告，Pages 再验证源码、测试和包内容。安装后调用官方窄范围插件登记。1.1.2 管理状态建立后的重装保留显式 TUN 选择和行政 Stop；未知旧状态仍安全关闭 TUN。构建、签名、回退和生产维护检查见 [DEPLOYMENT.md](../../DEPLOYMENT.md)。
