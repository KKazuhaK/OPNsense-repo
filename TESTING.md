# 插件测试

全部 14 个软件包都有独立测试，统一入口为 `tests/run.py`。入口会发现每个
软件包 `tests` 下的所有 `test_*.py`，包括没有 `__init__.py` 的嵌套目录。
新增软件包没有测试、任一测试失败或测试发现失败都会使入口返回非零状态。
CI 使用同一入口，并额外检查 PHP 和 shell 语法。

## 本地与 CI

Python 使用 3.13 或更新版本，并安装测试依赖：

```sh
python3 -m venv .private/test-venv
.private/test-venv/bin/python -m pip install -r tests/requirements.txt
.private/test-venv/bin/python -B tests/run.py
```

完整入口需要 PHP CLI。没有 PHP 的开发机可以运行
`python3 -B tests/run.py --python-only`；PHP、FreeBSD 和 Core 测试的跳过
会显示在输出中，这属于部分本地验证。只检查单个插件时使用
`--package os-ddclient-opnwall`；可重复该选项。`--list` 输出将执行的测试命令。

## OPNsense 原生测试

把源码和测试复制到 OPNsense 26.7 / FreeBSD 15 amd64，安装对应 Python
依赖，在源码根目录运行：

```sh
python3 -B tests/run.py --native
python3 -B tests/run.py --native --device-policy --bandwidth
```

`--native` 使用真实 Core、Phalcon、FreeBSD daemon、lockf 和 pkg；测试的
配置 XML、文件、PID、安装前缀和模拟外部命令均放在各自临时目录。
原生视图检查编译全部源码布局下的 Volt，并检查编译出的 PHP 语法。

`--device-policy` 需要 `/usr/local/bin/mihomo`，启动独立的 loopback 内核，
验证黑名单与白名单的实际匹配规则；关闭 DNS 和 TUN 接管。
`--bandwidth` 使用内置 FreeBSD Speedtest 引擎进行一次真实互联网测速，
结果和进度保存在临时目录。两项实际运行测试必须显式启用；包筛选不能静默
省略已请求的实际运行测试。

## 全新安装验收

最终验收使用全新安装的 OPNsense，记录官方镜像摘要/签名、首次启动及插件
安装前的包、配置和运行状态。被测插件不得有历史安装、恢复的插件设置或
遗留运行文件。首次安装必须从签名的软件包仓库正常执行 `pkg install`，
包含依赖解析和安装钩子。候选测试仓库的首装用于发布前验证；正式最终验收
必须从已经发布的软件包仓库首装，两个阶段分别记录。
升级、重装、进程命令夹具和 VNET jail 检查均属于附加覆盖，不能替代这项
验收，也不能证明管理界面/configd/原生 PF 集成全部正常。

Sing-box 的附加检查见 `src/os-sing-box/tests/native/README.md`。
EasyTier 的实际 TUN/远端私网/PF/故障测试入口是
`src/os-easytier/tests/native/native_network_fixture.py`。
Staticarp 的逐接口 ARP/模式恢复测试是
`src/os-staticarp/tests/native/test-owned-arp.py`；DDClient 的实例进程测试是
`src/os-ddclient-opnwall/tests/native/test-process-owner.py`、
`test-perl-backend.py` 和 `test-service-actions.py`。
涉及写内核路由、ARP 或临时 PF 的脚本必须在专用一次性 VNET jail 中执行，
并满足脚本的显式环境门禁；不得在生产系统直接启用这些夹具。

## 覆盖范围

| 软件包 | 自动化验证的主要行为 |
| --- | --- |
| Mihomo | YAML 合并、凭据、订阅与服务失败、DNS/TUN 状态恢复、原生备份、实际设备策略、打包 |
| Sing-box | 完整 JSON 订阅、受保护配置修改、设备名单在 TUN 前绕过、独立 FIB、DNS/回程保护、路由归属、故障恢复、备份与安装钩子 |
| FRP | TOML、服务和启动状态、配置 XML 字段保真与并发、备份恢复、安装钩子 |
| Speedtest | 阶段和单位解析、实际后台 fork 锁交接、执行失败与超时、进程组清理、原子结果写入、设置备份、实际测速 |
| EasyTier | TOML、禁用/启停意图、私网路由筛选、原生路由和接口归属、真实 TUN TCP/UDP/PF、Core 崩溃及 RPC 卡死恢复、备份 |
| Ttyd | SSH 端口、命令参数、启动失败、PID 身份与陈旧 PID、真实 daemon 和 PTY/WebSocket、备份 watcher、固定摘要的 FreeBSD 15 打包 |
| Staticarp | 绑定和接口校验、逐接口 ARP/模式归属及恢复、管理员修改保留、保存事务、PHP/Python/lockf 并发、安装钩子与备份 |
| Lucky | 类型和路径校验、原子设置、精确 PID/创建身份、守护进程及子进程停止、锁超时、API、原生备份和 watcher |
| DDNS-Go | 自定义 YAML 路径、凭据、精确 PID/创建身份、守护进程及子进程停止、RC 引号和监听地址、API 与原生备份 |
| Lang | ZIP 成员、权限、大小与校验和、下载及完整安装流程、队列并发、目录创建竞争、进度、失败和中断、真实 daemon |
| DDClient-opnwall | 提供商签名、Python/Perl 创建身份、改写标题后的监督器停止、后端切换/禁用/Force、模板与 API、凭据 XML 保真、原生 ABI |
| Unboundcustom | 片段及完整配置校验、重复 Apply 不重启、精确进程重启、真实 DNS 启动失败恢复、损坏记录拒绝、卸载归属、API 与安装钩子 |
| Pftop | 全部视图/排序/数量组合、过滤器的字面参数、输出边界、异常输入和 API、实际只读 PF 快照、安装钩子 |
| Kazuha Repo | 仓库配置、原生插件清单和锁、签名与构建流程、失败和安装钩子 |

共享测试验证备份归档、路径与符号链接、损坏和篡改、原子恢复、并发及原生
XML compare-and-swap；发布测试核对源码、共享文件、依赖、归档成员和安装钩子。

## 验证记录与边界

2026-09-13 的原生回归运行在专用 OPNsense 26.7.3_11 / FreeBSD 15.1
测试机。真实 PHP/Core、原生进程、PTY、RPC、PF 只读快照、私有 XML 备份
恢复和包构建均执行。测试修复了 DDClient 校验与安装路径、Unbound 回滚、
Staticarp 保存/恢复、Lucky/DDNS-Go 配置解析、Lang 目录竞争、Ttyd PID
身份、EasyTier RPC 启动参数，以及 Speedtest 临时文件与进程清理问题。

完整原生运行与受影响套件补测覆盖当时的 802 项 Python 检查，799 通过、
3 项条件跳过。完整运行包含 21 个 Python 套件、39 个入口命令和 793 项
检查；随后复测最新 Mihomo 194 项、FRP 117 项、Speedtest 46 项和 Lang
受影响套件，替换旧结果后得到当时的总计。17 个独立 PHP/Core/API 检查和
全部 15 个 Volt 视图检查通过。
3 项跳过分别为不在干净源码中的 2 个发布快照测试，以及原生队列中仅适用于
模拟启动器的 1 个失败注入测试；该启动失败测试在可移植队列套件中已经执行。

本地 Python 部分回归及补充测试也通过；受影响的可移植 PHP 套件复测通过。
原生 Core/FreeBSD 和 Python 3.13 专属构建用例在实机补齐。排除 vendor
与 dist 后，源码的 45 个 XML、107 个 Python、90 个 shell 文件及
107 个 PHP/INC 文件语法检查通过。最终 14 个原生候选包均通过源码逐字节
验证；FRP、Speedtest 和 Lang 在最后修改后重新构建并验证。

本地 `.site` 是已发布的签名快照；发布快照测试核对旧包的不可变内容，并用
受控源码修改验证漂移拒绝。干净源码中没有该快照时，这两个测试明确跳过。
当前候选包另由源码逐字节验证，测试不改写签名快照或已发布软件包。Ttyd
已登记为 FreeBSD 15 候选包，校验固定 vendor 摘要、选定许可证和动态库的
普通文件副本；旧 FreeBSD 14 资产保留，不用于当前候选包。

Mihomo 的独立 VNET 生命周期测试见 `src/os-mihomo/tests/jail/run.sh`、
`DEPLOYMENT.md` 和 `src/os-mihomo/tests/native/README.md`。准备脚本仅
复制软件包登记的 MVC 框架和 PHP/Python 运行文件，生成私有 PHP 配置；
真实 Core/BaseModel 使用测试生成的 jail `/conf/config.xml`。配置修订、
configd、服务、PF 和模板适配器仍为模拟实现，宿主配置、凭据和缓存不复制。
统一回归中的 loopback 设备规则及此 jail 测试不构成多设备 LAN/TUN、
宿主 PF 或模板集成验证。

最新 VNET 生命周期运行的 17 项检查全部通过，真实 SIGKILL 后的 watchdog
恢复耗时约 5.736 秒。检查包括原生 1.0.2 升级、同版本重装、显式 TUN
授权、行政 Stop、保留 XML 备份但擦除应用配置后的 Stop 恢复，以及仅移除
私有 Mihomo 备份节点后真正首次安装的默认代理端口启动。

后续备份专项原生检查通过：共享组件在 `/conf/os-config-backup/` 中保留应用
标记与自动同步时间，移走应用配置根和 `/var` 状态后仍能恢复；reconcile
仅重建完全缺失的归档根，保留其他根中的新修改，显式 import 才执行完整
导入。实际 watcher 检查按当前 30 秒预算等待 35 秒，验证禁用状态和端口
修改、进程重启后的节流、重复启动拒绝及父子进程停止。真实 Core 的 CAS
检查拒绝恢复竞争中的旧写入且不生成配置修订；六个归档模型的迁移不创建
缺失节点，并保留未来字段和属性。

FRP 与 Speedtest 另在专用测试机清除各自测试 XML 节点后安装，验证安装
自动登记配置镜像；移走配置存储再重装，FRP TOML 摘要、Speedtest JSON
和 FRP 的 `NO` 状态完全一致。系统原生 API 导出的 XML 为 50751 字节，
核对四个插件模块与仓库清单；大小仅反映本轮测试配置。测试未部署至生产。
