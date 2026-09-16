# OPNsense EasyTier 插件

`os-easytier` 是适用于 OPNsense 的 EasyTier 组网 VPN 插件。它集成 EasyTier Core，可在 **VPN > EasyTier** 中完成配置、服务管理、状态查看、节点查看和日志排查。

当前插件版本：`1.1.3`

内置 EasyTier 版本：`2.6.4`

## 原生配置备份与恢复

插件将 `/usr/local/etc/easytier` 中的持久文件及
`/etc/rc.conf.d/easytier` 的原始内容、文件权限和存在状态镜像到
`config.xml` 的 `OPNsense/EasyTier/backup` 节点。OPNsense 的完整配置
备份因此包含网络凭据及服务禁用状态。日志、PID、锁和 MVC 临时文件不进入镜像。

恢复 OPNsense 配置后，插件会在服务启动前还原文件。独立后台任务每秒检查
外部文件修改，WebGUI 保存配置或操作服务时也会同步更新镜像；保存后出现备份
提示时，应先处理该提示再导出配置备份。原有包升级时的 rc 文件临时备份继续保留。

该镜像采用压缩和 Base64 编码，编码本身不提供加密。请使用 OPNsense 配置备份
的加密选项保护导出的凭据。重新安装插件仍由 OPNsense 的插件恢复流程负责。

![EasyTier 配置页面](images/configuration.png)

## 支持平台

| OPNsense | FreeBSD ABI | 架构 | 状态 |
| --- | --- | --- | --- |
| OPNsense 26.7 | `FreeBSD:15:amd64` | amd64 | 已测试 |

当前构建脚本仅接受 FreeBSD 15 amd64 ABI。请勿在其他架构或 FreeBSD 主版本上强制安装。

## 主要功能

- 在 OPNsense WebGUI 中启动、停止和重启 EasyTier
- 直接编辑 EasyTier TOML 配置文件
- 显示服务状态、版本、进程、节点名称、虚拟地址和网络名称
- 显示节点延迟、丢包率、流量、隧道和 NAT 类型
- 支持英文、简体中文和繁体中文，其他语言默认显示英文
- 动态 TUN 接口访问权限由管理员防火墙规则控制，插件不优先放行或覆盖阻止规则
- 只导入不与原生网络冲突的远端私网路由，保护公网回程与其他 VPN
- Core 异常退出或管理 RPC 连续失去响应时，撤销自身导入的路由并清理已核验所属的接口
- 首次安装时复制示例配置，升级或强制重装不会覆盖现有配置
- 卸载时保留配置与日志，并避免全局防火墙重载中断 LAN 管理连接

## 目录结构

```text
packaging/freebsd/                                      FreeBSD pkg 元数据及安装、卸载脚本
src/etc/rc.conf.d/easytier                              rc.conf 默认设置
src/usr/local/etc/easytier/config.toml.sample           安装示例配置
src/usr/local/etc/rc.d/easytier                         EasyTier rc.d 服务
src/usr/local/etc/inc/plugins.inc.d/easytier.inc        OPNsense 服务与防火墙集成
src/usr/local/opnsense/service/conf/actions.d/           configd 服务动作
src/usr/local/opnsense/mvc/app/models/OPNsense/EasyTier/ 菜单和 ACL 模型
src/usr/local/sbin/easytier-core                         EasyTier 核心程序
src/usr/local/sbin/easytier-cli                          EasyTier 命令行工具
src/usr/local/opnsense/mvc/app/views/OPNsense/EasyTier/index.volt                           WebGUI 页面
images/                                                  README 页面截图
```

## 安装

### 通过 Opnwall 社区仓库安装

在 OPNsense 控制台或 SSH 中执行：

```sh
fetch -o /usr/local/etc/pkg/repos/opnwall.conf \
  https://opnwall.github.io/OPNsense-repo/opnwall.conf

pkg update -f
pkg install os-easytier
```

也可以进入 **系统 > 固件 > 插件**，查找并安装 `os-easytier`。

### 离线安装

下载与 FreeBSD 15 amd64 对应的软件包，然后执行：

```sh
pkg add -f os-easytier.pkg
```

安装完成后刷新 WebGUI，进入 **VPN > EasyTier**。

## 配置和使用

首次安装且正式配置不存在时，插件会把示例文件复制到：

```text
/usr/local/etc/easytier/config.toml
```

文件权限为 `0600`。进入 **VPN > EasyTier > 配置**，按实际网络修改配置文件。至少需要设置节点名称、虚拟地址、初始连接节点、网络名称、网络密钥和需要发布的本地网段。

```toml
instance_name = "OPNsense"
hostname = "opnsense"
ipv4 = "10.125.0.1/24"
dhcp = false

listeners = [
    "tcp://0.0.0.0:11010",
    "udp://0.0.0.0:11010",
]

rpc_portal = "127.0.0.1:15888"

[[peer]]
uri = "tcp://服务器地址:11010"

[[proxy_network]]
cidr = "192.168.10.0/24"

[network_identity]
network_name = "office"
network_secret = "请替换为自己的网络密钥"

[flags]
dev_name = "easytier0"
default_protocol = "tcp"
enable_encryption = true
enable_ipv6 = false
mtu = 1300
private_mode = true
proxy_forward_by_system = true
```

点击 **保存并重启** 后，到状态、节点和日志页面确认运行结果。

[查看完整示例配置](src/usr/local/etc/easytier/config.toml.sample)

![EasyTier 节点页面](images/peers.png)

## 动态接口与防火墙规则

EasyTier 使用 `flags.dev_name` 指定的动态 TUN 接口，默认是 `easytier0`。
名称必须以字母开头，只包含字母、数字或下划线，最长 15 个字符。启动时如该名称已被其他接口使用，插件会拒绝启动，避免 Core 改名或清理其他接口。

插件不自动添加 `any to any` 放行规则，也不创建优先于管理员规则的 `quick` 锚点。
需要允许 VPN 节点访问路由器或 LAN 时，进入 **防火墙 > 规则 > 浮动**，设置：

- 方向为入站，接口为任意；未分配的动态 TUN 不出现在接口下拉列表。
- 来源为明确的 VPN 虚拟地址或远端私网网段。
- 目标为允许访问的路由器地址、LAN 网段或具体设备。
- 按实际需要限制协议和端口，按管理员策略排列放行、阻止规则。

这些规则会匹配从动态 TUN 进入的流量；已有规则的优先级和状态保持不变。
WAN 的私网来源阻止等原生防护继续生效。不要把动态 TUN 分配为 OPNsense 固定接口。
日常启动、停止、重启不会重载全局防火墙或清空连接状态。
升级及卸载只退休逐字核验的旧版单条放行规则；同一锚点中后来添加的规则，以及同名的管理员文件，均保留。

## 路由隔离与兼容范围

插件保留原始 TOML 文件、凭据及未知字段，并在权限为 `0600` 的运行副本中设置 `routes = []`，禁止 Core 自行向系统路由表导入网段。
外层监控程序负责从节点 RPC 导入经过检查的远端 IPv4 子网。没有指定 `routes` 时自动学习；指定后按该数组导入。

允许范围为 `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` 内部的子网，且不能与任何已有非默认原生路由重叠。默认 WAN 路由不会导致所有远端私网都被拒绝。
本机管理 LAN、DNS 所在子网、其他 VPN 和原生网关路由受到保护。
明确配置公网、默认或冲突路由时，保存及启动会返回具体说明并保留原配置；从远端学习到的不安全路由会跳过，状态页显示数量及原因。
管理员新建原生路由后，监控程序也会撤回与其冲突的自身 VPN 路由。

虚拟 IPv4 地址必须使用不与本机网络重叠的固定私网子网；自动 overlay DHCP 不受支持。
虚拟 IPv6 地址可使用独立 ULA 子网。公网 IPv6 overlay 自动地址、提供公网前缀及默认路由模式不受支持；系统原生 IPv6 不受影响。
这些约束防止 VPN 从主路由表捕获公网 DNAT 回包，同时保留正常虚拟地址通信和远端私网子网访问。

新版本升级钩子只在已核验当前实例正在运行、且 rc 配置仍启用时记录恢复意图；停止的实例不会因升级或 WAN 地址事件被启动。
首次从历史版本升级时，旧卸载钩子可能先停止 Core，无法证明它在升级前仍运行。为保留停止意图，这种情况可能需要管理员在页面明确点击“启动”。

监控程序只终止自身启动的 Core，以 PID 出生时间、UID、可执行文件和内核返回的逐项参数核验每次停止信号。
接口清理核验内核 TUN 名称、打开进程、接口索引及本次运行的所属标记，路由清理核验实际前缀、接口与网关身份。新增路由前先持久化待处理凭据；即使进程在内核确认与所有权记录之间中断，恢复也只会接管或删除与该凭据完全一致的直连接口路由。
不会按接口名称盲目销毁其他设备，也不会删除管理员已替换的路由。

## 远端子网访问

如需访问 EasyTier 节点后方的局域网设备，应在远端节点发布对应网段：

```toml
[[proxy_network]]
cidr = "192.168.101.0/24"
```

如果只能访问远端路由器，不能访问其后方客户端，请依次检查：

- 远端代理网段是否正确发布
- 远端系统是否允许 IPv4 转发
- 客户端默认网关是否指向远端路由器
- 客户端主机防火墙是否允许来自 EasyTier 网段的流量
- 两端局域网网段是否发生重叠

## 配置与日志保留

以下文件在升级、强制重装和卸载时保留：

```text
/usr/local/etc/easytier/config.toml
/var/log/easytier.log
```

示例配置只在正式配置不存在时复制，不会覆盖用户已经修改的配置。

## 卸载

```sh
pkg delete os-easytier
```

卸载脚本会：

- 在限定时间内停止 EasyTier 进程
- 清理已核验所属的配置 TUN、导入路由及 PID 文件；保留其他接口和管理员路由
- 清理 VPN 菜单缓存和 configd 注册
- 保留配置文件与日志

## 编译

必须在 FreeBSD 15 amd64 或对应的 OPNsense 主机上编译，并确保系统已安装 `pkg`：

```sh
make package
```

也可以直接调用构建脚本：

```sh
ABI=native OUTPUT_NAME=os-easytier.pkg sh build.sh
```

如需生成通用 FreeBSD 15 amd64 ABI 标记的软件包：

```sh
ABI=FreeBSD:15:amd64 OUTPUT_NAME=os-easytier-freebsd15.pkg sh build.sh
```

构建结果位于 `dist/`：

```text
dist/os-easytier.pkg
```

## 注意事项

- 不要把 `easytier0` 分配为 OPNsense 固定接口。
- 不要使用 Cron 或 Shellcmd 重复添加 EasyTier 启动命令。
- 不要在多个节点中重复使用相同的虚拟 IP。
- 两端发布的局域网网段不能相互重叠。
- `rpc_portal` 默认使用 `127.0.0.1:15888`，也支持自定义端口；启动脚本会明确传入监听地址，节点页面跟随配置查询。
- VPN 节点入站访问需要明确的管理员防火墙规则；状态页显示被跳过的不安全路由。
- 本项目为非官方社区插件，不受 Deciso、OPNsense 或 EasyTier 官方支持，使用者应自行评估风险。

## 相关项目

- [EasyTier](https://github.com/EasyTier/EasyTier)
