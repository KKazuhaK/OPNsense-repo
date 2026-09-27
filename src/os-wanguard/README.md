# WAN Guard for OPNsense

`os-wanguard` 监视选定的 DHCP 接口；接口拿到不想要的 IPv4 地址时，重新请求该接口的
IPv4 租约。它针对 IP 直通（passthrough）或桥接模式下的运营商网关：这类网关在重启
后常常先从自己的 LAN 地址池给路由器一个**私网**租约，稍后才给公网租约。路由器会
一直持有私网租约直到租期结束，这段时间内入站访问、DDNS 和 IPv6 都不可用。

| | |
| --- | --- |
| 插件版本 | `1.0.0` |
| 目标 | OPNsense 26.7，`FreeBSD:15:amd64`，Python 3.13 |
| 菜单 | **服务 > WAN Guard > Settings**、**服务 > WAN Guard > Log File** |

软件包不含原生可执行文件，同一个构建适用于所有 amd64 ABI；安装钩子仍只接受
amd64 上的 FreeBSD 14、15、16。

## 为什么不用 “Reject Leases From”

接口选项 **Reject Leases From** 会生成 `dhclient.conf` 的 `reject` 语句，它匹配的是
DHCP **服务器标识**，而不是提供的地址。有的网关两个租约使用同一个标识：LAN 改为
`172.31.254.254/24` 的 AT&T BGW，私网租约和公网直通租约都来自 `172.31.254.254`，
拒绝这个服务器也就拒绝了公网租约。FreeBSD 的 `dhclient.conf` 没有按提供地址拒绝的
语句，因此只能在租约绑定后再判断。

## 工作方式

- 约每 30 秒检查一次所有被监视的接口；接口触发 `newwanip` 事件后一两秒内也会检查。
- 地址落在配置的网络内即为**不想要**；打开 **Private ranges are unwanted** 时，
  所有私网（RFC 1918）、共享地址（`100.64.0.0/10`）和链路本地地址也算。
- 连续两次、间隔至少 20 秒且不超过约 1 分钟观察到不想要的地址才动作；间隔更久（例如
  服务重启）时重新确认。
- 动作是：先把该接口 DHCP 客户端记住的租约移开，再通过 core 自己的
  `interface_dhcp_configure()` 重启这一个接口的 IPv4 DHCP 客户端。新客户端从
  DHCPDISCOVER 开始，由网关决定地址；如果保留租约记忆，客户端会再次请求同一个私网
  租约。移开的租约副本保存在 `/var/db/os-wanguard/`，便于排查。
- 地址一直不想要时，重试至少间隔 1、2、5 分钟，之后每次 15 分钟。同一接口任意两次
  动作至少间隔 1 分钟，每小时最多 8 次，中途修改设置也不会重置。拿到想要的地址后
  计划重置。
- DHCPv6、`rtsold`、前缀委派和其他接口都不受影响：重启 IPv4 客户端的这个调用不做
  别的事；而 **接口 > 概览 > 重新加载** 会清空并重建两个地址族。

**每次重试的代价。** 新租约绑定前旧地址一直保留在接口上，所以新客户端协商期间流量
不中断，前提是这几秒内没有别的操作重建路由表：新客户端启动时会清除该接口的 DHCP
网关记录，租约绑定后再重新设置。每次重试都以一次新的绑定结束，即使网关给回同一个
私网地址也是如此；每次绑定都会触发 core 正常的新地址处理：重新加载防火墙规则和
路由，并重新加载或重启所有响应 WAN 地址变化的服务，例如 Unbound、OpenVPN、
WireGuard 或 os-mihomo。网关持续分配私网地址时，第一个小时最多发生 7 次，之后
每小时 4 次。

## 设置

| 设置 | 默认 | 说明 |
| --- | --- | --- |
| Enable | 关 | 禁用时不运行任何进程，也不会动作。 |
| Interfaces | `wan` | 只能选择已启用、IPv4 类型为 DHCP 的接口，且不能选择 LAN。WAN 不是 DHCP 时，保存前请取消选择。 |
| Unwanted networks | 空 | IPv4 网络，前缀 `/8` 或更长，最多 32 个；不接受带主机位的写法。 |
| Private ranges are unwanted | 关 | 见下方警告。 |

没有列出网络且开关关闭时，没有任何地址是不想要的，页面会提示。Apply 保存设置并
启动、停止或唤醒服务；运行中的服务在下一次检查（约一秒内）采用新设置，速率限制
保持不变。

上面的 AT&T 例子：

- **Interfaces**：`WAN`
- **Unwanted networks**：`172.31.254.0/24`
- **Private ranges are unwanted**：关

**运营商使用 CGNAT 时不要打开 Private ranges are unwanted。** 分配
`100.64.0.0/10` 地址的运营商会让插件每 15 分钟重试一次，永不停止。只有路由器正常
拿到公网地址时才打开。

设置保存在 `config.xml` 的 `OPNsense/wanguard/general`，所有配置备份和历史版本都会
包含。

## 状态与日志

页面列出每个被监视接口的当前地址、状态、上次重置以来的尝试次数、上次动作（时间、
触发方式、原因、结果）以及下次最早重试时间，每 10 秒刷新。

| 状态 | 含义 |
| --- | --- |
| OK | 地址是想要的。 |
| No IPv4 address | 没有可判断的地址。 |
| Unwanted, confirming | 已看到一次，等待第二次确认。 |
| Unwanted, waiting to retry | 已动作，下次重试等待退避时间。 |
| Unwanted, hourly limit reached | 最近一小时已动作 8 次。 |
| Unwanted, no carrier | 链路断开，恢复前不动作。 |
| Unwanted, no DHCP client | 接口上没有运行 IPv4 DHCP 客户端。只有它是被插件自己的动作停止时才会重启，否则只等待。 |
| Ignored | 接口是 LAN，或不是已启用的 DHCP 接口。 |
| Waiting for boot to finish | 系统启动期间只观察。 |
| Disabled | 插件已禁用。 |
| Service stopped | 插件已启用，但服务没有运行。 |

**Retry now** 对地址不想要的接口立即重新请求：跳过两次确认和退避，但不跳过 1 分钟
间隔和每小时上限。

首次看到不想要的地址、每次动作（动作前一行、结果一行）、每次重置、每次手动重试和
每次拒绝都写入 `/var/log/wanguard/`，在 **服务 > WAN Guard > Log File** 查看。

## 安全边界

- 地址是想要的、没有地址、接口是 LAN、不是已启用的 DHCP 接口，或接口上没有运行
  DHCP 客户端时，绝不动作。守护进程检查一次，执行动作的辅助脚本再检查一次，并核对
  决策所依据的地址：期间地址变了就什么都不做。
- 系统启动期间、链路没有载波时不动作。
- 旧 DHCP 客户端 10 秒内没有停止时，不再做任何改动。新客户端没有启动时再启动一次，
  之后最多每 5 分钟尝试修复一次。插件从不修复不是它停止的客户端。
- 停止服务（关闭 Enable 后 Apply、升级、卸载）后不会再开始新动作；正在进行的动作会
  先完成，最多约一分钟。
- 只有守护进程执行动作。`newwanip` 钩子和 **Retry now** 只留下请求；没有任何 API
  或 configd 动作能直接调用辅助脚本。
- 状态（包括速率限制）保存在 `/var/db/os-wanguard/state.json`，守护进程重启和软件包
  升级后仍然有效，重启系统后丢弃。状态文件损坏时会被移到一旁，自动动作暂停 5 分钟。
- 卸载会停止守护进程，DHCP 客户端保持运行。设置留在 `config.xml`，重新安装后恢复。

被监视的 WAN 属于网关组时，重试造成的短暂重新绑定可能触发网关监控或故障切换；退避
会限制发生频率。

## 构建与测试

在 FreeBSD 或 OPNsense 上构建：

```sh
./build.sh
pkg add -f dist/os-wanguard.pkg
```

在仓库根目录运行：

```sh
python3 -B tests/run.py --package os-wanguard
```

在 OPNsense 26.7 测试机上，`--native` 还会运行真实模型校验、私网范围与 core
`is_private_ipv4()` 的一致性检查、辅助脚本和插件钩子调用的函数是否都存在，以及
辅助脚本看到的接口是否与 core 完全一致的只读检查：

```sh
python3 -B tests/run.py --native --package os-wanguard
```

测试机自身上联是 DHCP 时，不要在测试机上启用插件。
