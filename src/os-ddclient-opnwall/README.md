# os-ddclient-opnwall

完整替代 OPNsense 官方 `os-ddclient` 的社区插件，在保留官方 WebUI、服务、
日志和仪表盘集成的基础上增加：

- 阿里云 DNS（`aliyun`）
- 腾讯云 DNSPod（`tencentcloud`），支持查询、创建及修改记录
- `if6` IPv6 接口地址选择，适用于双栈及 PPPoE 场景

## 安装

本包与官方 `os-ddclient` 安装相同文件，安装前必须先删除官方插件：

```sh
pkg delete os-ddclient
pkg install os-ddclient-opnwall
```

安装 Opnwall 社区仓库后，也可在 **系统 > 固件 > 插件** 中安装。

## 编译

将源码复制到 OPNsense/FreeBSD amd64 主机后执行：

```sh
./build.sh
```

输出文件为 `dist/os-ddclient-opnwall.pkg`。可通过 `VERSION=1.1 ./build.sh`
覆盖默认版本。

## 配置

进入 **服务 > 动态 DNS > 设置**，后端选择 `native`。

- 阿里云：用户名填写 AccessKey ID，密码填写 AccessKey Secret。
- 腾讯云：用户名填写 SecretId，密码填写 SecretKey；建议明确填写 Zone。
- 腾讯云免费解析的 TTL 下限通常为 600，本插件会自动将更低值提升为 600。
- `Hostname(s)` 可填写完整域名；腾讯云记录不存在时会自动创建。

## 卸载与切回官方插件

```sh
pkg delete os-ddclient-opnwall
pkg install os-ddclient
```

卸载软件包不会删除 OPNsense 中已有的动态 DNS 配置。

## Python backend process ownership

The Python backend waits for its actual PID file after daemonization and records the exact executable, NUL-delimited arguments and microsecond kernel birth identity. Stop verifies the saved process and PID file before each signal, including any forced stop. Other Python backends, unrelated children and processes containing the script name as an argument are preserved. A missing legacy identity can be adopted only when the live interpreter, exact script path and configured PID-file argument match. Invalid, replaced or mismatched PID files fail without a signal. This uses conservative checks around signals; it does not claim an atomic kernel guarantee against all process-exit races.

## Perl backend process ownership

The selected Perl backend runs under the plugin's `ddclient_opnwall_perl` supervisor. The standard package's service remains disabled; its executable and dependencies are unchanged. The supervisor launches that executable in foreground mode and records its exact launch plus kernel birth, executable and UID before declaring it ready. DDClient may rewrite its process title while sleeping or updating without losing this launch ownership. Stop targets only that child and its verified Python supervisor. A missing supervisor PID file still permits cleanup of a child with a valid ownership record.

Start, Stop and Restart preserve the saved backend selection and global disablement. Restart stops both managed backends before starting the selected one; any ownership or stop failure prevents another backend from starting. Force uses a separate foreground one-shot for a selected Perl backend and never adds that short process to the daemon's stop targets. There are no `pkill -F` actions or global process-name scans.

A running legacy Perl backend without launch ownership cannot be identified from its rewritten basename-only title. Migration reports an error and preserves its existing process, parameters and PID file. Stop that legacy instance explicitly before enabling the new supervisor. No unrelated or guessed process is killed to complete migration.
