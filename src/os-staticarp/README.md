# Static Binding for OPNsense

OPNsense 静态 ARP/IP 绑定插件，参考 `Static Binding for pfSense` 的核心逻辑实现。

## 功能

- 在 `Services > Static Binding` 提供 WebGUI 管理页面。
- 维护 `IP MAC` 静态绑定列表，并可复制当前系统 ARP 表。
- 支持按接口设置 ARP 应答模式：正常应答、静态应答、取消应答。
- 通过 `configctl staticarp apply/reset/status` 应用和重置配置。
- 安装后注册 OPNsense Menu、ACL 和 configd action，不修改核心系统文件。

## 构建

在 FreeBSD/OPNsense 主机上执行：

```sh
make package
```

生成的包位于：

```text
dist/os-staticarp.pkg
```

如需构建通用 amd64 ABI 包：

```sh
TARGET_ABI=FreeBSD:*:amd64 make package
```

## 安装

```sh
pkg add -f dist/os-staticarp.pkg
```

安装后刷新浏览器，打开 `Services > Static Binding`。

## 注意

启用静态绑定或将接口切换为静态应答前，请先确认当前管理主机已经加入绑定列表，否则可能失去 WebGUI 访问。

## Configuration backup

The normal OPNsense configuration backup includes a compressed, checksummed snapshot of `/usr/local/etc/staticarp` and `/etc/rc.conf.d/staticarp` under `OPNsense/Staticarp/backup`. The existing files remain the runtime configuration source. Successful saves and apply/reset commands update the snapshot; a background watcher also captures external file and service-enable changes.

Restore the normal OPNsense backup and reboot. An early configuration hook restores changed snapshots before service configuration is loaded. Unchanged snapshots do not replace newer runtime files. File contents, absence and permission modes are preserved. Installation imports a saved snapshot before creating defaults. Temporary files, logs, PID files and locks are excluded.

## Runtime ownership

Apply and Reset never flush the global ARP table. Only bindings on directly connected configured interfaces and interface modes changed by this plugin are recorded in a private, durable journal. Reset restores any preexisting static binding or ARP mode when the current state still matches the plugin's last change. Later administrator edits and replaced interfaces take precedence. A conflicting Apply reports failure; remove the conflicting plugin setting before applying it again. Kernel and journal failures retain recovery information and cannot report a successful Apply.

The journal identifies the kernel boot and interface index. After a reboot, the explicit settings are applied against the new native baseline; stale runtime ownership is discarded. Existing installations without an ownership journal do not infer ownership of permanent neighbors or interface modes. Identical preexisting state is preserved. The outgoing removal hook of older releases predates these ownership protections; its historical upgrade behavior is not evidence of a fresh installation test.

The ownership journal is runtime state and is deliberately excluded from configuration backups. New installations start disabled and do not change unrelated neighbors. Package action registration requires one configd restart, without restarting the WebGUI. Daily Apply and Reset restart neither service.
