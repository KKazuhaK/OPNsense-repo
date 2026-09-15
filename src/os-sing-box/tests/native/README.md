# Native PHP checks

Run on the target OPNsense router after installing the plugin:

```sh
php check-undefined.php
php test-settings.php
php test-api-contract.php
```

The settings test calls the installed backend against temporary isolated files.
It checks API-safe redaction, retaining credentials when proxy entries move,
private file permissions, rejection without changing the active file, direct URL
storage and clearing, log redaction, detached update locking, and rejection of
unsafe request files. The controller contract test checks read-only account
guards, absence of secrets from configd arguments, and temporary-file cleanup
on success and failure. Neither test restarts a router service.
The settings test also checks rejection of stale saves after subscription
replacement and protected credentials moved to another proxy or field.

To check a staged source tree, set `SINGBOX_ROOT` for the undefined-function
checker and pass the helper's absolute path to `test-settings.php`.
Pass the staged controllers' `Api` directory to `test-api-contract.php`.

Additional isolation checks:

```sh
php test-routing-context.php
php test-config-setup.php
python3 test-render.py
python3 test-process-identity.py
python3 test-native-route.py --run
```

`test-config-setup.php` writes only private native Core XML fixtures, checking
policy order, preservation and concurrent saves. `test-render.py` invokes the
actual Core `check` command for both modes without starting a service.
`test-process-identity.py` launches only its own bounded Python child and checks
native NUL-delimited arguments, microsecond birth, UID/executable and ownership
across SIGSTOP/SIGCONT and reaping. It changes no PF rules, routes or services.
`test-native-route.py --run` is guarded to run only inside a disposable VNET jail;
its explicitly owned jail hostname must start with `singbox-isolation-`.
The fixture reads the initial single FIB through the production reader and
allocates three additional routing tables only inside that disposable jail.
It verifies numeric gateway/interface identity, cyclic gateways, exclusive prefix
creation, discard and scoped IPv6 transport while preserving the original FIB.
These fixtures are development coverage and never fresh-install acceptance.

Final acceptance must use a freshly installed OPNsense environment, record the
clean package/configuration/runtime baseline and install this plugin for the first
time from the published signed repository with normal dependency resolution and
install hooks. Verify no TUN/capture/resolver changes on first install and explicit
proxy start; then opt in and measure fresh TCP/UDP device whitelist/blacklist
flows on LAN, native WAN and TUN, administrator blocks/gateway/VPN routes, inbound
DNAT returns with floating and interface-bound states, Core SIGSTOP withdrawal
and explicit restart after SIGCONT, closed-TUN cleanup after SIGKILL, paused-Core
Stop, startup failure/Stop recovery and DNS/SSH/Web GUI/DHCP/RA.
Do not claim DHCP lease or RA acceptance from process/configuration checks alone.
