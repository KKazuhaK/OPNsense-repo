# MVC migration verification

Date: 2026-09-12. Implementation covers Staticarp, pfTop, Lucky, EasyTier,
DDNS-Go, Lang, ttyd, Speedtest and Sing-box. Existing Unboundcustom received
small MVC compatibility fixes. Parallel Mihomo changes are outside this work.

## Native environment and test method

Tests ran over SSH and the authenticated HTTPS API on a physical router running
OPNsense `26.7.3_11`, FreeBSD `15.1-RELEASE-p3` amd64, PHP `8.5`, Python
`3.13.15` and PyYAML `6.0.3`. Runtime controllers, views and configd helpers
were temporarily staged with backups. Actual requests used the installed MVC
framework, configd and native CLI dependencies. New proxy/VPN daemons were not
started on the production router.

All nine `1.1.0` candidates built with native pkg. Package inspection checked
runtime file hashes, menu/ACL/version metadata, absence of retired PHP pages
and generated state, and decoded hook contents and shell syntax. Packages were
not installed into the production package database or published. Five plugin upgrade suites used real pkg with an isolated database and scratch
paths. A second variant explicitly simulated destructive historical outgoing
uninstall hooks; ordinary pkg 2.3.1 upgrades do not run outgoing POST_DEINSTALL.

## Results

| Check | Result | Evidence |
| --- | --- | --- |
| Registered read APIs | Passed | 23 actual HTTPS endpoints returned valid responses, including every settings endpoint |
| Mutation method guards | Passed | All 32 mutation endpoints rejected GET |
| Invalid input and authentication | Passed | Eight invalid POST requests rejected; unauthenticated request rejected |
| Native controller contracts | Passed | Speedtest, Sing-box, small-plugin and utility/Unboundcustom contracts verify read-only denial before backend work, request transport and failure cleanup |
| Native PHP syntax | Passed | 28 temporarily staged PHP files linted on the physical router |
| Shell checks | Passed | 42 builders/hooks passed shell syntax; Speedtest and Sing-box passed ShellCheck |
| Native helper resolution | Passed | PHP entry points resolve against installed OPNsense libraries; no missing CLI functions |
| Speedtest settings | Passed | Actual settings round trip and invalid thread rejection |
| Speedtest execution | Passed | Background acceptance in 0.41 s, duplicate run and clear-during-run refused, progress advanced to `done` |
| Speedtest measurement | Passed | Real Vancouver server test: 273.29 Mbps download, 181.94 Mbps upload; these are test results, not performance guarantees |
| Speedtest server refresh | Passed | Actual WAN refresh returned 20 servers; an initial network failure retained the existing cache |
| EasyTier configuration | Passed | Actual API TOML save, credential omission, masked round trip and relocated-mask rejection |
| Sing-box configuration | Passed | Actual API save validated by the bundled native binary; masked round trip, stale revision rejection, omitted/retained/explicitly cleared subscription URL |
| Sing-box fresh state | Passed | Missing settings/sub directories initialize privately before reading or saving |
| Lang updater | Passed | Trusted archive downloaded and installed into an isolated prefix; native queue locking and archive traversal/symlink rejection tested |
| State preservation | Passed | Ten real pkg upgrade variants cover EasyTier, ttyd, Staticarp, Lucky and DDNS-Go; Sing-box fixtures also preserve exact settings and disabled state |
| ttyd terminal | Passed with host authentication limit | Actual service and HTTPS/WebSocket iframe connected to SSH port 10511; existing public-key-only SSH policy rejects the default password login; start/stop controls verified |
| Portable Python regression | Passed | 72 tests across migration, helper, packaging and existing release checks |
| Speedtest browser themes | Passed | Physical-router page inspected in both `opnsense` and `opnsense-dark` |
| All nine browser pages | Passed | After login in a controllable Chrome tab, physical-router dark-theme pages and merged configuration/log/subscription tabs were inspected |
| Native full help | Passed | All nine pages: 11 form toggles and 40 field/action descriptions; actual expand, collapse and individual-help clicks passed in both light and dark themes; native `H` shortcut verified |

The API checks exercise registered routes and selected workflows. They do not
claim that Lucky/DDNS/VPN service start/stop, a live localization replacement,
or every third-party terminal integration was executed on the production
router. The corresponding helpers and upgrade behavior were tested in isolated
native fixtures.

## Reproducible checks

On a development checkout with Python and PyYAML:

```sh
python3 -B -m unittest discover -s tests -v
python3 -B -m unittest discover -s src/os-speedtest/tests -v
python3 -B -m unittest discover -s src/os-lucky/tests -v
python3 -B -m unittest discover -s src/os-ddns-go/tests -v
python3 -B -m unittest discover -s src/os-easytier/tests/native -v
python3 -B -m unittest discover -s src/os-ttyd/tests/native -v
python3 -B -m unittest discover -s src/os-lang/tests/native -p test_archive.py -v
python3 -B -m unittest discover -s src/os-sing-box/tests -v
```

With native PHP:

```sh
php src/os-speedtest/tests/native/test-api.php
php src/os-sing-box/tests/native/test-api-contract.php
php tests/native/test-utility-api-contract.php
php tests/native/test-small-api-contract.php
```

Native build:

```sh
cd src/os-speedtest
ABI=native sh build.sh
php tests/native/check-undefined.php
```

The other builders likewise support `ABI=native`. On FreeBSD, run
`python3 tests/native/test-utility-upgrade.py -v` to exercise the real-pkg
fixture; it creates an isolated database and file prefix. Other native helper
tests require the installed CLI libraries and use their documented test-root
environment variables to avoid writing live settings.
Authentication material, runtime backups and raw router responses remain in
ignored private scratch storage and are not committed.

## Full-help follow-up

The nine migrated pages now display the native `full help` label and toggle,
alongside individual information icons. They reuse `initFormHelpUI()` in the
router's installed `opnsense_ui.js`; no separate help handler or settings store
was added. EasyTier and Sing-box have separate toggles for their two forms.
Help covers configuration choices, credential preservation, save/restart
behavior, subscriptions, localization updates, terminal authentication and
pfTop filters. Essential credential and interface warnings remain visible
when help is collapsed.

Authenticated Chrome clicks on the physical router verified all 11 toggles
in `opnsense` and `opnsense-dark`, checking every associated description's
expanded/collapsed state and one individual-help icon per form. The native `H`
shortcut expanded and collapsed Lang help. Expanded pfTop, Speedtest and
Sing-box subscription help were visually inspected. This exposed pfTop's
Bootstrap-select width overflowing its bounded field; `data-width="100%"`
fixed all three selectors, and their actual widths were checked in both themes.

All nine native candidates were rebuilt with these final views. Each archived
view matched its source bytes. The existing six migration integration checks
passed again. The follow-up used a fresh 77-file temporary overlay with backups
of three original files, then restored the original theme and files, removed
new temporary keys/locks, and reloaded configd and WebGUI. It did not install
packages into the production package database or run another speed test,
localization replacement or subscription update.

## Cleanup

Completed: restored the original `opnsense` theme and exact Speedtest
settings/results/progress backup; restored three original files and removed the
remaining temporary files across 111 tracked paths. Removed temporary terminal
runtime/proxy, its added loopback SSH host entry, and newly created fixture
configuration/keys/locks. Reloaded configd, menu/ACL caches and WebGUI. Original
HTTPS returned 200 and the existing Mihomo service was confirmed running.
The WAN server cache reflects the tested server refresh. Native package
candidates and private backup/test records remain in scratch storage; the
production package inventory is unchanged.
