# Speedtest for OPNsense

`os-speedtest` adds **Diagnostics > Speedtest** to OPNsense. It supports
outbound-interface selection, manual server refresh and selection, configurable
parallel connections, multilingual output, and persistent test results. Its MVC
page is `/ui/speedtest`; configuration and results remain in `/var/db/speedtest`.

Build on FreeBSD or OPNsense:

```sh
./build.sh
pkg add -f dist/os-speedtest.pkg
```

The page uses `settings/get`, `settings/servers` and `service/progress` under
`/api/speedtest/`. POST actions `settings/set`, `settings/refresh`, `service/run`
and `service/clear` enforce read-only account restrictions. A background run
returns immediately, refuses overlapping tests, and prevents clearing an active
test. Failed server refreshes retain the previous cache.

Native checks:

```sh
php tests/native/test-api.php
php tests/native/check-undefined.php
python3 -B -m unittest discover -s tests -v
```

The package bundles the MIT-licensed `speedtest-go` 1.7.10 engine.
