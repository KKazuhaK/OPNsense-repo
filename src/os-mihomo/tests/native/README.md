# Native checks

The VNET jail harness replaces `config.inc`, `configctl` and `service` with test
adapters, so a script that calls a function the real OPNsense tree defines
elsewhere passes there and fails on a router. `setup_unbound.php` did exactly
that: it required `config.inc` alone, and `config.inc` reaches for
`shell_safe()` from `util.inc` when it stamps a configuration revision, so
every write failed the moment it was attempted on a real system.

`check-undefined.php` resolves every function each CLI entry point calls after
that entry point's own includes have run. Run it on the target:

```sh
php src/os-mihomo/tests/native/check-undefined.php
```

It needs the real tree and therefore cannot run in CI or on the build host.
