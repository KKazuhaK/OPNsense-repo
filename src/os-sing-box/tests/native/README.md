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
