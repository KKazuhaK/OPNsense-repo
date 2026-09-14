# Regression tests

From the repository root:

```sh
python3 -m pip install -r src/os-unboundcustom/tests/requirements.txt
python3 -B -m unittest discover -s src/os-unboundcustom/tests -v
```

The suite executes the real apply script and package hooks against private
fragments and harmless command stubs. It checks validation before restart,
backup-copy failure, rollback of both exact copies and permissions, restoration
of prior absence, lock contention, and preservation of other includes. Actual
Jinja2 rendering preserves enabled directives verbatim and emits no disabled
directives. PHP, when present, exercises the real controllers' request-method,
read-only and apply-result handling with isolated framework stubs.

On OPNsense, the same command also uses the genuine Core model and field types
with private XML. It checks Boolean state, exact Unicode/CRLF directives and
unrelated XML preservation. Native FreeBSD `pkg` builds are confined to temporary
directories and verify ABI, every source file, executable actions and decoded
hooks. No package is installed and no live resolver, configd or system XML is
changed. Native checks skip on other platforms.
