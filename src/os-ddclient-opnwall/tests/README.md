# Regression tests

From the repository root, use Python 3 with the dependencies listed here:

```sh
python3 -m pip install -r src/os-ddclient-opnwall/tests/requirements.txt
python3 -B -m unittest discover -s src/os-ddclient-opnwall/tests -v
```

The suite runs the real provider code with mocked HTTP and address discovery,
checks successful and failed state transitions, renders both backends' actual
Jinja2 templates, and executes package hooks and statistics parsing in private
fixtures. It never contacts DNS providers or starts services. PHP, when present,
runs the real model validation and controllers with isolated framework stubs.

On OPNsense, the same command also runs the genuine Core model and field types
against a private XML file. It checks update-only credential redaction and
retention, disabled state, validation, and unrelated XML preservation. Native
FreeBSD `pkg` builds are confined to temporary directories and verify native
ABI, every shipped source file, executable service paths and decoded hooks;
packages are not installed. These native checks skip on other platforms.
