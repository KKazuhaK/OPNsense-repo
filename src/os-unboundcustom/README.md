# Unbound Custom Options for OPNsense

An updated replacement for `os-unboundcustom-maxit` targeting OPNsense 26.7.

## Safety behaviour

The plugin renders its dedicated fragment and a complete include tree below the
root-only `/var/db/os-unboundcustom` state directory, validates that candidate
with `unbound-checkconf`, and only then durably publishes the live fragments.
Candidate reads reject links, non-regular files, oversized files, and files
that change while they are being copied. A disabled first installation does
not restart DNS.
Repeated applications keep the running resolver when the complete generated
include closure still matches the receipt for that exact process. Changed
listeners, other plugin includes, and unknown include forms require a restart.
A resolver intentionally stopped by the administrator remains stopped.

Validation and template failures restore the previous owned fragments. Restarts
verify the original native Unbound executable, configuration argument, PID and
kernel birth time, then stop it and directly launch the validated runtime
configuration. The main configuration and other includes are not regenerated
from pending OPNsense settings. Full restarts retain support for listener and
remote-control changes that cannot take effect on reload. A concurrent Stop or
replacement resolver is preserved. If startup fails, the plugin restores its
fragments and directly starts the previous configuration; only its own launched
process may be stopped for recovery. Recovery failures are reported explicitly.
An existing corrupt or unsupported transaction receipt blocks apply and removal
before changing files or DNS; it never falls back to legacy marker ownership.
Removal preserves foreign same-named fragments and subsequent administrator
edits. The private receipt is accepted only with its exact owner and mode;
corrupt, linked, or permission-weakened state is never used as ownership
authority. Upgrade removal hooks
preserve the owned fragments; install/remove no longer restart the Web GUI.
The outgoing hooks of a previously installed package still govern the first
upgrade from that old version, including its historical DNS restart behaviour.

Custom directives still require knowledge of `unbound.conf`. They are inserted
verbatim and can override or conflict with settings managed by OPNsense.

All user-visible strings follow the standard OPNsense gettext format. The
plugin does not modify `OPNsense.mo` and contains no built-in language
selection. Add the entries listed in `translations/OPNsense-unboundcustom.pot`
to the desired system language catalog; untranslated strings remain English.

## Source layout

Files under `src/` mirror their locations below `/usr/local` on OPNsense. The
top-level Makefile follows the standard OPNsense plugins build framework.

## Standalone build

Run the build on an amd64 FreeBSD or OPNsense system with `pkg` available:

```sh
chmod +x build.sh
./build.sh
```

The resulting package is written to `dist/os-unboundcustom.pkg`. The default
package uses the portable `FreeBSD:*:amd64` ABI. Use `ABI=native ./build.sh` to
bind it to the build host's FreeBSD major version, or override other metadata,
for example `VERSION=1.2.9 OUTPUT_NAME=os-unboundcustom-1.2.9.pkg ./build.sh`.

## Apply without the UI

```sh
configctl unboundcustom apply
```
