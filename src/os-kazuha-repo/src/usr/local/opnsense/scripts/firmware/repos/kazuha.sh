#!/bin/sh
set -eu

# core reaches this hook through system_firmware_configure(), which runs it with
# no arguments at boot from rc.bootup, from rc.reload_all, from the
# firmware_reload pluginctl hook and from rc.configure_firmware once a package
# operation has finished.  Those are the moments the repository configuration
# has to be right, and they are also the only moments the set of installed
# plugins can have changed.  That is why the plugin manifest is maintained from
# here too: this package is allowed exactly one executable, and core already
# invites that executable to run everywhere the manifest needs refreshing.  No
# second file, no service, no timer, and nothing for an operator to remember.
verb="${1:-configure}"
argument="${2:-}"

root="${KAZUHA_REPO_ROOT:-}"
case "$root" in ''|/*) ;; *) echo 'error: repository root must be absolute' >&2; exit 1 ;; esac
root="${root%/}"
fingerprint=92e83cb0267c3ef27cb355bc2f045c3449fd5c741d1030c7a90c879b00fa5e9b

# The schema version travels inside the section so that a model introduced later
# can migrate a manifest this hook wrote before that model existed.
manifest_schema=1.0.0

configure_repository() {
    source_key="$root/usr/local/share/kazuha-repo/kazuha.pub"
    if [ ! -f "$source_key" ] || [ "$(sha256 -q "$source_key")" != "$fingerprint" ]; then
        echo 'error: repository public key does not match the trust anchor' >&2
        exit 1
    fi
    series="$(opnsense-version -x)"
    case "$series" in [0-9][0-9].[17]) ;; *) echo 'error: invalid OPNsense release series' >&2; exit 1 ;; esac
    suffix="/$series"
    [ "$series" != '26.7' ] || suffix=''

    keys="$root/usr/local/etc/pkg/keys"
    repos="$root/usr/local/etc/pkg/repos"
    install -d -m 0755 "$keys" "$repos"
    key_tmp="$(mktemp "$keys/.kazuha.pub.XXXXXX")"
    config_tmp="$(mktemp "$repos/.kazuha.conf.XXXXXX")"
    trap 'rm -f "$key_tmp" "$config_tmp"' EXIT
    trap 'exit 1' HUP INT TERM
    install -m 0644 "$source_key" "$key_tmp"
    # pkg expands the ABI placeholder after the hook selects the firmware series.
    # shellcheck disable=SC2016
    printf 'kazuha: {\n  url: "https://kkazuhak.github.io/OPNsense-repo/repo/${ABI}%s",\n  signature_type: "pubkey",\n  pubkey: "/usr/local/etc/pkg/keys/kazuha.pub",\n  priority: 10,\n  enabled: yes\n}\n' "$suffix" > "$config_tmp"
    chmod 0644 "$config_tmp"
    mv -f "$key_tmp" "$keys/kazuha.pub"
    mv -f "$config_tmp" "$repos/kazuha.conf"
    # The repository is configured and committed.  Nothing below may undo that,
    # so the cleanup that guarded the two temporary files retires with them.
    trap - EXIT HUP INT TERM
}

# Why the manifest exists at all: register.php falls through from 'sync' to
# 'resync' whenever <trigger_initial_wizard/> is set, and resync unregisters
# every plugin it cannot find on disk.  That flag is in the factory default
# configuration, so a freshly installed router that has just had a backup
# restored onto it empties <system><firmware><plugins> before anything can be
# installed from it.  resync only ever edits that one element, so a list kept
# anywhere else survives -- and //OPNsense/KazuhaRepo/backup is anywhere else.

# Names and versions read back out of a restored configuration are operator
# data that end up in front of pkg, so only the shapes pkg itself could have
# produced get through this filter.  It also sorts and de-duplicates, and
# because the later assignment to an entry wins, feeding it the stored manifest
# followed by what is installed right now performs the whole merge: an entry
# that is installed takes the installed version, an entry that is not installed
# is simply carried over unchanged.
sanitise_manifest() {
    awk '
        NF == 2 && $1 ~ /^os-[a-z0-9][a-z0-9-]*$/ && $2 ~ /^[0-9A-Za-z._,+~-]+$/ { version[$1] = $2 }
        END { for (name in version) print name, version[name] }
    ' | LC_ALL=C sort
}

# pkg answers two different questions and neither answer alone is complete.  It
# records the repository a package was installed from, which is exact but reads
# "unknown-repository" for anything side-loaded with pkg add, and side-loading
# is how a build reaches a router before it is published.  The catalog knows
# which names this repository offers, which covers that build but is only as
# fresh as the last pkg update.  A plugin belongs in the manifest if either
# answer claims it.
enumerate_installed() {
    offered="$(pkg rquery -r kazuha '%n' 2>/dev/null || true)"
    pkg query '%R|%n|%v' 2>/dev/null | _KAZUHA_OFFERED="$offered" awk -F'|' '
        BEGIN { total = split(ENVIRON["_KAZUHA_OFFERED"], names, "\n"); for (i = 1; i <= total; i++) ours[names[i]] = 1 }
        $1 == "kazuha" || ($2 in ours) { print $2, $3 }
    '
}

# The shim below is the only thing here that touches config.xml, and it is
# deliberately ignorant: one text document out, one text document in.  Every
# decision about what that document should contain is made in this file, in
# shell, where the suite can reach it.
run_shim() {
    _KAZUHA_VERB="$1" _KAZUHA_PLUGINS="${2:-}" _KAZUHA_SCHEMA="$manifest_schema" php <<'PHP'
<?php

/*
 * A router's configuration singleton owns /conf/config.xml: it takes the
 * exclusive lock, rotates /conf/backup and records the audit revision, so the
 * write is asked of it rather than made at the file.  KAZUHA_REPO_ROOT is the
 * same rooting the rest of this hook honours; under it there is no singleton to
 * ask and the document is read and written where that root says it lives.
 */

use OPNsense\Core\Config;

function backup_lock_current(Config $config): void
{
    $config->lock();
    /* Core's stream reader can downgrade the lock during reload. Reacquire
       exclusive mode and refresh the mutable document without another reader. */
    $config->lock(false);
    $settings = new \OPNsense\Core\AppConfig();
    $fresh = simplexml_load_string(
        file_get_contents($settings->application->configDir . '/config.xml'),
        'SimpleXMLElement',
        LIBXML_NOBLANKS | LIBXML_NONET
    );
    if ($fresh === false) {
        throw new RuntimeException('The current configuration could not be read.');
    }
    $source = dom_import_simplexml($fresh);
    $destination = dom_import_simplexml($config->object());
    while ($destination->firstChild !== null) {
        $destination->removeChild($destination->firstChild);
    }
    foreach ($source->childNodes as $child) {
        $destination->appendChild($destination->ownerDocument->importNode($child, true));
    }
}

function kazuha_manifest_shim(): int
{
    $verb = (string)getenv('_KAZUHA_VERB');
    if ($verb !== 'read' && $verb !== 'write') {
        return 1;
    }

    $root = rtrim((string)getenv('KAZUHA_REPO_ROOT'), '/');
    if ($root === '') {
        require_once('script/load_phalcon.php');
        $config = OPNsense\Core\Config::getInstance();
        if ($verb === 'write') {
            backup_lock_current($config);
        }
        $document = $config->object();
        $unlock = function () use ($config) { $config->unlock(); };
        $commit = function () use ($config) {
            $config->save();
        };
    } else {
        $file = $root . '/conf/config.xml';
        $handle = is_file($file) ? fopen($file, 'r+') : false;
        if ($handle === false || !flock($handle, $verb === 'write' ? LOCK_EX : LOCK_SH)) {
            return 1;
        }
        $document = simplexml_load_string(stream_get_contents($handle), 'SimpleXMLElement', LIBXML_NONET);
        $unlock = function () use ($handle) { flock($handle, LOCK_UN); fclose($handle); };
        if ($document === false) {
            return 1;
        }
        $commit = function () use ($document, $handle) {
            rewind($handle);
            ftruncate($handle, 0);
            fwrite($handle, $document->asXML());
            fflush($handle);
        };
    }

    try {
        $section = $document;
        foreach (['OPNsense', 'KazuhaRepo', 'backup'] as $name) {
            if (!isset($section->$name)) {
                /* An absent section reads as an empty manifest; only a write creates it. */
                if ($verb !== 'write') {
                    return 0;
                }
                $section->addChild($name);
            }
            $section = $section->$name;
        }

        if ($verb === 'read') {
            echo (string)$section->plugins;
            return 0;
        }

        /* A save rotates a backup and burns a revision, so only a real change earns one. */
        $plugins = (string)getenv('_KAZUHA_PLUGINS');
        if ((string)$section->plugins === $plugins) {
            echo "unchanged\n";
            return 0;
        }

        foreach (['version' => (string)getenv('_KAZUHA_SCHEMA'),
                  'updated' => gmdate('Y-m-d\TH:i:s\Z'),
                  'plugins' => $plugins] as $name => $value) {
            if (!isset($section->$name)) {
                $section->addChild($name);
            }
            /* Assignment escapes the value; addChild would not. */
            $section->$name = $value;
        }

        $commit();
        echo "changed\n";
        return 0;
    } finally {
        $unlock();
    }
}

try {
    exit(kazuha_manifest_shim());
} catch (Throwable $error) {
    fwrite(STDERR, "The repository plugin manifest could not be synchronized.\n");
    exit(1);
}
PHP
}

manifest_read() {
    stored_document="$(run_shim read)" || return 1
    printf '%s\n' "$stored_document" | sanitise_manifest
}

mirror_manifest() {
    # Mirroring is a courtesy to a future restore.  It must never be able to
    # fail the repository configuration that has already been committed above,
    # so every step here is allowed to give up without a word.
    command -v php >/dev/null 2>&1 || return 0
    stored="$(manifest_read)" || return 0
    merged="$(printf '%s\n%s\n' "$stored" "$(enumerate_installed)" | sanitise_manifest)"
    # Nothing is ever taken out of the manifest here.  "Not installed at this
    # moment" and "never install this again" are indistinguishable from inside a
    # hook, and only one of them can be recovered afterwards: a router that has
    # just had a configuration restored onto it has none of these plugins
    # installed yet, which is exactly when the manifest has to survive intact.
    # An entry is dropped on purpose, by an operator, through the forget verb.
    # Compare against the raw XML in the shim: sanitisation can have removed
    # invalid stored entries even when the merged valid entries are unchanged.
    run_shim write "$merged"
}

require_php() {
    command -v php >/dev/null 2>&1 || { echo 'error: php is unavailable' >&2; exit 1; }
}

case "$verb" in
configure)
    configure_repository
    mirror_manifest || true
    ;;
mirror)
    require_php
    mirror_manifest
    ;;
manifest)
    # What client.sh reads back on a restored router: one "name version" line
    # per plugin, sorted, empty when this router has never recorded anything.
    require_php
    manifest_read
    ;;
forget)
    case "$argument" in
    os-[a-z0-9]*) ;;
    *) echo 'error: forget needs a plugin name' >&2; exit 1 ;;
    esac
    require_php
    remaining="$(manifest_read)"
    kept="$(printf '%s\n' "$remaining" | awk -v drop="$argument" '$1 != drop')"
    [ "$kept" != "$remaining" ] || exit 0
    run_shim write "$kept"
    ;;
*)
    echo 'usage: kazuha.sh [configure | mirror | manifest | forget os-<plugin>]' >&2
    exit 1
    ;;
esac
