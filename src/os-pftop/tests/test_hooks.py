"""Execute package hooks under a private filesystem prefix and service stand-ins."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

PACKAGE = Path(__file__).resolve().parents[1]


class HookTests(unittest.TestCase):
    def test_install_removes_legacy_page_and_caches_then_uses_service_fallback(self):
        with tempfile.TemporaryDirectory(prefix='pftop-hooks-') as temporary:
            root = Path(temporary)
            legacy = root / 'usr/local/www/diag_pftop.php'
            menu = root / 'var/lib/php/tmp/opnsense_menu_cache.xml'
            acl = root / 'var/lib/php/tmp/opnsense_acl_cache.json'
            for path in [legacy, menu, acl]:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('retired fixture')
            owned = root / 'usr/local/opnsense/scripts/pftop/snapshot.py'
            owned.parent.mkdir(parents=True)
            owned.write_text('fixture')
            owned.chmod(0o600)
            events = root / 'events'
            source = (PACKAGE / 'packaging/freebsd/+POST_INSTALL').read_text()
            source = re.sub(r'(?<![A-Za-z0-9_./-])/(usr/local|var)(?=/)', lambda match: str(root / match.group(1)), source)
            source = source.replace('#!/bin/sh', '''#!/bin/sh
service() { printf 'service %s\\n' "$*" >> "$PFTOP_TEST_EVENTS"; }
configctl() { printf 'configctl %s\\n' "$*" >> "$PFTOP_TEST_EVENTS"; return 1; }
''', 1)
            candidate = root / 'post-install'
            candidate.write_text(source)
            process = subprocess.run(['sh', str(candidate)], capture_output=True, text=True,
                                     env={**os.environ, 'PFTOP_TEST_EVENTS': str(events)}, timeout=5)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertFalse(any(path.exists() for path in [legacy, menu, acl]))
            self.assertEqual(owned.stat().st_mode & 0o777, 0o644)
            self.assertEqual(events.read_text().splitlines(), ['service configd restart', 'configctl webgui restart',
                                                               'service lighttpd onerestart'])

    def test_deinstall_only_clears_caches_and_noop_pre_deinstall_runs_no_commands(self):
        with tempfile.TemporaryDirectory(prefix='pftop-hooks-') as temporary:
            root = Path(temporary)
            preserved = root / 'usr/local/opnsense/scripts/pftop/snapshot.py'
            preserved.parent.mkdir(parents=True)
            preserved.write_text('keep fixture')
            cache = root / 'var/lib/php/tmp/opnsense_menu_cache.xml'
            cache.parent.mkdir(parents=True)
            cache.write_text('cache')
            events = root / 'events'
            for hook in ['+PRE_DEINSTALL', '+POST_DEINSTALL']:
                source = (PACKAGE / 'packaging/freebsd' / hook).read_text()
                source = re.sub(r'(?<![A-Za-z0-9_./-])/(usr/local|var)(?=/)', lambda match: str(root / match.group(1)), source)
                source = source.replace('#!/bin/sh', '#!/bin/sh\nservice() { echo service >> "$PFTOP_TEST_EVENTS"; }\n'
                                        'configctl() { echo configctl >> "$PFTOP_TEST_EVENTS"; }\n', 1)
                candidate = root / hook
                candidate.write_text(source)
                process = subprocess.run(['sh', str(candidate)], capture_output=True,
                                         env={**os.environ, 'PFTOP_TEST_EVENTS': str(events)}, timeout=5)
                self.assertEqual(process.returncode, 0, process.stderr)
                if hook == '+PRE_DEINSTALL':
                    self.assertFalse(events.exists())
                    self.assertTrue(cache.exists())
            self.assertFalse(cache.exists())
            self.assertEqual(preserved.read_text(), 'keep fixture')
            self.assertEqual(events.read_text().splitlines(), ['configctl'])


if __name__ == '__main__':
    unittest.main()
