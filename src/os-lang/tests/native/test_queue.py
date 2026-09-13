#!/usr/local/bin/python3
"""Exercise daemon handoff and native file locking with an isolated installer."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[2] / 'src/usr/local/opnsense/scripts/langtool/manage.php'


@unittest.skipUnless(Path('/usr/sbin/daemon').exists() and shutil.which('php'), 'requires native FreeBSD daemon and PHP')
class QueueTest(unittest.TestCase):
    def test_worker_completes_after_queue_handoff(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / 'state'
            source = SOURCE.read_text().replace("const LANGTOOL_STATE = '/var/db/os-lang';", "const LANGTOOL_STATE = '" + str(state) + "';")
            # Keep the real queue, daemon, locking and status code. Only replace
            # download/install so this regression test cannot alter live files.
            source = re.sub(r'function langtool_install\(&\$log, &\$readme\)\n\{.*?\n\}', "function langtool_install(&$log, &$readme)\n{\n    $readme = 'isolated worker';\n    langtool_log($log, 'isolated install completed');\n    return true;\n}", source, flags=re.S)
            helper = root / 'manage.php'
            helper.write_text(source)
            queued = json.loads(subprocess.check_output(['php', str(helper), 'update'], text=True))
            self.assertEqual(queued['status'], 'ok')
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                current = json.loads(subprocess.check_output(['php', str(helper), 'status'], text=True))
                if not current.get('running'):
                    self.assertEqual(current['status'], 'ok')
                    self.assertEqual(current['readme'], 'isolated worker')
                    self.assertIn('isolated install completed', current['log'])
                    break
                time.sleep(0.1)
            else:
                self.fail('Daemon worker left the queue permanently busy.')


if __name__ == '__main__':
    unittest.main()
