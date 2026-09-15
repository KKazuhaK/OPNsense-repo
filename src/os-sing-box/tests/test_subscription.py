"""Run the subscription shell entry point and assert direct, private fetching."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'src/usr/local/etc/sing-box/sub/sub.sh'


class DirectSubscriptionTests(unittest.TestCase):
    def test_direct_url_private_argv_and_log_with_http_failure_no_retry(self):
        for status in ('200', '404'):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                shutil.copyfile(SCRIPT, root / 'sub.sh')
                (root / 'env').write_text("SING_BOX_URL='https://example.invalid/SENTINEL_TOKEN'\n")
                for name, code in {
                    'curl': '''import os,sys,json\nfrom pathlib import Path\na=sys.argv[1:]; c=Path(a[a.index('--config')+1]); assert c.stat().st_mode & 0o777 == 0o600; assert c.read_text() == 'url = "https://example.invalid/SENTINEL_TOKEN"\\n'; assert not any('SENTINEL_TOKEN' in x for x in a); Path(os.environ['TRACE']).write_text(json.dumps(a)); Path(a[a.index('--output')+1]).write_text('{"outbounds":[{"type":"direct"}]}'); print(os.environ['HTTP_STATUS'],end='')''',
                    'jq': 'import json,sys; json.load(open(sys.argv[-1]))',
                    'core': 'import sys; assert sys.argv[1] == "check"',
                    'service': 'import sys; assert sys.argv[1:] in (["sing-box", "onestatus"], ["sing-box", "onerestart"])',
                }.items():
                    path = root / name
                    path.write_text('#!' + sys.executable + '\n' + code + '\n')
                    path.chmod(0o755)
                result = subprocess.run(['sh', str(root / 'sub.sh')], capture_output=True, text=True,
                    env=dict(os.environ, PATH=str(root)+':'+os.environ['PATH'], TRACE=str(root/'trace'), HTTP_STATUS=status, SING_BOX_BIN=str(root/'core'), SING_BOX_FORMAL_CONFIG=str(root/'config.json')))
                self.assertEqual(0 if status=='200' else 1, result.returncode, result.stderr)
                self.assertNotIn('SENTINEL_TOKEN', result.stdout + result.stderr)
                args = json.loads((root / 'trace').read_text())
                self.assertNotIn('--retry', args)
                self.assertNotIn('--retry-all-errors', args)
                if status=='200':
                    self.assertEqual([{'type':'direct'}], json.loads((root/'config.json').read_text())['outbounds'])
                    self.assertEqual(0o600, (root/'config.json').stat().st_mode & 0o777)

    def test_subscription_update_keeps_an_explicitly_stopped_service_stopped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copyfile(SCRIPT, root / 'sub.sh')
            (root / 'env').write_text("SING_BOX_URL='https://example.invalid/private-subscription'\n")
            for name, code in {
                'curl': 'import sys,json; from pathlib import Path; a=sys.argv[1:]; Path(a[a.index("--output")+1]).write_text(json.dumps({"outbounds":[{"type":"direct"}]})); print("200",end="")',
                'jq': 'import json,sys; json.load(open(sys.argv[-1]))',
                'core': 'import sys; assert sys.argv[1] == "check"',
                'service': 'import sys; assert sys.argv[1:] == ["sing-box", "onestatus"]; sys.exit(1)',
            }.items():
                path = root / name
                path.write_text('#!' + sys.executable + '\n' + code + '\n')
                path.chmod(0o755)
            result = subprocess.run(['sh', str(root / 'sub.sh')], capture_output=True, text=True,
                env=dict(os.environ, PATH=str(root)+':'+os.environ['PATH'],
                         SING_BOX_BIN=str(root/'core'), SING_BOX_FORMAL_CONFIG=str(root/'config.json')))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((root/'config.json').read_text())['outbounds'], [{'type': 'direct'}])


if __name__ == '__main__':
    unittest.main()
