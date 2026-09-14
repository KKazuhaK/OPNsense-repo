"""Build private copies of the real helper with no live language or WebGUI access."""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time

SOURCE = Path(__file__).parents[1] / 'src/usr/local/opnsense/scripts/langtool/manage.php'
PHP = shutil.which('php')


def replace_once(source, original, replacement):
    if source.count(original) != 1:
        raise AssertionError('The helper changed; review fixture isolation before running it.')
    return source.replace(original, replacement, 1)


def replace_function(source, name, replacement):
    source, count = re.subn(r'function ' + name + r'\([^\n]*\)\n\{.*?\n\}', lambda _: replacement, source, flags=re.S)
    if count != 1:
        raise AssertionError('The helper changed; review fixture isolation before running it.')
    return source


class HelperFixture:
    def __init__(self, root, native=False):
        self.root = Path(root)
        self.state = self.root / 'state'
        self.install = self.root / 'installed'
        self.install.mkdir()
        self.configuration = self.root / 'config.xml'
        self.configuration.write_text('<opnsense><system><language>en_US</language></system></opnsense>')
        self.version = self.root / 'version.json'
        self.version.write_text(json.dumps({'CORE_PKGVERSION': 'fixture-26.7'}))
        source = SOURCE.read_text()
        source = replace_once(source, "const LANGTOOL_STATE = '/var/db/os-lang';", f'const LANGTOOL_STATE = {json.dumps(str(self.state))};')
        source = replace_once(source, "const LANGTOOL_INSTALL_ROOT = '/usr/local';", f'const LANGTOOL_INSTALL_ROOT = {json.dumps(str(self.install))};')
        if source.count("'/conf/config.xml'") != 2:
            raise AssertionError('Review language-read isolation after a source change.')
        source = source.replace("'/conf/config.xml'", json.dumps(str(self.configuration)))
        source = replace_once(source, "'/usr/local/opnsense/version/core'", json.dumps(str(self.version)))
        # Always replace reload, including for library tests. No fixture can
        # restart WebGUI or touch its caches even if a test invokes install.
        source = replace_function(source, 'langtool_reload_webgui', '''function langtool_reload_webgui(&$log)
{
    file_put_contents(LANGTOOL_STATE . '/private-reload', 'fixture');
    langtool_log($log, 'isolated reload completed');
}''')
        self.library_source = source
        installer = '''function langtool_install(&$log, &$readme)
{
    file_put_contents(LANGTOOL_STATE . '/workers', getmypid() . "\\n", FILE_APPEND);
    langtool_log($log, 'isolated download started');
    file_put_contents(LANGTOOL_STATE . '/entered', 'fixture');
    $deadline = microtime(true) + 10;
    $progress = 0;
    while (!file_exists(LANGTOOL_STATE . '/release')) {
        if (microtime(true) > $deadline) { throw new RuntimeException('fixture timed out'); }
        langtool_log($log, 'isolated progress ' . ++$progress);
        usleep(20000);
    }
    $behavior = trim((string)@file_get_contents(LANGTOOL_STATE . '/behavior'));
    if ($behavior === 'throw') { throw new RuntimeException('PRIVATE_INSTALL_SENTINEL'); }
    $readme = 'isolated worker: 中文 ' . $behavior;
    langtool_log($log, $behavior === 'fail' ? 'isolated install failed' : 'isolated install completed');
    return $behavior !== 'fail';
}'''
        source = replace_function(source, 'langtool_install', installer)
        if not native:
            launcher = self.root / 'launch.py'
            launcher.write_text('import os,subprocess,sys\nif os.environ.get("LANGTOOL_TEST_LAUNCH_FAIL"):sys.exit(1)\nsubprocess.Popen(sys.argv[1:],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)\n')
            prefix = shlex.quote(sys.executable) + ' ' + shlex.quote(str(launcher)) + ' ' + shlex.quote(PHP or 'php') + ' '
            source = replace_once(source, "'/usr/sbin/daemon -f /usr/local/bin/php '", json.dumps(prefix))
        self.helper = self.root / 'manage.php'
        self.helper.write_text(source)

    def request(self, action='status', **environment):
        result = subprocess.run([PHP, '-d', 'display_errors=stderr', str(self.helper), action], env={**os.environ, **environment}, text=True, capture_output=True, timeout=15)
        if result.returncode or result.stderr:
            raise AssertionError('The isolated helper crashed or emitted PHP diagnostics: ' + result.stderr)
        return json.loads(result.stdout)

    def wait(self, predicate, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            current = self.request()
            if predicate(current):
                return current
            time.sleep(0.025)
        raise AssertionError('The isolated queue did not reach its expected state.')

    def release(self, behavior='success'):
        self.state.mkdir(exist_ok=True)
        (self.state / 'behavior').write_text(behavior)
        (self.state / 'release').touch()

    def close(self):
        self.release()
        if (self.state / 'workers').exists():
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if not self.request().get('running'):
                    return
                time.sleep(0.025)
            # Only terminate PIDs recorded by this private synthetic installer.
            for pid in (self.state / 'workers').read_text().splitlines():
                try:
                    os.kill(int(pid), signal.SIGTERM)
                except ProcessLookupError:
                    pass

    def library(self, body, checksum=''):
        source = replace_once(self.library_source, "const LANGTOOL_EXPECTED_SHA256 = '';", f'const LANGTOOL_EXPECTED_SHA256 = {json.dumps(checksum)};')
        source = replace_once(source, "'/usr/local/bin/python3 '", json.dumps(shlex.quote(sys.executable) + ' '))
        marker = '\ntry {\n'
        if source.count(marker) != 1:
            raise AssertionError('The CLI changed; review library fixture isolation.')
        source = source.split(marker, 1)[0] + '\n' + body
        helper = self.root / 'library.php'
        helper.write_text(source)
        self.state.mkdir(exist_ok=True)
        return helper
