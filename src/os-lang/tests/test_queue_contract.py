"""Exercise real queue locking and atomic progress with an isolated installer."""
from concurrent.futures import ThreadPoolExecutor
import fcntl
import json
import tempfile
import time
import unittest

from fixture import HelperFixture, PHP, replace_once


@unittest.skipUnless(PHP, 'requires PHP CLI')
class QueueContractTests(unittest.TestCase):
    native_daemon = False

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='lang-contract-')
        self.addCleanup(self.temporary.cleanup)
        self.fixture = HelperFixture(self.temporary.name, native=self.native_daemon)
        self.addCleanup(self.fixture.close)

    def start(self):
        self.assertEqual(self.fixture.request('update'), {'status': 'ok', 'running': True})
        return self.fixture.wait(lambda status: 'isolated download started' in status.get('log', ''))

    def finish(self, behavior='success'):
        self.fixture.release(behavior)
        return self.fixture.wait(lambda status: not status.get('running'))

    def test_concurrent_requests_launch_one_worker_and_publish_live_progress(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(pool.map(lambda _: self.fixture.request('update'), range(8)))
        self.assertEqual(sum(response['status'] == 'ok' for response in responses), 1)
        for response in responses:
            if response['status'] == 'failed':
                self.assertIn('already running', response['error'])
        running = self.fixture.wait(lambda status: 'isolated download started' in status.get('log', ''))
        self.assertTrue(running['running'])
        self.assertEqual((self.fixture.state / 'workers').read_text().count('\n'), 1)
        for _ in range(25):
            self.assertTrue(json.loads((self.fixture.state / 'status.json').read_text())['running'])
            time.sleep(0.005)
        self.assertEqual((self.fixture.state / 'status.json').stat().st_mode & 0o777, 0o600)
        finished = self.finish()
        self.assertEqual(finished['status'], 'ok')
        self.assertIn('中文', finished['readme'])
        self.assertIn('isolated install completed', finished['log'])
        self.assertEqual(list(self.fixture.state.glob('.status.*')), [])
        self.assertFalse((self.fixture.state / 'private-reload').exists())

    def test_worker_failure_releases_queue_and_allows_another_update(self):
        self.start()
        failed = self.finish('fail')
        self.assertEqual(failed['status'], 'failed')
        self.assertFalse(failed['running'])
        self.assertIn('isolated install failed', failed['log'])
        (self.fixture.state / 'release').unlink()
        self.start()
        self.assertEqual(self.finish()['status'], 'ok')
        self.assertEqual((self.fixture.state / 'workers').read_text().count('\n'), 2)

    def test_worker_exception_is_generic_and_not_permanently_busy(self):
        self.start()
        failed = self.finish('throw')
        self.assertEqual(failed['status'], 'failed')
        self.assertFalse(failed['running'])
        self.assertNotIn('PRIVATE_INSTALL_SENTINEL', json.dumps(failed))
        self.assertEqual(failed['readme'], '')
        self.assertEqual(failed['log'], '')
        self.assertIn('Unable to read or update', failed['error'])

    def test_launch_failure_clears_published_queue(self):
        if self.native_daemon:
            self.skipTest('The native case retains the genuine daemon; portable launcher failure runs in CI.')
        failed = self.fixture.request('update', LANGTOOL_TEST_LAUNCH_FAIL='1')
        self.assertEqual(failed['status'], 'failed')
        self.assertIn('Unable to start', failed['error'])
        self.assertFalse(self.fixture.request()['running'])
        self.assertFalse((self.fixture.state / 'workers').exists())
        self.start()
        self.assertEqual(self.finish()['status'], 'ok')

    def test_stale_progress_recovers_but_held_lock_still_prevents_a_worker(self):
        self.fixture.state.mkdir()
        (self.fixture.state / 'status.json').write_text(json.dumps({'running': True, 'updated': int(time.time()) - 901, 'log': 'old'}))
        self.assertEqual(self.fixture.request()['error'], 'The previous localization update was interrupted.')
        with (self.fixture.state / 'update.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertIn('already running', self.fixture.request('update')['error'])
        self.assertFalse((self.fixture.state / 'workers').exists())
        self.start()
        self.assertEqual(self.finish()['status'], 'ok')

    def test_corrupt_state_unknown_action_and_private_status_metadata(self):
        self.fixture.state.mkdir()
        (self.fixture.state / 'status.json').write_bytes(b'partial invalid JSON \xff')
        status = self.fixture.request()
        self.assertFalse(status['running'])
        self.assertEqual(status['version'], 'fixture-26.7')
        self.assertEqual(status['language'], 'en_us')
        self.assertEqual(self.fixture.request('unknown')['error'], 'Unknown action.')
        self.fixture.configuration.write_text('<opnsense><language>zh-Hant-TW</language></opnsense>')
        self.assertEqual(self.fixture.request()['language'], 'zh_hant_tw')
        self.fixture.version.unlink()
        self.assertEqual(self.fixture.request()['version'], '未知')

    def test_progress_publish_failure_does_not_launch_worker(self):
        self.fixture.state.mkdir()
        (self.fixture.state / 'status.json').mkdir()
        result = self.fixture.request('update')
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['running'])
        self.assertFalse((self.fixture.state / 'workers').exists())
        self.assertEqual(list(self.fixture.state.glob('.status.*')), [])

    def test_raced_state_directory_creation_uses_directory_created_by_another_request(self):
        # Deterministically simulate another request winning mkdir after this
        # request's initial is_dir check, without sleeps or live directories.
        source = replace_once(self.fixture.helper.read_text(), '<?php', '''<?php
namespace PrivateLangDirectoryRace;
use \\Throwable;
use \\RuntimeException;
function mkdir($path, $mode, $recursive = false) {
    \\mkdir($path, $mode, $recursive);
    return false;
}''')
        self.fixture.helper.write_text(source)
        response = self.fixture.request()
        self.assertEqual(response['status'], 'ok')
        self.assertFalse(response['running'])
        self.assertTrue(self.fixture.state.is_dir())
        self.assertFalse((self.fixture.state / 'workers').exists())


if __name__ == '__main__':
    unittest.main()
