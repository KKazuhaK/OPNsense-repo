"""Run the WAN Guard daemon loop and CLI against private directories and fake helpers."""
import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / 'src/usr/local/opnsense/scripts/wanguard'
sys.path.insert(0, str(SCRIPTS))
import guard  # noqa: E402
import wanguard  # noqa: E402

START = 1000.0


def interface(name='opt2', **changes):
    row = {'name': name, 'descr': 'WAN2', 'exists': True, 'device': 'vtnet3', 'enabled': True,
           'ipaddr': 'dhcp', 'eligible': True, 'address': '10.0.3.15', 'carrier': True,
           'dhclient_running': True}
    row.update(changes)
    return row


def observation(rows=None, enabled=True, watched=('opt2',), networks=('10.0.3.0/24',), private=False, booting=False):
    return {'enabled': enabled, 'booting': booting, 'watched': list(watched), 'networks': list(networks),
            'private_ranges': private, 'interfaces': [interface()] if rows is None else rows}


class FakeHelper:
    def __init__(self, answer=None, results=()):
        self.answer = answer or (lambda: observation())
        self.results = list(results)
        self.observed = 0
        self.calls = []

    def observe(self):
        self.observed += 1
        value = self.answer()
        if isinstance(value, Exception):
            raise value
        return guard.parse_snapshot(value)

    def redhcp(self, name, address, reason):
        self.calls.append(('redhcp', name, address))
        return self.results.pop(0) if self.results else 'requested'

    def restore(self, name):
        self.calls.append(('restore', name))
        return 'restored'


class Log(list):
    def __call__(self, level, message):
        self.append((level, message))

    def having(self, text):
        return [line for line in self if text in line[1]]


class Private(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.paths = wanguard.Paths(root / 'run', root / 'db', root / 'wanguard.pid')

    def loop(self, helper, until, events=None, boot='1:1', start=START):
        """Run the real loop on a fake clock; until and events count from start."""
        clock = {'now': start}
        log = Log()
        events = dict(events or {})

        def sleep(seconds):
            clock['now'] += seconds
            for moment in sorted(events):
                if clock['now'] - start >= moment:
                    events.pop(moment)()
            if clock['now'] - start >= until:
                daemon.stop()

        daemon = wanguard.Daemon(self.paths, helper, log, boot, clock=lambda: clock['now'],
                                 wall=lambda: 1790000000 + clock['now'], sleep=sleep)
        self.assertEqual(daemon.run(), 0)
        return log

    def state(self):
        return json.loads(self.paths.state.read_text())


class BootIdTests(Private):
    """boot_id() replaces kern.boottime, which moves on any clock step (the
    acceptance finding this fixes): a random marker under /var/run, which
    FreeBSD clears only at reboot.
    """

    def test_a_marker_is_created_once_and_then_reused(self):
        self.assertFalse(self.paths.boot_marker.exists())
        first = wanguard.boot_id(self.paths)
        self.assertRegex(first, r'\A[0-9a-f]{32}\Z')
        self.assertEqual(self.paths.boot_marker.stat().st_mode & 0o777, 0o600)
        self.assertEqual(wanguard.boot_id(self.paths), first)
        # A clock step is not a reboot: nothing here reads kern.boottime any
        # more, so nothing a clock step touches can change this value.
        self.assertEqual(wanguard.boot_id(self.paths), first)

    def test_the_status_path_and_the_daemon_compute_the_same_marker(self):
        # main() calls boot_id(paths) fresh for both 'run' and 'state'; a
        # second Paths object stands in for that second process, started
        # before or after the first.
        mine = wanguard.boot_id(self.paths)
        other_process = wanguard.Paths(self.paths.run, self.paths.db, self.paths.pidfile)
        self.assertEqual(wanguard.boot_id(other_process), mine)

    def test_a_missing_marker_after_the_run_directory_is_gone_is_a_new_boot(self):
        first = wanguard.boot_id(self.paths)
        shutil.rmtree(self.paths.run)  # what FreeBSD does to /var/run at boot
        second = wanguard.boot_id(self.paths)
        self.assertNotEqual(first, second)
        self.assertRegex(second, r'\A[0-9a-f]{32}\Z')

    def test_a_caller_that_loses_the_creation_race_adopts_the_winners_value(self):
        # Two processes computing a token for the same, still-empty marker at
        # once: this call generates its own, but by the time it tries to
        # claim the name (os.link, where the race is actually settled) the
        # other process's token is already there.
        winner = 'b' * 32

        def another_process_wins_first(source, target):
            self.paths.boot_marker.write_text(winner + '\n')
            os.chmod(self.paths.boot_marker, 0o600)
            raise FileExistsError()

        with mock.patch('os.link', side_effect=another_process_wins_first):
            token = wanguard.boot_id(self.paths)
        self.assertEqual(token, winner)
        # Not just this call: the marker on disk is what every later caller,
        # including this same one asked again, must agree on.
        self.assertEqual(wanguard.boot_id(self.paths), winner)
        self.assertFalse(list(self.paths.run.glob('.boot-id.*')), 'the loser must not leave its temp file behind')

    def test_a_marker_that_fails_validation_is_replaced_not_left_stuck(self):
        self.paths.run.mkdir(mode=0o700, parents=True)
        self.paths.boot_marker.write_text('not a valid token\n')
        token = wanguard.boot_id(self.paths)
        self.assertRegex(token, r'\A[0-9a-f]{32}\Z')
        # It was actually written this time, unlike the invalid one before it.
        self.assertEqual(wanguard.boot_id(self.paths), token)

    def test_boot_id_no_longer_reads_the_clock_at_all(self):
        # The direct regression guard for the acceptance finding: kern.
        # boottime (sec:usec) moves on any clock step with no reboot
        # involved (NTP's first correction, a manual time set), which used to
        # make a daemon restart or a status query discard or hide state.json
        # for no real reboot. boot_id() must not consult the clock, or any
        # subprocess, to tell one boot from another any more.
        with mock.patch('subprocess.run', side_effect=AssertionError('boot_id must not run a subprocess')):
            token = wanguard.boot_id(self.paths)
        self.assertRegex(token, r'\A[0-9a-f]{32}\Z')


class LoopTests(Private):
    def test_observes_at_start_and_every_thirty_seconds(self):
        helper = FakeHelper(lambda: observation(rows=[interface(address='198.51.100.7')]))
        log = self.loop(helper, 95)
        self.assertEqual(helper.observed, 4)
        self.assertEqual(log[0], ('notice', 'started; observing every 30 s'))
        self.assertEqual(log[-1], ('notice', 'stopped'))
        self.assertEqual(len(log.having('settings: enabled yes; watching opt2; unwanted networks 10.0.3.0/24; '
                                        'private ranges off')), 1)
        self.assertEqual(self.paths.run.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.paths.db.stat().st_mode & 0o777, 0o700)

    def test_confirms_then_acts_on_the_second_observation(self):
        helper = FakeHelper()
        log = self.loop(helper, 35)
        self.assertEqual(helper.calls, [('redhcp', 'opt2', '10.0.3.15')])
        self.assertEqual(self.state()['interfaces']['opt2']['stage'], 1)
        self.assertEqual(len(log.having('re-requesting IPv4 DHCP on opt2')), 1)

    def test_wake_requests_are_consumed_and_bursts_coalesce(self):
        helper = FakeHelper(lambda: observation(rows=[interface(address='198.51.100.7')]))
        events = {10: lambda: wanguard.wake(self.paths), 11: lambda: wanguard.wake(self.paths),
                  12: lambda: wanguard.wake(self.paths)}
        self.loop(helper, 20, events)
        self.assertEqual(helper.observed, 3)
        self.assertFalse(self.paths.wake.exists())

    def test_retry_files_are_consumed_and_bad_names_ignored(self):
        def drop():
            for name in ['retry-opt2', 'retry-BAD', 'retry-' + 'x' * 40, 'retry-']:
                (self.paths.run / name).touch()
        helper = FakeHelper()
        log = self.loop(helper, 8, {5: drop})
        self.assertEqual(helper.calls, [('redhcp', 'opt2', '10.0.3.15')])
        self.assertEqual(self.state()['interfaces']['opt2']['last_action']['trigger'], 'manual')
        self.assertEqual(sorted(os.listdir(self.paths.run)), ['daemon.lock', 'observed.json'])
        self.assertEqual(len(log.having('trigger manual')), 1)

    def test_stale_requests_are_cleared_at_start(self):
        self.paths.run.mkdir(mode=0o700)
        (self.paths.run / 'retry-opt2').touch()
        self.paths.wake.write_text('wan\n')
        helper = FakeHelper()
        self.loop(helper, 5)
        self.assertEqual(helper.observed, 1)
        self.assertEqual(helper.calls, [])
        self.assertFalse(self.paths.wake.exists())

    def test_observation_failures_are_logged_once_per_five_minutes_and_the_loop_continues(self):
        helper = FakeHelper(lambda: guard.ObserveError('the helper did not answer within 20 s'))
        events = {}
        self.paths.run.mkdir(mode=0o700)
        log = self.loop(helper, 700, events)
        self.assertEqual(helper.observed, 24)
        self.assertEqual(len(log.having('observation failed')), 3)
        self.assertEqual(helper.calls, [])

    def test_manual_retry_is_refused_when_the_observation_fails(self):
        helper = FakeHelper(lambda: guard.ObserveError('broken'))
        log = self.loop(helper, 8, {5: lambda: (self.paths.run / 'retry-opt2').touch()})
        self.assertEqual(len(log.having('manual retry on opt2 refused: the interfaces could not be observed')), 1)

    def test_an_unexpected_exception_does_not_end_the_loop(self):
        helper = FakeHelper(lambda: RuntimeError('surprise'))
        log = self.loop(helper, 400)
        self.assertEqual(len(log.having('a cycle failed: RuntimeError: surprise')), 2)
        self.assertEqual(helper.observed, 14)

    def test_a_second_instance_exits_on_the_lock(self):
        self.paths.run.mkdir(mode=0o700)
        holder = os.open(self.paths.daemon_lock, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, holder)
        fcntl.flock(holder, fcntl.LOCK_EX)
        helper = FakeHelper()
        log = self.loop(helper, 5)
        self.assertEqual(helper.observed, 0)
        self.assertEqual(log, [('notice', 'another WAN Guard daemon is already running')])

    def test_state_is_written_only_when_a_decision_changes(self):
        helper = FakeHelper(lambda: observation(rows=[interface(address='198.51.100.7')]))
        with mock.patch.object(guard.Store, 'save', autospec=True, side_effect=guard.Store.save) as save:
            self.loop(helper, 300)
        self.assertEqual(save.call_count, 1)
        observed = json.loads(self.paths.observed.read_text())
        self.assertEqual(observed['wall'], 1790000000 + START + 270)
        self.assertEqual(observed['interfaces']['opt2']['verdict'], 'wanted')
        self.assertEqual(self.paths.observed.stat().st_mode & 0o777, 0o600)

    def test_a_corrupt_state_file_is_set_aside_and_holds_automatic_actions(self):
        self.paths.db.mkdir(mode=0o700)
        self.paths.state.write_text('{broken')
        os.chmod(self.paths.state, 0o600)
        helper = FakeHelper()
        log = self.loop(helper, 290)
        self.assertEqual(helper.calls, [])
        self.assertTrue((self.paths.db / 'state.json.bad').exists())
        self.assertEqual(len(log.having('was set aside as state.json.bad; automatic actions wait 300 s')), 1)
        self.assertIsNotNone(self.state()['cooldown_until'])

    def test_state_of_an_earlier_boot_is_discarded(self):
        store = guard.Store(str(self.paths.state), '0:0')
        state = guard.new_state('0:0')
        state['interfaces']['opt2'] = dict(guard.new_tracker('vtnet3'), stage=3, next_retry=START + 500)
        store.save(state)
        log = self.loop(FakeHelper(), 35)
        self.assertEqual(len(log.having('earlier boot')), 1)
        self.assertEqual(self.state()['boot'], '1:1')
        self.assertEqual(self.state()['interfaces']['opt2']['stage'], 1)

    def test_a_restart_in_backoff_keeps_the_schedule(self):
        helper = FakeHelper()
        self.loop(helper, 35)
        self.assertEqual(len(helper.calls), 1)
        first = self.state()['interfaces']['opt2']['next_retry']
        self.assertEqual(first, START + 90)
        # The daemon comes back ten seconds later in the same boot: its first
        # observations confirm again but the backoff still holds.
        restarted = FakeHelper()
        self.loop(restarted, 45, start=START + 40)
        self.assertEqual(restarted.observed, 2)
        self.assertEqual(restarted.calls, [])
        self.assertEqual(self.state()['interfaces']['opt2']['next_retry'], first)
        # Once the backoff is over the carried-over confirmation is enough.
        again = FakeHelper()
        self.loop(again, 5, start=START + 100)
        self.assertEqual(again.calls, [('redhcp', 'opt2', '10.0.3.15')])
        self.assertEqual(self.state()['interfaces']['opt2']['stage'], 2)

    def test_a_restart_after_a_long_pause_confirms_again(self):
        self.loop(FakeHelper(), 5)
        self.assertEqual(self.state()['interfaces']['opt2']['streak'], 1)
        restarted = FakeHelper()
        self.loop(restarted, 5, start=START + 3 * guard.HOUR)
        self.assertEqual(restarted.calls, [])
        again = FakeHelper()
        self.loop(again, 35, start=START + 3 * guard.HOUR + 10)
        self.assertEqual(again.calls, [('redhcp', 'opt2', '10.0.3.15')])

    def test_a_stop_during_an_observation_starts_no_action(self):
        holder = {}

        class Stopping(FakeHelper):
            def observe(inner):
                value = super().observe()
                if inner.observed == 2:
                    holder['daemon'].stop()
                return value

        helper = Stopping()
        original = wanguard.Daemon.__init__

        def remember(daemon, *args, **kwargs):
            original(daemon, *args, **kwargs)
            holder['daemon'] = daemon
        with mock.patch.object(wanguard.Daemon, '__init__', remember):
            log = self.loop(helper, 100)
        self.assertEqual(helper.observed, 2)
        self.assertEqual(helper.calls, [])
        self.assertEqual(self.state()['interfaces']['opt2']['streak'], 2)
        self.assertEqual(log[-1], ('notice', 'stopped'))

    def test_settings_changes_are_logged_and_an_empty_rule_set_is_noted(self):
        answers = iter([observation(networks=()), observation(networks=('10.0.3.0/24',))] + [observation()] * 5)
        log = self.loop(FakeHelper(lambda: next(answers)), 35)
        self.assertEqual(len(log.having('settings:')), 2)
        self.assertEqual(len(log.having('nothing is considered unwanted')), 1)


class SignalTests(Private):
    def test_sigterm_stops_the_daemon_within_one_poll(self):
        script = textwrap.dedent('''
            import signal, sys
            sys.path.insert(0, {scripts!r})
            import guard, wanguard
            class Helper:
                def observe(self):
                    print('observed', flush=True)
                    return guard.parse_snapshot({{'enabled': True, 'booting': False, 'watched': [],
                        'networks': [], 'private_ranges': False, 'interfaces': []}})
            paths = wanguard.Paths({run!r}, {db!r}, {pid!r})
            daemon = wanguard.Daemon(paths, Helper(), lambda level, message: None, '1:1')
            signal.signal(signal.SIGTERM, daemon.stop)
            sys.exit(daemon.run())
        ''').format(scripts=str(SCRIPTS), run=str(self.paths.run), db=str(self.paths.db), pid=str(self.paths.pidfile))
        process = subprocess.Popen([sys.executable, '-B', '-c', script], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(), 'observed')
            started = time.monotonic()
            process.send_signal(signal.SIGTERM)
            self.assertEqual(process.wait(timeout=5), 0)
            self.assertLess(time.monotonic() - started, 2.5)
        finally:
            if process.poll() is None:
                process.kill()
            process.stdout.close()


class HelperTests(Private):
    def stub(self, body):
        path = Path(self.directory.name) / 'helper.py'
        path.write_text('import json, sys, time\n' + textwrap.dedent(body))
        return wanguard.Helper([sys.executable, '-B', str(path)])

    def test_the_last_json_line_is_the_answer(self):
        helper = self.stub('''
            print('PHP Warning: something harmless')
            print(json.dumps({'enabled': False, 'booting': False, 'watched': [], 'networks': [],
                              'private_ranges': False, 'interfaces': []}))
        ''')
        self.assertFalse(helper.observe()['enabled'])

    def test_output_after_the_answer_or_odd_bytes_do_not_cost_the_answer(self):
        helper = self.stub('''
            sys.stdout.buffer.write(b'PHP Warning: \\xff\\xfe odd bytes\\n')
            print(json.dumps({"result": "requested"}), flush=True)
            sys.stdout.buffer.write(b'PHP Deprecated: after the answer \\xff\\n')
        ''')
        self.assertEqual(helper.redhcp('opt2', '10.0.3.15', 'test'), 'requested')
        self.assertEqual(self.stub('sys.stdout.buffer.write(b"\\xff\\xfe\\n")').redhcp('opt2', '10.0.3.15', 'x'),
                         'failed:helper')

    def test_unusable_answers_raise(self):
        for body in ['print("not json")', 'sys.exit(1)', 'print(json.dumps([1]))',
                     'print(json.dumps({"enabled": 1}))']:
            with self.subTest(body=body), self.assertRaises(guard.ObserveError):
                self.stub(body).observe()

    def test_a_hung_helper_times_out(self):
        helper = self.stub('time.sleep(5)')
        with mock.patch.object(guard, 'OBSERVE_TIMEOUT', 0.5), self.assertRaises(guard.ObserveError):
            helper.observe()
        with mock.patch.object(guard, 'ACTION_TIMEOUT', 0.5):
            self.assertEqual(helper.redhcp('opt2', '10.0.3.15', 'test'), 'failed:helper')

    def test_action_results_are_checked(self):
        cases = [('requested', 0, 'requested'), ('busy', 0, 'busy'), ('refused:address-changed', 0, 'refused:address-changed'),
                 ('failed:no-client', 3, 'failed:no-client'), ('restored', 0, 'failed:helper'),
                 ('weird', 0, 'failed:helper'), ('failed:X; rm', 0, 'failed:helper'), (5, 0, 'failed:helper')]
        for result, code, expected in cases:
            with self.subTest(result=result):
                helper = self.stub('print(json.dumps({"result": %r})); sys.exit(%d)' % (result, code))
                self.assertEqual(helper.redhcp('opt2', '10.0.3.15', 'test'), expected)
        self.assertEqual(self.stub('print(json.dumps({"result": "restored"}))').restore('opt2'), 'restored')
        self.assertEqual(self.stub('print(json.dumps({"result": "running"}))').restore('opt2'), 'running')
        self.assertEqual(self.stub('sys.exit(0)').restore('opt2'), 'failed:helper')

    def test_arguments_reach_the_helper_as_separate_words(self):
        helper = self.stub('print(json.dumps({"result": "requested" if sys.argv[1:] == ["redhcp", "opt2", "10.0.3.15", "a b; c"] else "busy"}))')
        self.assertEqual(helper.redhcp('opt2', '10.0.3.15', 'a b; c'), 'requested')


class ReportTests(Private):
    def prepare(self, running=True):
        self.paths.run.mkdir(mode=0o700)
        self.paths.db.mkdir(mode=0o700)
        if running:
            self.paths.pidfile.write_text('%d\n' % os.getpid())
        state = guard.new_state('1:1')
        tracker = guard.new_tracker('vtnet3')
        tracker.update(stage=2, streak=1, next_retry=5120.0, actions=[4900.0, 5000.0],
                       last_action={'wall': 1790004000.0, 'mono': 5000.0, 'address': '10.0.3.15',
                                    'rule': '10.0.3.0/24', 'reason': 'address 10.0.3.15 is in 10.0.3.0/24',
                                    'result': 'requested', 'trigger': 'auto', 'attempt': 2})
        state['interfaces']['opt2'] = tracker
        guard.Store(str(self.paths.state), '1:1').save(state)
        wanguard.write_private(self.paths.observed, {'wall': 1790004050.0, 'interfaces': {'opt2': {'wall': 1790004050.0}}})

    def report(self, helper=None, boot='1:1'):
        return wanguard.report(self.paths, helper or FakeHelper(lambda: observation(
            rows=[interface(), interface('wan', device='igc1', address='198.51.100.7'),
                  interface('opt5', ipaddr='static', eligible=False)], watched=('opt2', 'wan', 'opt5'))),
            boot, clock=lambda: 5060.0, wall=lambda: 1790004060.0)

    def test_the_state_answer_is_the_api_contract(self):
        self.prepare()
        answer = self.report()
        self.assertEqual(set(answer), {'status', 'enabled', 'running', 'booting', 'rules', 'interfaces'})
        self.assertEqual(answer['rules'], {'networks': ['10.0.3.0/24'], 'private_ranges': False, 'empty': False})
        self.assertTrue(answer['running'])
        opt2, wan, opt5 = answer['interfaces']
        self.assertEqual(set(opt2), {'name', 'descr', 'device', 'eligible', 'address', 'verdict', 'rule', 'carrier',
                                     'state', 'streak', 'attempts', 'actions_last_hour', 'observed_at',
                                     'last_action', 'last_manual', 'next_retry_at'})
        self.assertEqual((opt2['verdict'], opt2['rule'], opt2['state'], opt2['attempts'], opt2['streak']),
                         ('unwanted', '10.0.3.0/24', 'backoff', 2, 1))
        self.assertEqual(opt2['actions_last_hour'], 2)
        self.assertEqual(opt2['next_retry_at'], 1790004060 + 60)
        self.assertEqual(opt2['observed_at'], 1790004050)
        self.assertEqual(opt2['last_action'], {'at': 1790004000, 'trigger': 'auto', 'result': 'requested',
                                               'reason': 'address 10.0.3.15 is in 10.0.3.0/24', 'attempt': 2})
        self.assertEqual((wan['state'], wan['verdict'], wan['attempts'], wan['next_retry_at']), ('ok', 'wanted', 0, None))
        self.assertEqual((opt5['state'], opt5['eligible'], opt5['address']), ('ignored', False, '10.0.3.15'))
        json.dumps(answer)

    def test_a_stopped_or_disabled_service_is_reported_as_such(self):
        self.prepare(running=False)
        self.assertEqual(self.report()['interfaces'][0]['state'], 'stopped')
        disabled = self.report(FakeHelper(lambda: observation(enabled=False, rows=[])))
        self.assertFalse(disabled['enabled'])
        self.assertEqual(disabled['interfaces'][0]['state'], 'disabled')

    def test_reading_never_changes_a_corrupt_state_file(self):
        self.prepare()
        self.paths.state.write_text('{broken')
        answer = self.report()
        self.assertEqual(answer['interfaces'][0]['attempts'], 0)
        self.assertEqual(self.paths.state.read_text(), '{broken')
        self.assertFalse((self.paths.db / 'state.json.bad').exists())

    def test_history_of_an_earlier_boot_is_not_shown(self):
        self.prepare()
        self.assertEqual(self.report(boot='2:2')['interfaces'][0]['attempts'], 0)

    def test_an_observation_failure_is_reported(self):
        self.prepare()
        answer = self.report(FakeHelper(lambda: guard.ObserveError('broken')))
        self.assertEqual(answer['status'], 'failed')
        self.assertEqual(answer['interfaces'], [])


class RetryAndWakeTests(Private):
    def request(self, name='opt2', **kwargs):
        log = Log()
        answer = wanguard.request_retry(self.paths, FakeHelper(lambda: observation(**kwargs)), name, log)
        return answer, log

    def test_retry_requests(self):
        self.assertEqual(self.request('../etc')[0], {'status': 'refused', 'code': 'invalid'})
        self.assertEqual(self.request(enabled=False)[0], {'status': 'refused', 'code': 'disabled'})
        self.assertEqual(self.request()[0], {'status': 'refused', 'code': 'stopped'})
        self.paths.run.mkdir(mode=0o700)
        self.paths.pidfile.write_text('%d\n' % os.getpid())
        answer, log = self.request('wan')
        self.assertEqual(answer, {'status': 'refused', 'code': 'not-watched'})
        self.assertEqual(log.having('manual retry on wan refused: the interface is not watched')[0][0], 'notice')
        answer, log = self.request()
        self.assertEqual(answer, {'status': 'queued', 'code': 'queued'})
        self.assertEqual(log, [('notice', 'manual retry requested for opt2')])
        self.assertEqual((self.paths.run / 'retry-opt2').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.request()[0], {'status': 'refused', 'code': 'queued-already'})
        unavailable = wanguard.request_retry(self.paths, FakeHelper(lambda: guard.ObserveError('x')), 'opt2', Log())
        self.assertEqual(unavailable, {'status': 'refused', 'code': 'unavailable'})

    def test_a_stale_pidfile_is_not_running(self):
        self.paths.pidfile.write_text('999999\n')
        self.assertFalse(wanguard.daemon_running(self.paths.pidfile))
        self.paths.pidfile.write_text('garbage')
        self.assertFalse(wanguard.daemon_running(self.paths.pidfile))
        self.paths.pidfile.write_text('%d' % os.getpid())
        self.assertTrue(wanguard.daemon_running(self.paths.pidfile))

    def test_wake_needs_the_private_directory(self):
        self.assertFalse(wanguard.wake(self.paths))
        self.assertFalse(self.paths.run.exists())
        self.paths.run.mkdir(mode=0o700)
        self.assertTrue(wanguard.wake(self.paths))
        self.assertTrue(wanguard.wake(self.paths))
        self.assertEqual(self.paths.wake.read_text(), 'reload\nreload\n')
        self.assertEqual(wanguard.main(['wake'], paths=self.paths), 0)

    def test_usage(self):
        for argv in [[], ['redhcp', 'wan'], ['retry'], ['state', 'x'], ['run', 'now']]:
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()) as error:
                self.assertEqual(wanguard.main(argv, paths=self.paths, helper=FakeHelper()), 2)
                self.assertIn('usage: wanguard.py', error.getvalue())


if __name__ == '__main__':
    unittest.main()
