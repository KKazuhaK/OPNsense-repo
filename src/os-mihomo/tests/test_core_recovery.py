"""Bring the core back when it exits on its own, keep its memory bounded and its log rotating."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_mihomo import Clock, SUBSCRIPTION, m
from test_routing_lifecycle import RoutingSystem
import process_owner as owner

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'src'
REOPEN = SOURCE / 'usr/local/opnsense/scripts/mihomo/reopen_log.sh'
NEWSYSLOG = SOURCE / 'usr/local/etc/newsyslog.conf.d/mihomo.conf'
MIB = 1024 * 1024
GIB = 1024 * MIB


class RecoverySystem(RoutingSystem):
    """A core that can die on its own, be killed by the kernel and grow in memory."""

    def __init__(self):
        super().__init__()
        self.lives = 0
        self.identity = None
        # The kill lines dmesg holds, by pid, oldest first.
        self.kills = {}
        self.singbox = False
        self.resident = 150 * MIB
        # The resident size a new core starts with, when a test sets one.
        self.resident_on_start = None
        self.usage_reads = 0
        self.physical = 4 * GIB

    def start(self, config, transparent):
        super().start(config, transparent)
        self.lives += 1
        self.identity = {'pid': 5000 + self.lives, 'birth': '1700000000:%d' % self.lives}
        if self.resident_on_start is not None:
            self.resident = self.resident_on_start

    def core_identity(self):
        return self.identity if self.alive else None

    def kill_reasons(self, pid):
        self.events.append('dmesg')
        return list(self.kills.get(pid, []))

    def singbox_owns_routing(self):
        return self.singbox

    def core_usage(self):
        self.usage_reads += 1
        return {'core': self.identity, 'resident': self.resident} if self.alive else None

    def physical_memory(self):
        return self.physical


class RecoveryCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.clock = Clock()
        self.system = RecoverySystem()
        self.manager = m.Manager(Path(self.temp.name), self.system)
        self.manager.clock = self.clock
        self.system.state = self.manager.state
        self.manager.initialize()
        self.manager.write_settings(dict(self.manager.settings(), dns_scope='all'))
        self.manager.dispatch('start')
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.assertTrue(self.system.routing_active)
        self.assertTrue(self.system.forwarded)
        self.system.events.clear()

    def tick(self, seconds=5.0):
        """One watchdog tick as main() runs it: under the manager lock, which the restart must not take again."""
        self.clock.now += seconds
        with self.manager.lock(blocking=False):
            return self.manager.watchdog_tick()

    def log(self):
        path = self.manager.path('/var/log/mihomo.log')
        return path.read_text().splitlines() if path.exists() else []

    def logged(self, since):
        return [line.split('] ', 1)[1] for line in self.log()[since:]]

    def record(self):
        return self.manager.restart_record()

    def status(self):
        return json.loads(self.manager.status_file.read_bytes())

    def crash(self, reason=None):
        """The core exits without a stop; reason is what the kernel logged for its pid."""
        if reason is not None:
            self.system.kills.setdefault(self.system.identity['pid'], []).append(reason)
        self.system.alive = False

    def restart_after(self, delay, reason=m.EXIT_UNEXPECTED):
        """Detect an exit, wait until just short of delay after it, then see the restart happen."""
        lines = len(self.log())
        self.tick(1)
        self.assertEqual([m.RESTART_SCHEDULED_LOG % (reason, delay)], self.logged(lines)[-1:])
        self.tick(delay - 0.5)
        self.assertFalse(self.system.alive, 'restarted before its delay')
        status = self.tick(0.5)
        self.assertTrue(self.system.alive, 'not restarted after its delay')
        return status


class AutomaticRestartTests(RecoveryCase):
    def test_a_core_that_exits_is_restarted_ten_seconds_after_the_exit(self):
        first = self.system.identity
        lines = len(self.log())
        self.crash()
        status = self.tick()
        # The rescue comes first and stays as it was: routing withdrawn,
        # direct DNS back.
        self.assertFalse(status['running'])
        self.assertFalse(self.system.routing_active)
        self.assertFalse(self.system.forwarded)
        self.assertFalse(status['dns_active'])
        self.assertIn('Mihomo stopped (exited unexpectedly) and is restarted automatically at about ',
                      status['error'])
        self.assertIn('Direct DNS and routing were restored automatically.', status['error'])
        self.assertEqual([m.RESTART_SCHEDULED_LOG % (m.EXIT_UNEXPECTED, 10)], self.logged(lines))
        # The status action republishes the error it read; the notice is not doubled.
        again = self.manager.dispatch('status')
        self.assertEqual(1, again['error'].count('is restarted automatically'))
        status = self.tick(9)
        self.assertFalse(self.system.alive)
        self.assertIn('is restarted automatically', status['error'])
        status = self.tick(1)
        self.assertTrue(self.system.alive)
        self.assertNotEqual(first, self.system.identity)
        self.assertTrue(status['running'] and status['routing_active'] and status['dns_active'], status)
        self.assertEqual('', status['error'])
        self.assertEqual(m.EXIT_UNEXPECTED, status['last_restart']['reason'])
        self.assertTrue(status['restart_note'].startswith('Restarted automatically at '))
        self.assertTrue(status['restart_note'].endswith('(exited unexpectedly).'))
        self.assertEqual([m.RESTART_SCHEDULED_LOG % (m.EXIT_UNEXPECTED, 10),
                          m.RESTART_ATTEMPT_LOG % (1, 3), m.RESTART_DONE_LOG], self.logged(lines))
        # The new core is armed in its turn and the note survives other republishers.
        self.assertEqual({'armed': True, 'core': self.system.identity}, {
            key: self.record()[key] for key in ('armed', 'core')})
        self.assertEqual(status['restart_note'], self.manager.dispatch('status')['restart_note'])
        self.assertEqual(status['restart_note'], self.tick()['restart_note'])

    def test_the_restart_takes_the_start_actions_path(self):
        # What an automatic restart does to the system...
        self.crash()
        self.tick(1)
        self.tick(9.5)
        self.system.events.clear()
        self.tick(0.5)
        automatic = list(self.system.events)
        # ...is the rescue that every tick of a stopped core repeats, then
        # exactly what the Start button does from the same state.
        self.assertEqual(['routing-disable', 'destroy-tun'], automatic[:2])
        self.crash()
        self.tick(1)
        self.system.events.clear()
        self.manager.dispatch('start')
        self.assertEqual(automatic[2:], self.system.events)
        self.assertIn('start-transparent', automatic)
        self.assertIn('routing-enable', automatic)
        self.assertIn('dns-on', automatic)
        self.assertTrue(self.system.routing_active and self.system.forwarded)

    def test_the_backoff_ladder_and_three_restarts_in_any_hour(self):
        for delay in m.RESTART_DELAYS:
            self.crash()
            self.restart_after(delay)
        self.assertEqual(3, len(self.record()['attempts']))
        # A fourth exit within the hour is not restarted: the budget is spent.
        lines = len(self.log())
        self.crash()
        status = self.tick(1)
        self.assertEqual(['Mihomo stopped (exited unexpectedly); ' + m.RESTART_PAUSE_TAIL], self.logged(lines))
        self.assertTrue(status['error'].startswith(m.RESTART_PAUSED), status['error'])
        self.assertTrue(self.record()['paused'])
        for _ in range(3):
            status = self.tick(600)
        self.assertFalse(self.system.alive)
        self.assertTrue(status['error'].startswith(m.RESTART_PAUSED))
        self.assertEqual(1, len(self.logged(lines)), 'a paused restart is logged once')
        # Start resumes it, with a fresh budget.
        self.manager.dispatch('start')
        self.assertTrue(self.system.alive)
        self.assertEqual('', self.status()['error'])
        self.assertEqual(([], False, None), (self.record()['attempts'], self.record()['paused'],
                                             self.record()['last']))
        self.crash()
        self.restart_after(10)

    def test_the_budget_rolls_with_the_hour(self):
        for delay in m.RESTART_DELAYS:
            self.crash()
            self.restart_after(delay)
        # Three restarts are an hour old once the clock passes the last of
        # them by that much, and the next exit is a first one again.
        self.clock.now = self.record()['attempts'][-1] + m.RESTART_WINDOW
        self.tick(0)
        self.crash()
        self.restart_after(10)
        self.assertEqual(1, len(self.manager.recent_attempts(self.record(), self.clock())))

    def test_a_failed_start_counts_and_backs_off_until_the_budget_is_spent(self):
        lines = len(self.log())
        self.system.fail_start = 3
        self.crash()
        self.tick(1)
        status = self.tick(10)
        self.assertFalse(self.system.alive)
        self.assertIn(m.RESTART_FAILED % 'Injected startup failure.', status['error'])
        self.assertIn('is restarted automatically at about', status['error'])
        self.assertEqual(m.RESTART_FAILED_LOG % ('Injected startup failure.', m.RESTART_RETRY_LOG % 60),
                         self.logged(lines)[-1])
        self.assertEqual(1, self.system.events.count('start-transparent'))
        self.tick(59)
        self.assertEqual(1, self.system.events.count('start-transparent'))
        status = self.tick(1)
        self.assertEqual(2, self.system.events.count('start-transparent'))
        self.assertEqual(m.RESTART_FAILED_LOG % ('Injected startup failure.', m.RESTART_RETRY_LOG % 300),
                         self.logged(lines)[-1])
        self.tick(299)
        status = self.tick(1)
        self.assertEqual(3, self.system.events.count('start-transparent'))
        self.assertFalse(self.system.alive)
        self.assertEqual(m.RESTART_FAILED_LOG % ('Injected startup failure.', m.RESTART_PAUSE_TAIL),
                         self.logged(lines)[-1])
        self.assertTrue(status['error'].startswith(m.RESTART_PAUSED), status['error'])
        self.tick(3600)
        self.assertEqual(3, self.system.events.count('start-transparent'))
        # A failed attempt never leaves Unbound forwarding to a stopped core.
        self.assertFalse(self.system.forwarded)

    def test_the_kernels_reason_is_logged_and_published(self):
        lines = len(self.log())
        self.crash('failed to reclaim memory')
        status = self.restart_after(10, 'killed by the kernel: failed to reclaim memory')
        self.assertIn('dmesg', self.system.events)
        self.assertEqual('killed by the kernel: failed to reclaim memory', status['last_restart']['reason'])
        self.assertTrue(status['restart_note'].endswith('(killed by the kernel: failed to reclaim memory).'))
        self.assertEqual('Mihomo stopped (killed by the kernel: failed to reclaim memory); restarting it '
                         'automatically in 10 seconds.', self.logged(lines)[0])

    def test_a_kill_line_from_before_the_core_is_not_its_reason(self):
        # Pids wrap within hours while a quiet router's message buffer keeps
        # lines for days: an earlier process with the pid the next core gets
        # was killed for memory.
        reused = 5000 + self.system.lives + 1
        self.system.kills[reused] = ['failed to reclaim memory']
        self.manager.dispatch('restart')
        self.assertEqual(reused, self.system.identity['pid'])
        self.assertEqual(1, self.record()['kills'])
        self.crash()
        status = self.restart_after(10)
        self.assertEqual(m.EXIT_UNEXPECTED, status['last_restart']['reason'])
        # A line the kernel writes for the core itself still counts, next to
        # an old one for the same pid.
        reused = self.system.identity['pid'] + 1
        self.system.kills[reused] = ['failed to reclaim memory']
        self.manager.dispatch('restart')
        self.assertEqual(reused, self.system.identity['pid'])
        self.crash('out of swap space')
        status = self.restart_after(10, 'killed by the kernel: out of swap space')
        self.assertEqual('killed by the kernel: out of swap space', status['last_restart']['reason'])

    def test_a_restart_waits_for_the_rescue_to_succeed(self):
        self.crash()
        self.system.fail_destroy = True
        for _ in range(4):
            status = self.tick(10)
        self.assertFalse(self.system.alive)
        self.assertIn('Routing cleanup failed', status['error'])
        self.assertTrue(self.record()['armed'], 'the exit is detected only once the rescue is done')
        self.system.fail_destroy = False
        self.restart_after(10)

    def test_a_failed_direct_dns_recovery_holds_the_restart_back(self):
        original = self.system.dns
        self.system.dns = lambda enabled, settings: (_ for _ in ()).throw(m.Error('Injected Unbound failure.'))
        self.crash()
        for _ in range(3):
            status = self.tick(10)
        self.assertIn('Direct DNS recovery failed', status['error'])
        self.assertFalse(self.system.alive)
        self.system.dns = original
        self.restart_after(10)

    def test_without_dns_recovery_the_restart_brings_the_forwarding_core_back(self):
        # Unbound keeps forwarding to the stopped core by the operator's
        # choice; the restart is what answers it again.
        self.manager.write_settings(dict(self.manager.settings(), dns_fallback=False))
        self.crash()
        self.assertTrue(self.tick(1)['dns_active'])
        self.assertTrue(self.system.forwarded)
        status = self.tick(10)
        self.assertTrue(status['running'] and status['dns_active'])


class IntendedStopTests(RecoveryCase):
    def assertNeverRestarted(self, seconds=(1, 10, 60, 300, 3600)):
        lines = len(self.log())
        starts = self.system.events.count('start-transparent') + self.system.events.count('start-proxy')
        for step in seconds:
            self.tick(step)
        self.assertFalse(self.system.alive)
        self.assertEqual(starts, self.system.events.count('start-transparent')
                         + self.system.events.count('start-proxy'))
        self.assertFalse(any(line.startswith('Restarting Mihomo') or 'restarting it automatically' in line
                             for line in self.logged(lines)), self.logged(lines))

    def test_stop_is_never_undone(self):
        self.manager.dispatch('stop')
        self.assertNeverRestarted()
        self.assertEqual('', self.status()['error'])

    def test_a_stop_while_a_restart_waits_cancels_it(self):
        self.crash()
        self.tick(1)
        self.manager.dispatch('stop')
        self.assertIsNone(self.record()['pending'])
        self.assertNeverRestarted()
        self.assertNotIn('restarted automatically', self.status()['error'])

    def test_suspend_and_remove_are_never_undone(self):
        # suspend is the package upgrade's stop: it keeps the service enabled.
        self.manager.dispatch('suspend')
        self.assertTrue(self.manager.settings()['service_enabled'])
        self.assertNeverRestarted()
        self.manager.dispatch('start')
        self.manager.dispatch('remove')
        self.assertNeverRestarted()

    def test_an_administrative_restart_that_cannot_start_is_not_retried_behind_it(self):
        # The administrator sees this failure; retrying it is theirs to decide.
        self.system.fail_start = 1
        with self.assertRaises(m.Error):
            self.manager.dispatch('restart')
        self.assertNeverRestarted()
        self.assertIsNone(self.record()['pending'])

    def test_a_service_disabled_without_a_stop_is_not_restarted(self):
        lines = len(self.log())
        self.manager.write_settings(dict(self.manager.settings(), service_enabled=False))
        self.crash()
        self.assertNeverRestarted()
        self.assertIn(m.RESTART_DECLINED_LOG % (m.EXIT_UNEXPECTED, 'the service is administratively stopped'),
                      self.logged(lines))

    def test_a_scope_change_that_left_the_service_stopped_stays_stopped(self):
        lines = len(self.log())
        reason = m.IPV6_STOPPED_ERROR % 'injected'
        self.manager.annotate_observation(self.manager.dns_observation(), stopped=reason)
        self.crash()
        self.assertNeverRestarted()
        self.assertIn(m.RESTART_DECLINED_LOG % (m.EXIT_UNEXPECTED, 'a DNS scope change left it stopped'),
                      self.logged(lines))
        self.assertTrue(self.status()['error'].startswith(reason))

    def test_sing_box_owning_transparent_routing_keeps_mihomo_down(self):
        lines = len(self.log())
        self.system.singbox = True
        self.crash()
        self.assertNeverRestarted()
        self.assertIn(m.RESTART_DECLINED_LOG % (m.EXIT_UNEXPECTED, 'Sing-box owns transparent routing'),
                      self.logged(lines))

    def test_sing_box_taking_over_while_a_restart_waits_cancels_it(self):
        self.crash()
        self.tick(1)
        self.system.singbox = True
        self.assertNeverRestarted()
        self.assertIsNone(self.record()['pending'])

    def test_the_backup_guard_branch_never_restarts(self):
        self.crash()
        with mock.patch.object(self.manager, '_guard_backup',
                               side_effect=m.BackupIntegrityError('Edited backup fixture.')):
            for _ in range(5):
                status = self.tick(60)
        self.assertFalse(self.system.alive)
        self.assertFalse(self.system.forwarded)
        self.assertNotIn('start-transparent', self.system.events)
        self.assertIn('Edited backup fixture.', status['error'])
        # The exit is still the core's own: once the guard passes, the
        # ordinary tick restarts it as it would have.
        self.assertTrue(self.record()['armed'])
        self.restart_after(10)

    def test_a_core_left_running_by_any_start_is_armed_by_the_next_tick(self):
        # A core that survived an upgrade, or whose start could not write the
        # record, is armed as soon as a tick sees it run.
        self.manager.restart_file.unlink()
        # The kernel's message buffer already holds a line for this pid.
        self.system.kills[self.system.identity['pid']] = ['failed to reclaim memory']
        self.tick()
        self.assertEqual((True, self.system.identity, 1),
                         (self.record()['armed'], self.record()['core'], self.record()['kills']))
        self.crash()
        self.restart_after(10)


class FailedCycleTests(RecoveryCase):
    """A stop and start nobody asked for, whose start fails, leaves a core nobody meant to be down."""

    def assertRestartedLikeAnExit(self, reason, lines, forwarded=True):
        """The failure planned the first restart 10 seconds out, and the watchdog makes it."""
        self.assertFalse(self.system.alive)
        self.assertEqual([m.RESTART_SCHEDULED_LOG % (reason, 10)], self.logged(lines))
        # Said at once, in front of the cycle's own error.
        self.assertTrue(self.status()['error'].startswith(
            'Mihomo stopped (%s) and is restarted automatically at about ' % reason), self.status()['error'])
        self.tick(5)
        self.tick(4.5)
        self.assertFalse(self.system.alive, 'restarted before its delay')
        status = self.tick(0.5)
        self.assertTrue(self.system.alive, 'not restarted after its delay')
        self.assertTrue(status['running'] and status['routing_active'], status)
        self.assertIs(forwarded, status['dns_active'])
        self.assertEqual(reason, status['last_restart']['reason'])
        self.assertEqual(1, len(self.record()['attempts']), 'the restart is counted in the same budget')
        self.assertEqual([m.RESTART_ATTEMPT_LOG % (1, 3), m.RESTART_DONE_LOG], self.logged(lines)[-2:])

    def test_a_wan_restart_that_cannot_start_is_retried_like_an_exit(self):
        # newwanip runs this while the WAN settles, with nobody to press Start.
        lines = len(self.log())
        self.system.fail_start = 1
        with self.assertRaisesRegex(m.Error, 'Injected startup failure'):
            self.manager.dispatch('wan-restart')
        self.assertRestartedLikeAnExit(m.RESTART_CYCLE_WAN % 'Injected startup failure.', lines)

    def test_a_wan_restart_whose_stop_fails_is_retried_too(self):
        lines = len(self.log())
        self.system.fail_stop_after_dead = 1
        with self.assertRaisesRegex(m.Error, 'Injected routing cleanup failure'):
            self.manager.dispatch('wan-restart')
        self.assertRestartedLikeAnExit(
            m.RESTART_CYCLE_WAN % 'Injected routing cleanup failure after stopping the core.', lines)

    def test_a_failed_re_apply_for_new_router_dns_upstreams_is_retried_like_an_exit(self):
        self.manager.write_settings(dict(self.manager.settings(), router_dns=True))
        upstreams = ('forward-addr: 192.0.2.53@853\n', False)
        lines = len(self.log())
        with mock.patch.object(self.manager, 'router_context', return_value=upstreams):
            # The new pins and the rollback to the previous configuration both fail.
            self.system.fail_start = 2
            with self.assertRaisesRegex(m.Error, 'Rollback restored the files; the service could not restart'):
                self.tick()
            reason = m.RESTART_CYCLE_APPLY % (
                'Rollback restored the files; the service could not restart. Direct DNS is active.')
            # Router DNS leaves Unbound alone.
            self.assertRestartedLikeAnExit(reason, lines, forwarded=False)
            # The start that came back rendered the pins, so nothing is re-applied.
            self.system.events.clear()
            self.tick()
            self.assertNotIn('validate', self.system.events)

    def test_a_subscription_update_whose_restart_fails_is_retried_like_an_exit(self):
        lines = len(self.log())
        self.system.fail_start = 2
        with mock.patch.object(m, 'fetch_subscription', return_value=SUBSCRIPTION):
            with self.assertRaisesRegex(m.Error, 'Rollback restored the files; the service could not restart'):
                self.manager.update()
        self.assertRestartedLikeAnExit(m.RESTART_CYCLE_UPDATE % (
            'Rollback restored the files; the service could not restart. Direct DNS is active.'), lines)

    def test_a_cycle_whose_rollback_brings_the_core_back_plans_nothing(self):
        lines = len(self.log())
        self.system.fail_start = 1
        with mock.patch.object(m, 'fetch_subscription', return_value=SUBSCRIPTION):
            with self.assertRaisesRegex(m.Error, 'The change failed'):
                self.manager.update()
        self.assertTrue(self.system.alive)
        self.assertEqual(([], None, True), (self.logged(lines), self.record()['pending'], self.record()['armed']))

    def test_an_update_that_fails_while_the_core_is_already_down_plans_nothing(self):
        # An administrator's Restart failed; that core stays down for them.
        self.system.fail_start = 1
        with self.assertRaises(m.Error):
            self.manager.dispatch('restart')
        lines = len(self.log())
        self.system.reject = True
        with mock.patch.object(m, 'fetch_subscription', return_value=SUBSCRIPTION):
            with self.assertRaises(m.Error):
                self.manager.update()
        self.assertEqual(([], None), (self.logged(lines), self.record()['pending']))
        for _ in range(4):
            self.tick(60)
        self.assertFalse(self.system.alive)

    def test_a_blocked_cycle_is_declined_as_an_exit_would_be(self):
        lines = len(self.log())
        self.system.singbox = True
        self.system.fail_start = 1
        with self.assertRaises(m.Error):
            self.manager.dispatch('wan-restart')
        reason = m.RESTART_CYCLE_WAN % 'Injected startup failure.'
        self.assertEqual([m.RESTART_DECLINED_LOG % (reason, 'Sing-box owns transparent routing')],
                         self.logged(lines))
        for _ in range(4):
            self.tick(60)
        self.assertFalse(self.system.alive)


class HeldRestartTests(RecoveryCase):
    """While the watchdog cannot act on the core, the status promises nothing it will not do."""

    def test_the_backup_guard_holds_a_planned_restart_without_promising_a_time(self):
        self.crash()
        status = self.tick(1)
        self.assertIn('is restarted automatically at about', status['error'])
        reason = m.RESTART_HELD % m.EXIT_UNEXPECTED
        with mock.patch.object(self.manager, '_guard_backup', side_effect=m.Error(
                'A restored Mihomo configuration is pending. Stop the service and restore it or reboot before '
                'saving.')):
            for _ in range(8):
                status = self.tick(60)
                self.assertFalse(self.system.alive)
                self.assertTrue(status['error'].startswith(reason), status['error'])
                self.assertNotIn('at about', status['error'])
                self.assertIn('A restored Mihomo configuration is pending.', status['error'])
            # Whoever republishes meanwhile says the same, once.
            again = self.manager.dispatch('status')
            self.assertEqual(1, again['error'].count(reason), again['error'])
            self.assertNotIn('at about', again['error'])
        # Once the guard passes, the overdue restart is made on the next tick.
        status = self.tick()
        self.assertTrue(self.system.alive)
        self.assertEqual('', status['error'])
        self.assertFalse(self.record()['held'])

    def test_a_failing_routing_cleanup_holds_a_planned_restart_without_promising_a_time(self):
        self.crash()
        self.tick(1)
        self.system.fail_destroy = True
        for _ in range(4):
            status = self.tick(10)
            self.assertFalse(self.system.alive)
            self.assertTrue(status['error'].startswith(m.RESTART_HELD % m.EXIT_UNEXPECTED), status['error'])
            self.assertIn('Routing cleanup failed', status['error'])
            self.assertNotIn('at about', status['error'])
        self.system.fail_destroy = False
        status = self.tick()
        self.assertTrue(self.system.alive)
        self.assertTrue(status['running'] and status['routing_active'], status)

    def test_the_memory_guard_does_not_run_and_the_status_offers_no_limit_while_the_guard_fails(self):
        self.system.resident = 3 * GIB
        identity = self.system.identity
        with mock.patch.object(self.manager, '_guard_backup',
                               side_effect=m.BackupIntegrityError('Edited backup fixture.')):
            for _ in range(5):
                status = self.tick()
        self.assertEqual(identity, self.system.identity, 'the guard branch never restarts')
        self.assertEqual(3 * GIB, status['core_memory'])
        self.assertIsNone(status['core_memory_limit'])
        self.assertIsNone(self.manager.dispatch('status')['core_memory_limit'])
        # The guard passes: the limit is back and the memory guard acts on it.
        status = self.tick()
        self.assertNotEqual(identity, self.system.identity)
        self.assertEqual(2 * GIB, status['core_memory_limit'])


class MemoryGuardTests(RecoveryCase):
    def test_the_soft_limit_is_thirty_percent_and_never_below_256_mib(self):
        self.assertEqual(4 * GIB * 30 // 100, m.go_memory_limit(4 * GIB))
        self.assertEqual(256 * MIB, m.go_memory_limit(512 * MIB))
        for unknown in (None, 0, -1, True, '4294967296'):
            self.assertIsNone(m.go_memory_limit(unknown), unknown)
        self.assertEqual(2 * GIB, m.memory_restart_limit(4 * GIB))
        self.assertIsNone(m.memory_restart_limit(None))
        system = m.System()
        with mock.patch.object(system, 'physical_memory', return_value=4 * GIB):
            environment = system.core_environment()
        self.assertEqual('1228MiB', environment['GOMEMLIMIT'])
        self.assertEqual({key: value for key, value in os.environ.items() if key != 'GOMEMLIMIT'},
                         {key: value for key, value in environment.items() if key != 'GOMEMLIMIT'})
        with mock.patch.object(system, 'physical_memory', return_value=None):
            self.assertNotIn('GOMEMLIMIT', system.core_environment())

    def test_physical_memory_is_read_from_sysctl_once(self):
        system = m.System()
        answers = [m.Error('timed out'), subprocess.CompletedProcess([], 0, b'4294967296\n', b'')]

        def run(args, **kwargs):
            self.assertEqual(['/sbin/sysctl', '-n', 'hw.physmem'], args)
            answer = answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer

        with mock.patch.object(system, 'run', side_effect=run):
            self.assertIsNone(system.physical_memory())
            self.assertEqual(4 * GIB, system.physical_memory())
            self.assertEqual(4 * GIB, system.physical_memory())
        self.assertEqual([], answers)
        for output in (b'', b'0\n', b'-1\n', b'4 GB\n'):
            with self.subTest(output=output), mock.patch.object(
                    m.System, 'run', return_value=subprocess.CompletedProcess([], 0, output, b'')):
                self.assertIsNone(m.System().physical_memory())

    def test_the_status_publishes_core_memory_and_the_restart_limit(self):
        status = self.tick()
        self.assertEqual(150 * MIB, status['core_memory'])
        self.assertEqual(2 * GIB, status['core_memory_limit'])
        self.manager.dispatch('stop')
        status = self.status()
        self.assertIsNone(status['core_memory'])
        self.assertEqual(2 * GIB, status['core_memory_limit'])
        self.system.physical = None
        self.assertIsNone(self.manager.publish_status()['core_memory_limit'])

    def test_a_core_above_half_of_memory_is_restarted_inside_the_budget(self):
        lines = len(self.log())
        first = self.system.identity
        self.system.resident = 2 * GIB + 100 * MIB
        status = self.tick()
        self.assertNotEqual(first, self.system.identity)
        self.assertTrue(status['running'] and status['routing_active'] and status['dns_active'])
        self.assertLess(self.system.events.index('stop'), self.system.events.index('start-transparent'))
        reason = 'memory use 2.1 GB above the restart limit of 2.0 GB'
        self.assertEqual(reason, status['last_restart']['reason'])
        self.assertEqual([m.MEMORY_RESTART_LOG % ('2.1 GB', '2.0 GB'), m.RESTART_ATTEMPT_LOG % (1, 3),
                          m.RESTART_DONE_LOG], self.logged(lines))
        # A core at the limit itself is left alone.
        self.system.resident = 2 * GIB
        self.system.events.clear()
        self.tick()
        self.assertNotIn('stop', self.system.events)

    def test_memory_restarts_wait_on_the_ladder_from_the_last_attempt(self):
        # A core that is above the limit again as soon as it starts is not
        # torn down, routing and DNS with it, on every tick.
        self.system.resident = 3 * GIB
        self.tick()
        first = self.record()['attempts'][-1]
        identity = self.system.identity
        lines = len(self.log())
        for _ in range(11):
            self.tick()
        self.assertEqual(identity, self.system.identity, 'restarted again within 60 seconds')
        self.assertEqual([m.MEMORY_WAIT_LOG % ('3.0 GB', '2.0 GB', 5, 55)], self.logged(lines),
                         'a wait is logged once')
        self.tick()
        self.assertEqual(first + 60, self.record()['attempts'][-1])
        self.assertNotEqual(identity, self.system.identity)
        identity = self.system.identity
        lines = len(self.log())
        for _ in range(59):
            self.tick()
        self.assertEqual(identity, self.system.identity, 'restarted again within 300 seconds')
        self.assertEqual([m.MEMORY_WAIT_LOG % ('3.0 GB', '2.0 GB', 5, 295)], self.logged(lines))
        self.tick()
        self.assertEqual([first, first + 60, first + 360], self.record()['attempts'])

    def test_the_memory_guard_spends_the_same_budget_and_then_pauses(self):
        self.crash()
        self.restart_after(10)
        self.system.resident = 3 * GIB
        self.tick(60)
        self.tick(300)
        self.assertEqual(3, len(self.record()['attempts']))
        identity = self.system.identity
        lines = len(self.log())
        status = self.tick(300)
        self.assertEqual(identity, self.system.identity, 'the budget is spent')
        self.assertTrue(status['running'])
        # The core did not exit, and the status does not say it did.
        self.assertTrue(status['error'].startswith(m.MEMORY_PAUSED), status['error'])
        self.assertNotIn('exited', status['error'])
        self.assertEqual('memory', self.record()['paused'])
        self.assertEqual([m.MEMORY_PAUSED_LOG % ('3.0 GB', '2.0 GB')], self.logged(lines))
        self.tick()
        self.tick()
        self.assertEqual(1, len(self.logged(lines)), 'a pause is logged once')
        # A later exit leaves the pause the memory guard began, and its words.
        self.crash()
        status = self.tick()
        self.assertTrue(status['error'].startswith(m.MEMORY_PAUSED), status['error'])
        # Start resumes it.
        self.manager.dispatch('start')
        self.assertEqual('', self.status()['error'])
        identity = self.system.identity
        self.tick()
        self.assertNotEqual(identity, self.system.identity)

    def test_one_tick_reads_the_cores_memory_once(self):
        # Each reading proves the core's ownership, which costs a process.
        self.system.usage_reads = 0
        status = self.tick()
        self.assertEqual(150 * MIB, status['core_memory'])
        self.assertEqual(1, self.system.usage_reads)
        # A restart within the tick reads the new core, not the old one's size.
        self.system.resident = 3 * GIB
        self.system.resident_on_start = 170 * MIB
        status = self.tick()
        self.assertEqual(170 * MIB, status['core_memory'])
        self.assertEqual(170 * MIB, self.status()['core_memory'])
        # Outside a tick every status reads afresh.
        self.system.usage_reads = 0
        self.manager.dispatch('status')
        self.manager.dispatch('status')
        self.assertEqual(2, self.system.usage_reads)

    def test_core_usage_reads_the_resident_set_of_the_recorded_core(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'var/db/os-mihomo').mkdir(parents=True, mode=0o700)
            (root / 'var/run').mkdir(parents=True)
            live = {}
            group = owner.core_group(root=root, process_reader=lambda pid: live.get(pid),
                                     signaler=lambda pid, number: None, sleeper=lambda seconds: None)
            parent = {'pid': 101, 'ppid': 1, 'uid': os.geteuid(), 'birth': '1700000000:1',
                      'executable': owner.DAEMON, 'argv': ['daemon: mihomo[102]'], 'stopped': False}
            child = {'pid': 102, 'ppid': 101, 'uid': os.geteuid(), 'birth': '1700000000:2',
                     'executable': owner.CORE, 'argv': list(group.child_argv), 'stopped': False}
            live.update({101: parent, 102: child})
            group.persist(parent, child)
            raw = bytearray(m.KINFO_SIZE)
            struct.pack_into('=i', raw, 0, m.KINFO_SIZE)
            struct.pack_into('=i', raw, m.KINFO_PID, 102)
            struct.pack_into('=q', raw, m.KINFO_RSSIZE, 43776)
            system = m.System()
            with mock.patch.object(system, '_core_group', return_value=group), \
                    mock.patch.object(m.process_identity, 'kernel_value', return_value=bytes(raw)) as kernel:
                usage = system.core_usage()
            kernel.assert_called_once_with('kern.proc.pid', 102)
            self.assertEqual({'core': {'pid': 102, 'birth': '1700000000:2'},
                              'resident': 43776 * os.sysconf('SC_PAGE_SIZE')}, usage)
            # A core that is gone has no size to report.
            live.pop(102)
            with mock.patch.object(system, '_core_group', return_value=group), \
                    mock.patch.object(m.process_identity, 'kernel_value', return_value=bytes(raw)):
                self.assertIsNone(system.core_usage())

    def test_any_other_process_record_layout_gives_no_size(self):
        raw = bytearray(m.KINFO_SIZE)
        struct.pack_into('=i', raw, 0, m.KINFO_SIZE)
        struct.pack_into('=i', raw, m.KINFO_PID, 102)
        struct.pack_into('=q', raw, m.KINFO_RSSIZE, 10)
        self.assertEqual(10 * os.sysconf('SC_PAGE_SIZE'), m.resident_bytes(bytes(raw), 102))
        self.assertIsNone(m.resident_bytes(bytes(raw), 103))
        self.assertIsNone(m.resident_bytes(bytes(raw[:-8]), 102))
        self.assertIsNone(m.resident_bytes(bytes(raw) + b'\0' * 8, 102))
        wrong = bytearray(raw)
        struct.pack_into('=i', wrong, 0, 1096)
        self.assertIsNone(m.resident_bytes(bytes(wrong), 102))
        negative = bytearray(raw)
        struct.pack_into('=q', negative, m.KINFO_RSSIZE, -1)
        self.assertIsNone(m.resident_bytes(bytes(negative), 102))
        self.assertIsNone(m.resident_bytes(None, 102))


class KernelReasonTests(unittest.TestCase):
    MESSAGES = ('pid 51154 (mihomo), jid 0, uid 0, was killed: out of swap space\n'
                'pid 51155 (python3.13), jid 0, uid 0, was killed: failed to reclaim memory\n'
                '[518400] pid 51155 (mihomo), jid 0, uid 0, was killed: failed to reclaim memory\n'
                'pid 51155 (mihomo), jid 0, uid 0: exited on signal 9\n'
                'pid 7 (mihomo), jid 0, uid 0, was killed: a thread waited too long to allocate a page\n')

    def test_every_line_for_that_pid_and_name_is_read_in_order(self):
        self.assertEqual(['failed to reclaim memory'], m.kernel_kill_reasons(self.MESSAGES, 51155))
        self.assertEqual(['out of swap space'], m.kernel_kill_reasons(self.MESSAGES, 51154))
        self.assertEqual(['a thread waited too long to allocate a page'], m.kernel_kill_reasons(self.MESSAGES, 7))
        self.assertEqual([], m.kernel_kill_reasons(self.MESSAGES, 5115))
        self.assertEqual([], m.kernel_kill_reasons(self.MESSAGES, 1))
        self.assertEqual([], m.kernel_kill_reasons('', 51155))
        later = self.MESSAGES + 'pid 51155 (mihomo), jid 0, uid 0, was killed: out of swap space\n'
        self.assertEqual(['failed to reclaim memory', 'out of swap space'], m.kernel_kill_reasons(later, 51155))

    def test_only_a_line_written_after_the_core_was_armed_is_its_reason(self):
        reasons = ['failed to reclaim memory', 'out of swap space']
        self.assertEqual('out of swap space', m.kernel_kill_reason(reasons, 0))
        self.assertEqual('out of swap space', m.kernel_kill_reason(reasons, 1))
        # Both lines were there before this core: they belong to earlier
        # processes that had its pid.
        self.assertIsNone(m.kernel_kill_reason(reasons, 2))
        self.assertIsNone(m.kernel_kill_reason([], 0))
        self.assertIsNone(m.kernel_kill_reason(None, 0))
        # A count dmesg could not give at arming counts as none.
        self.assertEqual('out of swap space', m.kernel_kill_reason(reasons, None))

    def test_the_reason_is_one_bounded_printable_line(self):
        reason = m.kernel_kill_reasons('pid 9 (mihomo), jid 0, uid 0, was killed: \x1b[31m' + 'x' * 900, 9)[-1]
        self.assertNotIn('\x1b', reason)
        self.assertLessEqual(len(reason.encode()), m.ROUTING_DIAGNOSTIC_LIMIT)
        self.assertEqual('killed by the kernel: failed to reclaim memory',
                         m.exit_reason('failed to reclaim memory'))
        self.assertEqual('exited unexpectedly', m.exit_reason(None))

    def test_the_system_reads_dmesg_and_reports_nothing_it_cannot_read(self):
        system = m.System()
        with mock.patch.object(system, 'run', return_value=subprocess.CompletedProcess(
                [], 0, self.MESSAGES.encode(), b'')) as run:
            self.assertEqual(['failed to reclaim memory'], system.kill_reasons(51155))
        run.assert_called_once_with(['/sbin/dmesg'], timeout=15, check=False)
        with mock.patch.object(system, 'run', return_value=subprocess.CompletedProcess([], 0, b'', b'')):
            self.assertEqual([], system.kill_reasons(51155))
        with mock.patch.object(system, 'run', return_value=subprocess.CompletedProcess([], 1, b'', b'')):
            self.assertIsNone(system.kill_reasons(51155))
        with mock.patch.object(system, 'run', side_effect=m.Error('timed out')):
            self.assertIsNone(system.kill_reasons(51155))
        self.assertIsNone(system.kill_reasons(None))


class RestartRecordTests(RecoveryCase):
    def test_the_record_is_private_runtime_state_and_garbage_reads_as_empty(self):
        self.assertEqual(self.manager.path(m.RESTART_FILE), self.manager.restart_file)
        self.assertTrue(str(self.manager.restart_file).endswith('/var/run/mihomo-restart.json'))
        self.assertEqual(0o600, self.manager.restart_file.stat().st_mode & 0o777)
        empty = {'armed': False, 'core': None, 'kills': None, 'attempts': [], 'pending': None, 'held': False,
                 'paused': False, 'last': None}
        stored = json.loads(self.manager.restart_file.read_bytes())
        for broken in ('nonsense', '[]', json.dumps(dict(stored, version=2)),
                       json.dumps(dict(stored, extra=1)), json.dumps(dict(stored, armed='yes')),
                       json.dumps(dict(stored, attempts=[1e300])),
                       json.dumps(dict(stored, pending={'reason': 'x', 'due': 1, 'at': float('inf')})),
                       json.dumps(dict(stored, last={'time': 'now', 'reason': 'x'})),
                       json.dumps(dict(stored, core={'pid': 'one', 'birth': '1:1'})),
                       json.dumps(dict(stored, kills=-1)), json.dumps(dict(stored, kills=True)),
                       json.dumps(dict(stored, held=1)), json.dumps(dict(stored, paused=True)),
                       json.dumps(dict(stored, paused=0)), json.dumps(dict(stored, paused='crash'))):
            with self.subTest(broken=broken):
                self.manager.restart_file.write_text(broken)
                self.assertEqual(empty, self.manager.restart_record())
                # Every stop publishes the status, which must survive it.
                self.manager.publish_status()

    def test_the_watchdog_counts_on_the_monotonic_clock_the_probes_use(self):
        self.assertIs(m.time.monotonic, m.Manager(Path(self.temp.name), self.system).clock)
        self.crash()
        self.tick(1)
        self.assertEqual(self.clock() + 10, self.record()['pending']['due'])
        self.tick(9)
        self.tick(1)
        self.assertEqual([self.clock()], self.record()['attempts'])

    def test_administrative_actions_clear_the_history_and_others_keep_it(self):
        self.crash()
        self.restart_after(10)
        for action in ('wan-restart', 'status', 'boot'):
            self.manager.dispatch(action)
            self.assertEqual(1, len(self.record()['attempts']), action)
            self.assertIsNotNone(self.record()['last'], action)
        self.manager.apply(SUBSCRIPTION)
        self.assertEqual(1, len(self.record()['attempts']))
        for action in ('restart', 'start', 'stop'):
            self.manager.write_restart_record(dict(self.record(), attempts=[self.clock()], paused='exit',
                                                   last={'time': 1.0, 'reason': 'x'}))
            self.manager.dispatch(action)
            self.assertEqual(([], False, None), (self.record()['attempts'], self.record()['paused'],
                                                 self.record()['last']), action)


class ConfigCacheTests(RecoveryCase):
    def config_parses(self, calls):
        content = self.manager.config_file.read_bytes()
        return sum(1 for call in calls if call.args and call.args[0] == content)

    def test_the_applied_configuration_is_parsed_once_per_version(self):
        with mock.patch.object(m, 'parse_yaml', wraps=m.parse_yaml) as parse:
            for _ in range(3):
                self.manager.applied_config()
            for _ in range(3):
                self.tick()
            self.manager.redirect_configured()
            self.manager.applied_dns_shape()
        self.assertLessEqual(self.config_parses(parse.call_args_list), 1)

    def test_router_dns_ticks_reuse_the_parse(self):
        self.manager.write_settings(dict(self.manager.settings(), router_dns=True))
        pins = m.dns_transport_rules('forward-addr: 192.0.2.53@853\n')
        data = self.manager.applied_config()
        data['rules'] = pins + data['rules']
        m.atomic_write(self.manager.config_file, m.yaml.safe_dump(data).encode())
        with mock.patch.object(self.manager, 'router_context', return_value=('forward-addr: 192.0.2.53@853\n', False)), \
                mock.patch.object(self.manager, 'apply') as apply:
            with mock.patch.object(m, 'parse_yaml', wraps=m.parse_yaml) as parse:
                for _ in range(4):
                    self.tick()
            # UFS with soft updates settles the change time of the renamed
            # file a few milliseconds after the rename, so the first tick
            # after a rewrite may parse it once more; the ticks after that
            # must not parse it at all.
            self.assertLessEqual(self.config_parses(parse.call_args_list), 2)
            with mock.patch.object(m, 'parse_yaml', wraps=m.parse_yaml) as parse:
                for _ in range(4):
                    self.tick()
        apply.assert_not_called()
        self.assertEqual(0, self.config_parses(parse.call_args_list))

    def test_the_backup_mirror_parses_the_subscription_once_per_version(self):
        # The mirror runs on every tick, router DNS or not; the subscription
        # is as large as the configuration rendered from it.
        source = self.manager.source_file.read_bytes()
        upstreams = 'forward-addr: 192.0.2.53@853\n'
        for router_dns in (False, True):
            if router_dns:
                # Pins that match, so the tick re-applies nothing.
                data = self.manager.applied_config()
                data['rules'] = m.dns_transport_rules(upstreams) + data['rules']
                m.atomic_write(self.manager.config_file, m.yaml.safe_dump(data).encode())
            self.manager.write_settings(dict(self.manager.settings(), router_dns=router_dns))
            self.manager._source_parse = None
            with mock.patch.object(self.manager, 'router_context', return_value=(upstreams, False)), \
                    mock.patch.object(self.manager, 'apply') as apply, \
                    mock.patch.object(m, 'parse_yaml', wraps=m.parse_yaml) as parse:
                for _ in range(4):
                    self.tick()
            apply.assert_not_called()
            self.assertEqual(1, sum(1 for call in parse.call_args_list if call.args and call.args[0] == source),
                             router_dns)
        # The mirror only reads the cached parse.
        self.assertEqual(m.parse_yaml(source), self.manager._source_parsed(source))
        # New bytes are parsed afresh, whatever their file's times say.
        self.manager.write_settings(dict(self.manager.settings(), router_dns=False))
        changed = SUBSCRIPTION.replace(b'rules: ["MATCH,Proxy"]', b'rules: ["MATCH,DIRECT"]')
        self.manager.apply(changed)
        self.assertEqual(changed, self.manager.source_file.read_bytes())
        self.assertEqual(['MATCH,DIRECT'], self.manager._source_parsed(changed)['rules'][-1:])
        self.assertEqual(['MATCH,Proxy'], self.manager._source_parsed(source)['rules'][-1:])

    def test_a_rewrite_is_never_served_from_the_cache(self):
        before = self.manager.applied_config()
        changed = SUBSCRIPTION.replace(b'rules: ["MATCH,Proxy"]', b'rules: ["MATCH,DIRECT"]')
        self.manager.apply(changed)
        self.assertEqual(['MATCH,DIRECT'], self.manager.applied_config()['rules'][-1:])
        self.assertNotEqual(before['rules'], self.manager.applied_config()['rules'])
        # Same length, same modification time, even the same inode: the
        # change time still tells the versions apart.
        path = self.manager.config_file
        current = path.read_bytes()
        self.manager.applied_config()
        info = path.stat()
        swapped = current.replace(b'MATCH,DIRECT', b'MATCH,REJECT')
        self.assertEqual(len(current), len(swapped))
        with path.open('r+b') as stream:
            stream.write(swapped)
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
        self.assertEqual((info.st_ino, info.st_size, info.st_mtime_ns),
                         (path.stat().st_ino, path.stat().st_size, path.stat().st_mtime_ns))
        self.assertEqual(['MATCH,REJECT'], self.manager.applied_config()['rules'][-1:])

    def test_callers_cannot_change_the_cached_parse(self):
        shape = copy.deepcopy(self.manager.applied_dns_shape())
        data = self.manager.applied_config()
        pristine = copy.deepcopy(data)
        data['rules'].append('MATCH,REJECT')
        data['dns']['ipv6'] = 'mutated'
        data['tun']['enable'] = False
        del data['proxies']
        data.clear()
        self.assertEqual(pristine, self.manager.applied_config())
        self.assertEqual(shape, self.manager.applied_dns_shape())
        self.assertIsNot(self.manager.applied_config(), self.manager.applied_config())

    def test_a_file_replaced_while_it_was_read_is_not_kept(self):
        original = m.parse_yaml
        path = self.manager.config_file
        replaced = []

        def racing(content):
            result = original(content)
            if not replaced and content == path.read_bytes():
                replaced.append(True)
                m.atomic_write(path, content.replace(b'MATCH,Proxy', b'MATCH,DIRECT'))
            return result

        self.manager._applied_config = None
        with mock.patch.object(m, 'parse_yaml', side_effect=racing):
            self.assertEqual(['MATCH,Proxy'], self.manager.applied_config()['rules'][-1:])
        self.assertEqual(['MATCH,DIRECT'], self.manager.applied_config()['rules'][-1:])


class LogRotationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'var/db/os-mihomo').mkdir(parents=True, mode=0o700)
        self.live = {}
        self.signals = []

    def reader(self, pid):
        value = self.live.get(pid)
        return dict(value) if value is not None else None

    def signaler(self, pid, number):
        self.signals.append((pid, number))

    def group(self, factory=owner.core_group):
        return factory(root=self.root, process_reader=self.reader, signaler=self.signaler,
                       sleeper=lambda seconds: None)

    def run_supervisor(self, group, parent=101, child=102, birth='1700000000:1'):
        """A supervisor and its child as daemon(8) leaves them, recorded in the ownership journal."""
        title = 'daemon: %s[%d]' % (group.tag, child)
        self.live[parent] = {'pid': parent, 'ppid': 1, 'uid': os.geteuid(), 'birth': birth,
                             'executable': owner.DAEMON, 'argv': [title], 'stopped': False}
        self.live[child] = {'pid': child, 'ppid': parent, 'uid': os.geteuid(), 'birth': birth,
                            'executable': group.child_executable, 'argv': list(group.child_argv),
                            'stopped': False}
        return group.persist(self.live[parent], self.live[child])

    def test_both_supervisors_are_started_with_dash_h(self):
        system = m.System()
        commands = []

        def run(args, **kwargs):
            commands.append((list(args), kwargs.get('env')))
            return subprocess.CompletedProcess(args, 1 if args[0] == '/usr/sbin/service' else 0, b'', b'')

        config = self.root / 'config.yaml'
        config.write_text('mixed-port: 7890\ntun: {enable: false}\ndns: {enable: false}\n')
        core = mock.Mock()
        core.record_started.return_value = {'core': 'record'}
        watch = mock.Mock()
        watch.running.return_value = False
        watch.record_started.return_value = {'watch': 'record'}
        with mock.patch.object(system, 'run', side_effect=run), \
                mock.patch.object(system, 'running', side_effect=[False, True]), \
                mock.patch.object(system, 'recover_reloads'), mock.patch.object(system, 'destroy_tun'), \
                mock.patch.object(system, '_core_group', return_value=core), \
                mock.patch.object(system, '_watch_group', return_value=watch), \
                mock.patch.object(system, 'physical_memory', return_value=4 * GIB), \
                mock.patch.object(m.socket, 'create_connection'):
            system.start(config, False)
            system.watch()
        daemons = [(args, env) for args, env in commands if args[0] == '/usr/sbin/daemon']
        self.assertEqual(2, len(daemons))
        (start, start_env), (watcher, watcher_env) = daemons
        self.assertEqual(['/usr/sbin/daemon', '-H', '-P', m.DAEMON_PID, '-p', m.PID, '-f', '-o',
                          '/var/log/mihomo.log', '-t', 'mihomo', '/usr/local/bin/mihomo'], start[:12])
        self.assertEqual(['/usr/sbin/daemon', '-H', '-P', m.WATCH_PID, '-p', m.WATCH_CHILD_PID, '-f', '-o',
                          '/var/log/mihomo.log', '-t', 'mihomo-watch', '/usr/local/bin/python3', m.SCRIPT,
                          'watch'], watcher)
        self.assertEqual('1228MiB', start_env['GOMEMLIMIT'])
        self.assertIsNone(watcher_env)
        # Each start records the supervisor it started with -H.
        core.mark_reopenable.assert_called_once_with({'core': 'record'})
        watch.mark_reopenable.assert_called_once_with({'watch': 'record'})

    def test_newsyslog_runs_the_reopen_executable_after_rotating_the_core_log(self):
        lines = {line.split()[0]: line.split() for line in NEWSYSLOG.read_text().splitlines()
                 if line.strip() and not line.startswith('#')}
        self.assertEqual(['/var/log/mihomo.log', '640', '5', '1024', '*', 'JCR',
                          '/usr/local/opnsense/scripts/mihomo/reopen_log.sh'], lines['/var/log/mihomo.log'])
        # Every write to the subscription log opens it afresh, so a rotation
        # needs no signal there.
        self.assertEqual(['/var/log/mihomo_sub.log', '640', '5', '512', '*', 'JC'], lines['/var/log/mihomo_sub.log'])

    def test_the_subscription_log_has_no_long_lived_writer(self):
        manager = m.Manager(self.root, mock.Mock())
        manager.log('before the rotation')
        log = self.root / 'var/log/mihomo_sub.log'
        log.rename(log.with_name('mihomo_sub.log.0'))
        manager.log('after the rotation')
        self.assertIn('after the rotation', log.read_text())
        self.assertNotIn('after the rotation', log.with_name('mihomo_sub.log.0').read_text())

    def test_the_reopen_executable_is_committed_executable_and_packaged_so(self):
        self.assertTrue(REOPEN.stat().st_mode & 0o111, 'newsyslog cannot run a file that is not executable')
        subprocess.run(['sh', '-n', str(REOPEN)], check=True)
        commands = [line for line in REOPEN.read_text().splitlines() if line and not line.startswith('#')]
        self.assertEqual(['#!/bin/sh'], [line for line in REOPEN.read_text().splitlines()[:1]])
        self.assertEqual(['exec /usr/local/bin/python3 /usr/local/opnsense/scripts/mihomo/mihomo.py reopen-log'],
                         commands)
        self.assertIn('"$STAGEDIR/usr/local/opnsense/scripts/mihomo/reopen_log.sh"', (ROOT / 'build.sh').read_text())
        spec = importlib.util.spec_from_file_location('reopen_target', ROOT / 'packaging/target.py')
        target = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(target)
        values = target.target_values('FreeBSD:15:amd64', '26.7', '3.13')
        self.assertIn(b'/usr/local/bin/python3.13 /usr/local/opnsense/scripts/mihomo/mihomo.py reopen-log',
                      target.transform_content(REOPEN.read_bytes(), values))

    def test_only_a_supervisor_marked_as_started_with_dash_h_is_signalled(self):
        group = self.group()
        record = self.run_supervisor(group)
        # Started by 1.5.0, without -H: SIGHUP would end it, so it is left alone.
        self.assertFalse(group.reopen_output())
        self.assertEqual([], self.signals)
        group.mark_reopenable(record)
        marker = self.root / 'var/db/os-mihomo/log-reopen.json'
        self.assertEqual(0o600, marker.stat().st_mode & 0o777)
        self.assertTrue(group.reopen_output())
        # The supervisor alone: the core never sees the signal.
        self.assertEqual([(101, signal.SIGHUP)], self.signals)

    def test_a_marker_for_another_supervisor_signals_nothing(self):
        group = self.group()
        old = self.run_supervisor(group)
        group.mark_reopenable(old)
        # A later start without a new marker, under the same PID numbers:
        # its supervisor's birth differs from the one the marker proves.
        self.live.clear()
        self.run_supervisor(group, birth='1700000500:1')
        self.assertFalse(group.reopen_output())
        # A supervisor that is gone is not signalled either.
        group.mark_reopenable(group.load()[0])
        self.live.pop(101)
        self.assertFalse(group.reopen_output())
        self.assertEqual([], self.signals)

    def test_a_marker_that_is_not_ours_proves_nothing(self):
        group = self.group()
        group.mark_reopenable(self.run_supervisor(group))
        marker = self.root / 'var/db/os-mihomo/log-reopen.json'
        content = json.loads(marker.read_text())
        for broken in ('nonsense', json.dumps(dict(content, tag='mihomo-watch')),
                       json.dumps(dict(content, version=2)),
                       json.dumps(dict(content, parent=dict(content['parent'], executable='/bin/sh')))):
            with self.subTest(broken=broken):
                marker.write_text(broken)
                marker.chmod(0o600)
                with self.assertRaises(owner.OwnershipError):
                    group.reopen_output()
        marker.write_text(json.dumps(content))
        marker.chmod(0o644)
        with self.assertRaises(owner.OwnershipError):
            group.reopen_output()
        self.assertEqual([], self.signals)
        with self.assertRaises(owner.OwnershipError):
            group.mark_reopenable({'parent': {'pid': 1}})

    def test_the_system_asks_both_supervisors_and_reports_one_it_cannot_prove(self):
        core = self.group()
        watch = self.group(owner.watch_group)
        core.mark_reopenable(self.run_supervisor(core))
        watch.mark_reopenable(self.run_supervisor(watch, parent=201, child=202))
        system = m.System()
        with mock.patch.object(system, '_core_group', return_value=core), \
                mock.patch.object(system, '_watch_group', return_value=watch):
            self.assertEqual(2, system.reopen_logs())
            self.assertEqual([(101, signal.SIGHUP), (201, signal.SIGHUP)], self.signals)
            self.signals.clear()
            (self.root / 'var/db/os-mihomo/log-reopen.json').write_text('nonsense')
            with self.assertRaisesRegex(m.Error, 'not signalled'):
                system.reopen_logs()
            # The proven one is still asked.
            self.assertEqual([(201, signal.SIGHUP)], self.signals)
        # Nothing running and nothing recorded is a success.
        empty = Path(self.temp.name) / 'empty'
        (empty / 'var/db/os-mihomo').mkdir(parents=True, mode=0o700)
        with mock.patch.object(system, '_core_group', return_value=owner.core_group(root=empty)), \
                mock.patch.object(system, '_watch_group', return_value=owner.watch_group(root=empty)):
            self.assertEqual(0, system.reopen_logs())

    def test_the_action_takes_no_lock_prints_nothing_and_fails_loudly(self):
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, 'argv', ['mihomo.py', 'reopen-log']), \
                mock.patch.object(m.os, 'geteuid', return_value=0), \
                mock.patch.object(m.Manager, 'lock', side_effect=AssertionError('newsyslog must not wait')), \
                mock.patch.object(m.System, 'reopen_logs', return_value=0) as reopen, \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            self.assertEqual(0, m.main())
        reopen.assert_called_once_with()
        self.assertEqual(('', ''), (output.getvalue(), errors.getvalue()))
        with mock.patch.object(sys, 'argv', ['mihomo.py', 'reopen-log']), \
                mock.patch.object(m.os, 'geteuid', return_value=0), \
                mock.patch.object(m.System, 'reopen_logs', side_effect=m.Error('unproven')), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            self.assertEqual(1, m.main())
        self.assertIn('unproven', errors.getvalue())


class StatusViewTests(unittest.TestCase):
    VIEW = SOURCE / 'usr/local/opnsense/mvc/app/views/OPNsense/Mihomo/index.volt'

    def test_the_status_tab_shows_core_memory_and_the_last_restart(self):
        view = self.VIEW.read_text()
        self.assertIn('id="mihomo-service-note"', view)
        for field in ('state.core_memory', 'state.core_memory_limit', 'state.restart_note'):
            self.assertIn(field, view)
        self.assertIn("{{ lang._('Core memory: %s') }}", view)
        self.assertIn("{{ lang._('(restarted above %s)') }}", view)
        manager = (SOURCE / 'usr/local/opnsense/scripts/mihomo/mihomo.py').read_text()
        for key in ('"restart_note": restart_note', '"last_restart"', '"core_memory": core_memory',
                    '"core_memory_limit"'):
            self.assertIn(key, manager)

    def test_the_readmes_no_longer_promise_a_crashed_core_stays_down(self):
        for path, stale, current in ((ROOT / 'README.US.md', 'the core is not restarted', 'automatic restart'),
                                     (ROOT / 'README.md', '核心不会自动重启', '自动重启')):
            with self.subTest(path=path.name):
                text = path.read_text()
                self.assertNotIn(stale, text)
                self.assertIn(current, text)
                self.assertIn('GOMEMLIMIT', text)
                self.assertIn('newsyslog', text)

    def test_the_readmes_quote_each_pause_message_where_it_is_written(self):
        # The status error carries the pause notices; the log carries the
        # pause beside what met it, never the status's own sentence.
        logged = 'Mihomo stopped (%s); %s' % (m.EXIT_UNEXPECTED, m.RESTART_PAUSE_TAIL)
        for path in (ROOT / 'README.US.md', ROOT / 'README.md'):
            with self.subTest(path=path.name):
                text = path.read_text()
                self.assertIn('`%s`' % m.RESTART_PAUSED, text)
                self.assertIn('`%s`' % m.MEMORY_PAUSED, text)
                self.assertIn('`%s`' % logged, text)
                self.assertNotRegex(text, r'`mihomo\.log`[^.`]*(?:say|写明)[^`]*Mihomo exited repeatedly')

    def test_the_readmes_say_a_pending_backup_holds_the_restart_and_the_memory_guard(self):
        # restart_core()'s reconciliation never sees a pending restore: the
        # backup guard's branch of the tick runs neither it nor the memory guard.
        for path, stale, held in ((ROOT / 'README.US.md', 'reconciliation of a restored configuration backup',
                                   'it neither restarts the core nor guards its memory'),
                                  (ROOT / 'README.md', '包括对已恢复配置备份的核对', '既不自动重启核心，也不做内存保护')):
            with self.subTest(path=path.name):
                text = path.read_text()
                self.assertNotIn(stale, text)
                self.assertIn(held, text)


if __name__ == '__main__':
    unittest.main()
