"""Exercise every WAN Guard decision with a fake clock, fake helper and fake log."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE / 'src/usr/local/opnsense/scripts/wanguard'))
import guard  # noqa: E402


class Clock:
    def __init__(self, now=10000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class Actor:
    """Records helper calls; answers from a script, 'requested' by default."""

    def __init__(self, results=(), restores=()):
        self.results = list(results)
        self.restores = list(restores)
        self.calls = []

    def redhcp(self, name, address, reason):
        self.calls.append(('redhcp', name, address, reason))
        return self.results.pop(0) if self.results else 'requested'

    def restore(self, name):
        self.calls.append(('restore', name))
        return self.restores.pop(0) if self.restores else 'restored'


class Log(list):
    def __call__(self, level, message):
        self.append((level, message))

    def having(self, text):
        return [line for line in self if text in line[1]]


def interface(name='opt2', **changes):
    row = {'name': name, 'descr': name.upper(), 'exists': True, 'device': 'vtnet3', 'enabled': True,
           'ipaddr': 'dhcp', 'eligible': True, 'address': '10.0.3.15', 'carrier': True,
           'dhclient_running': True}
    row.update(changes)
    return row


def snapshot(rows=None, enabled=True, watched=('opt2',), networks=('10.0.3.0/24',), private=False, booting=False):
    rows = [interface()] if rows is None else rows
    return guard.parse_snapshot({'enabled': enabled, 'booting': booting, 'watched': list(watched),
                                 'networks': list(networks), 'private_ranges': private, 'interfaces': rows})


class Harness:
    def __init__(self, results=(), restores=()):
        self.clock = Clock()
        self.actor = Actor(results, restores)
        self.log = Log()
        self.state = guard.new_state('1:1')
        self.saves = 0
        self.guard = guard.Guard(self.state, self.actor, self.log, self.clock, lambda: 1790000000 + self.clock.now,
                                 persist=self.persist)

    def persist(self):
        self.saves += 1

    def tick(self, seconds=30, manual=(), **kwargs):
        self.clock.advance(seconds)
        self.guard.apply(snapshot(**kwargs), manual)

    def actions(self):
        return [call for call in self.actor.calls if call[0] == 'redhcp']

    def tracker(self, name='opt2'):
        return self.state['interfaces'].get(name)


class ClassifierTests(unittest.TestCase):
    def test_configured_networks_and_their_boundaries(self):
        networks, dropped = guard.parse_networks('172.31.254.0/24')
        rules = guard.Rules(networks)
        self.assertEqual(dropped, [])
        self.assertEqual(rules.classify('172.31.254.0'), (guard.UNWANTED, '172.31.254.0/24'))
        self.assertEqual(rules.classify('172.31.254.10'), (guard.UNWANTED, '172.31.254.0/24'))
        self.assertEqual(rules.classify('172.31.254.255'), (guard.UNWANTED, '172.31.254.0/24'))
        self.assertEqual(rules.classify('172.31.255.1'), (guard.WANTED, None))
        self.assertEqual(rules.classify('172.31.253.255'), (guard.WANTED, None))
        self.assertEqual(rules.classify('104.52.226.170'), (guard.WANTED, None))

    def test_private_switch_uses_the_core_ranges_only_when_on(self):
        self.assertEqual([str(network) for network in guard.PRIVATE_RANGES],
                         ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8',
                          '100.64.0.0/10', '169.254.0.0/16'])
        off, on = guard.Rules([], False), guard.Rules([], True)
        for address, rule in [('10.0.3.15', '10.0.0.0/8'), ('172.16.0.1', '172.16.0.0/12'),
                              ('172.31.255.255', '172.16.0.0/12'), ('192.168.1.2', '192.168.0.0/16'),
                              ('100.64.0.1', '100.64.0.0/10'), ('100.127.255.254', '100.64.0.0/10'),
                              ('169.254.1.1', '169.254.0.0/16'), ('127.0.0.1', '127.0.0.0/8')]:
            with self.subTest(address=address):
                self.assertEqual(off.classify(address), (guard.WANTED, None))
                self.assertEqual(on.classify(address), (guard.UNWANTED, rule))
        for address in ['172.32.0.1', '100.128.0.1', '100.63.255.255', '9.255.255.255', '11.0.0.0',
                        '192.169.0.1', '169.253.255.255', '104.52.226.170']:
            with self.subTest(address=address):
                self.assertEqual(on.classify(address), (guard.WANTED, None))
        self.assertTrue(guard.Rules([], False).empty())
        self.assertFalse(on.empty())

    def test_configured_network_wins_over_the_private_range_for_the_logged_rule(self):
        rules = guard.Rules(guard.parse_networks(['10.0.3.0/24'])[0], True)
        self.assertEqual(rules.classify('10.0.3.7'), (guard.UNWANTED, '10.0.3.0/24'))
        self.assertEqual(rules.classify('10.0.4.7'), (guard.UNWANTED, '10.0.0.0/8'))

    def test_no_usable_address_is_none(self):
        rules = guard.Rules(guard.parse_networks(['10.0.0.0/8'])[0], True)
        for address in [None, '', '0.0.0.0', 'fe80::1', '2001:db8::1', 'garbage', '10.0.0', 42, ['10.0.0.1']]:
            with self.subTest(address=address):
                self.assertEqual(rules.classify(address), (guard.NONE, None))

    def test_invalid_or_too_wide_entries_are_dropped(self):
        networks, dropped = guard.parse_networks(['10.0.3.0/24', ' 172.31.254.0/24 ', '0.0.0.0/0', '10.0.0.0/7',
                                                  '10.0.3.1/24', '10.0.3.1', 'fe80::/10', 'nonsense', '', 5,
                                                  '10.0.3.0/24'])
        self.assertEqual([str(network) for network in networks], ['10.0.3.0/24', '172.31.254.0/24'])
        self.assertEqual(dropped, ['0.0.0.0/0', '10.0.0.0/7', '10.0.3.1/24', '10.0.3.1', 'fe80::/10',
                                   'nonsense', '5'])
        many = ['10.%d.0.0/16' % index for index in range(40)]
        networks, dropped = guard.parse_networks(','.join(many))
        self.assertEqual(len(networks), guard.MAX_NETWORKS)
        self.assertEqual(dropped, many[guard.MAX_NETWORKS:])

    def test_dropped_entries_are_logged_once(self):
        harness = Harness()
        for _ in range(3):
            harness.tick(networks=('10.0.3.0/24', '0.0.0.0/0'), rows=[interface(address='198.51.100.7')])
        self.assertEqual(len(harness.log.having('0.0.0.0/0')), 1)
        self.assertEqual(harness.log.having('0.0.0.0/0')[0][0], 'warning')


class SnapshotTests(unittest.TestCase):
    def test_malformed_observations_are_rejected_whole(self):
        good = {'enabled': True, 'booting': False, 'watched': ['wan'], 'networks': [], 'private_ranges': False,
                'interfaces': [interface('wan')]}
        guard.parse_snapshot(good)
        for key, value in [('enabled', 1), ('booting', None), ('private_ranges', 'no'), ('watched', 'wan'),
                           ('networks', None), ('interfaces', {}), ('interfaces', ['wan'])]:
            broken = dict(good)
            broken[key] = value
            with self.subTest(key=key), self.assertRaises(guard.ObserveError):
                guard.parse_snapshot(broken)
        for row in [interface('WAN'), interface('wan', address=5), interface('../x')]:
            with self.subTest(row=row['name']), self.assertRaises(guard.ObserveError):
                guard.parse_snapshot(dict(good, interfaces=[row]))
        with self.assertRaises(guard.ObserveError):
            guard.parse_snapshot(None)

    def test_flags_are_read_strictly(self):
        value = guard.parse_snapshot({'enabled': True, 'booting': False, 'watched': ['wan', 'Bad!', 'wan'],
                                      'networks': [], 'private_ranges': False,
                                      'interfaces': [interface('wan', carrier='yes', eligible=1)]})
        self.assertEqual(value['watched'], ['wan'])
        self.assertFalse(value['interfaces']['wan']['carrier'])
        self.assertFalse(value['interfaces']['wan']['eligible'])


class DebounceTests(unittest.TestCase):
    def test_a_single_unwanted_observation_never_acts(self):
        harness = Harness()
        harness.tick()
        self.assertEqual(harness.actions(), [])
        self.assertEqual(harness.tracker()['streak'], 1)
        self.assertEqual(len(harness.log.having('confirming')), 1)

    def test_the_second_observation_twenty_seconds_later_acts(self):
        harness = Harness()
        harness.tick()
        harness.tick(20)
        self.assertEqual(len(harness.actions()), 1)
        self.assertEqual(harness.actions()[0][1:3], ('opt2', '10.0.3.15'))

    def test_a_wake_right_after_a_tick_counts_once(self):
        harness = Harness()
        harness.tick()
        harness.tick(1)
        harness.tick(5)
        harness.tick(13)
        self.assertEqual(harness.actions(), [])
        self.assertEqual(harness.tracker()['streak'], 1)
        harness.tick(1)
        self.assertEqual(len(harness.actions()), 1)

    def test_a_confirmation_from_before_a_long_pause_does_not_count(self):
        harness = Harness()
        harness.tick()
        # Nothing was observed for three hours: a stopped service, say.
        harness.tick(3 * guard.HOUR)
        self.assertEqual(harness.actions(), [])
        self.assertEqual(harness.tracker()['streak'], 1)
        harness.tick(30)
        self.assertEqual(len(harness.actions()), 1)

    def test_one_skipped_observation_keeps_the_streak(self):
        harness = Harness()
        harness.tick()
        harness.tick(guard.STREAK_WINDOW)
        self.assertEqual(len(harness.actions()), 1)

    def test_no_address_breaks_the_streak(self):
        harness = Harness()
        harness.tick()
        harness.tick(rows=[interface(address=None)])
        harness.tick()
        self.assertEqual(harness.actions(), [])
        self.assertEqual(harness.tracker()['streak'], 1)

    def test_a_wanted_address_resets_everything(self):
        harness = Harness()
        harness.tick()
        harness.tick()
        self.assertEqual(harness.tracker()['stage'], 1)
        harness.tick(rows=[interface(address='198.51.100.7')])
        tracker = harness.tracker()
        self.assertEqual((tracker['streak'], tracker['stage'], tracker['next_retry']), (0, 0, None))
        self.assertEqual(len(tracker['actions']), 1)
        self.assertEqual(len(harness.log.having('now has wanted address 198.51.100.7; state reset after 1')), 1)
        harness.tick(rows=[interface(address='198.51.100.7')])
        self.assertEqual(len(harness.log.having('state reset')), 1)


class BackoffTests(unittest.TestCase):
    def test_gaps_between_actions_follow_the_schedule_exactly(self):
        harness = Harness()
        times = []
        for _ in range(int(2 * guard.HOUR / 30)):
            before = len(harness.actions())
            harness.tick()
            if len(harness.actions()) > before:
                times.append(harness.clock.now)
        gaps = [later - earlier for earlier, later in zip(times, times[1:])]
        self.assertEqual(gaps[:6], [60, 120, 300, 900, 900, 900])
        self.assertTrue(all(gap == 900 for gap in gaps[3:]))
        for start in times:
            self.assertLessEqual(len([t for t in times if start <= t < start + guard.HOUR]), 7)
        self.assertEqual([call[3] for call in harness.actions()][0], 'address 10.0.3.15 is in 10.0.3.0/24')

    def test_the_stage_survives_a_missing_address(self):
        harness = Harness()
        harness.tick()
        harness.tick()
        harness.tick(rows=[interface(address=None)])
        self.assertEqual(harness.tracker()['stage'], 1)
        self.assertIsNotNone(harness.tracker()['next_retry'])

    def test_after_a_reset_the_next_streak_starts_at_sixty_seconds_again(self):
        harness = Harness()
        for _ in range(12):
            harness.tick()
        self.assertGreaterEqual(harness.tracker()['stage'], 3)
        harness.tick(rows=[interface(address='198.51.100.7')])
        harness.clock.advance(guard.HOUR)
        count = len(harness.actions())
        harness.tick()
        harness.tick()
        self.assertEqual(len(harness.actions()), count + 1)
        self.assertEqual(harness.tracker()['stage'], 1)
        self.assertEqual(harness.tracker()['next_retry'] - harness.clock.now, 60)

    def test_backoff_values(self):
        self.assertEqual([guard.backoff(stage) for stage in range(1, 8)], [60, 120, 300, 900, 900, 900, 900])


class RateLimitTests(unittest.TestCase):
    def test_manual_retry_bypasses_confirmation_and_backoff_but_not_the_minimum_gap(self):
        harness = Harness()
        harness.tick(manual={'opt2'})
        self.assertEqual(len(harness.actions()), 1)
        self.assertEqual(harness.tracker()['last_action']['trigger'], 'manual')
        self.assertEqual(harness.tracker()['last_manual']['result'], 'requested')
        harness.tick(30, manual={'opt2'})
        self.assertEqual(len(harness.actions()), 1)
        self.assertEqual(harness.tracker()['last_manual']['result'], 'refused:too-soon')
        self.assertEqual(len(harness.log.having('manual retry on opt2 refused: the previous action')), 1)
        harness.tick(30, manual={'opt2'})
        self.assertEqual(len(harness.actions()), 2)
        self.assertEqual(harness.tracker()['stage'], 2)

    def test_the_hourly_cap_holds_for_automatic_and_manual_requests(self):
        harness = Harness()
        harness.tick()
        tracker = harness.tracker()
        tracker['actions'] = [harness.clock.now - 3000 + index * 300 for index in range(8)]
        tracker['stage'] = 4
        tracker['next_retry'] = harness.clock.now
        tracker['streak'] = 1
        harness.tick(61)
        harness.tick(61, manual={'opt2'})
        self.assertEqual(harness.actions(), [])
        self.assertEqual(tracker['last_manual']['result'], 'refused:hourly-cap')
        self.assertEqual(len(harness.log.having('opt2 reached 8 actions in the last hour')), 1)
        # The oldest actions age out of the rolling hour; then it may act
        # again, once the address is confirmed anew after the long pause.
        harness.tick(670)
        self.assertEqual(harness.actions(), [])
        harness.tick(30)
        self.assertEqual(len(harness.actions()), 1)

    def test_manual_retry_is_refused_unless_the_address_is_unwanted_and_watched(self):
        cases = [({'rows': [interface(address='198.51.100.7')]}, 'wanted'),
                 ({'rows': [interface(address=None)]}, 'no-address'),
                 ({'enabled': False}, 'disabled'),
                 ({'booting': True}, 'booting'),
                 ({'rows': [interface(carrier=False)]}, 'no-carrier'),
                 ({'rows': [interface(ipaddr='static', eligible=False)]}, 'not-eligible')]
        for kwargs, code in cases:
            with self.subTest(code=code):
                harness = Harness()
                harness.tick(manual={'opt2'}, **kwargs)
                self.assertEqual(harness.actions(), [])
                self.assertEqual(len(harness.log.having('manual retry on opt2 refused: ' + guard.REFUSALS[code])), 1)
        harness = Harness()
        harness.tick(manual={'wan'})
        self.assertEqual(harness.actions(), [])
        self.assertEqual(len(harness.log.having('manual retry on wan refused: the interface is not watched')), 1)


class SafetyTests(unittest.TestCase):
    def test_a_disabled_plugin_never_acts_and_keeps_its_history(self):
        harness = Harness()
        harness.tick()
        for _ in range(10):
            harness.tick(enabled=False)
        self.assertEqual(harness.actor.calls, [])
        self.assertEqual(harness.tracker()['streak'], 1)

    def test_non_dhcp_disabled_or_missing_interfaces_are_ignored_and_forgotten(self):
        for row in [interface(ipaddr='static', eligible=False), interface(ipaddr='pppoe', eligible=False),
                    interface(enabled=False, eligible=False), interface(exists=False, eligible=False),
                    interface(device='bad device'), interface(eligible=False)]:
            with self.subTest(row=row):
                harness = Harness()
                harness.tick()
                self.assertIsNotNone(harness.tracker())
                for _ in range(10):
                    harness.tick(rows=[row])
                self.assertEqual(harness.actor.calls, [])
                self.assertIsNone(harness.tracker())
                self.assertEqual(len(harness.log.having('opt2 is ignored because')), 1)
        harness = Harness()
        for _ in range(4):
            harness.tick(rows=[])
        self.assertEqual(harness.actor.calls, [])

    def test_an_unwatched_interface_loses_its_state(self):
        harness = Harness()
        harness.tick()
        harness.tick(watched=('wan',), rows=[interface('wan', address='198.51.100.7')])
        self.assertIsNone(harness.tracker())
        self.assertEqual(len(harness.log.having('opt2 is no longer watched')), 1)

    def test_an_interface_without_a_running_client_is_left_alone(self):
        harness = Harness()
        for _ in range(6):
            harness.tick(rows=[interface(dhclient_running=False)])
        harness.tick(manual={'opt2'}, rows=[interface(dhclient_running=False)])
        self.assertEqual(harness.actor.calls, [])
        self.assertEqual(len(harness.log.having('but no IPv4 DHCP client is running; waiting')), 1)
        self.assertEqual(harness.tracker()['last_manual']['result'], 'refused:no-client')
        # Once core runs a client, the usual confirmation applies.
        harness.tick()
        self.assertEqual(len(harness.actions()), 1)

    def test_the_lan_is_never_watched(self):
        harness = Harness()
        for _ in range(6):
            harness.tick(watched=('lan',), rows=[interface('lan')])
        harness.tick(watched=('lan',), rows=[interface('lan')], manual={'lan'})
        self.assertEqual(harness.actor.calls, [])
        self.assertIsNone(harness.tracker('lan'))
        self.assertEqual(len(harness.log.having('lan is ignored because it is the LAN')), 1)
        self.assertEqual(len(harness.log.having('manual retry on lan refused: the interface is the LAN')), 1)

    def test_the_rate_limits_survive_a_dropped_record(self):
        changes = [{'rows': [interface(eligible=False)]}, {'watched': (), 'rows': []}, {'rows': [interface(device='igc1')]}]
        for change in changes:
            with self.subTest(change=sorted(change)):
                harness = Harness()
                for _ in range(8):
                    harness.tick(61, manual={'opt2'})
                self.assertEqual(len(harness.actions()), 8)
                harness.tick(1, **change)
                harness.tick(61, manual={'opt2'})
                self.assertEqual(len(harness.actions()), 8)
                self.assertEqual(harness.tracker()['last_manual']['result'], 'refused:hourly-cap')
                # The carried actions still age out of the rolling hour.
                harness.tick(guard.HOUR - 8 * 61, manual={'opt2'})
                self.assertEqual(len(harness.actions()), 9)
                self.assertEqual(harness.state['recent'], {})

    def test_recent_actions_of_a_forgotten_interface_expire(self):
        harness = Harness()
        harness.tick(manual={'opt2'})
        harness.tick(watched=(), rows=[])
        self.assertEqual(list(harness.state['recent']), ['opt2'])
        harness.tick(guard.HOUR, watched=(), rows=[])
        self.assertEqual(harness.state['recent'], {})

    def test_booting_and_missing_carrier_block_actions(self):
        harness = Harness()
        for _ in range(6):
            harness.tick(booting=True)
        self.assertEqual(harness.actions(), [])
        for _ in range(6):
            harness.tick(rows=[interface(carrier=False)])
        self.assertEqual(harness.actions(), [])
        self.assertEqual(len(harness.log.having('but no carrier')), 1)
        harness.tick()
        self.assertEqual(len(harness.actions()), 1)

    def test_a_changed_device_starts_a_fresh_record(self):
        harness = Harness()
        harness.tick()
        harness.tick(rows=[interface(device='igc1')])
        self.assertEqual(harness.tracker()['device'], 'igc1')
        self.assertEqual(harness.tracker()['streak'], 1)
        self.assertEqual(harness.actions(), [])

    def test_refused_and_busy_results_are_not_counted(self):
        for result in ['busy', 'refused:address-changed', 'refused:no-carrier']:
            with self.subTest(result=result):
                harness = Harness(results=[result])
                harness.tick()
                harness.tick()
                tracker = harness.tracker()
                self.assertEqual(len(harness.actions()), 1)
                self.assertEqual((tracker['stage'], tracker['actions'], tracker['next_retry']), (0, [], None))
                self.assertEqual(harness.saves, 1)
                self.assertEqual(len(harness.log.having('result %s; not counted' % result)), 1)
                harness.tick()
                self.assertEqual(len(harness.actions()), 2)

    def test_a_failed_action_counts_and_the_repair_is_bounded(self):
        harness = Harness(results=['failed:no-client'], restores=['failed:no-client', 'restored'])
        harness.tick()
        harness.tick()
        tracker = harness.tracker()
        self.assertEqual(tracker['stage'], 1)
        self.assertTrue(tracker['owned'] and tracker['repair_due'])
        self.assertEqual(len([line for line in harness.log if line[0] == 'error']), 1)
        down = [interface(dhclient_running=False)]
        harness.tick(rows=down)
        self.assertEqual(harness.actor.calls[-1], ('restore', 'opt2'))
        for _ in range(9):
            harness.tick(rows=down)
        self.assertEqual(len([call for call in harness.actor.calls if call[0] == 'restore']), 1)
        self.assertEqual(len(harness.actions()), 1)
        harness.tick(rows=down)
        self.assertEqual(len([call for call in harness.actor.calls if call[0] == 'restore']), 2)
        harness.tick(rows=[interface(address='198.51.100.7')])
        self.assertFalse(tracker['owned'] or tracker['repair_due'])
        count = len(harness.actor.calls)
        for _ in range(20):
            harness.tick(rows=[interface(address='198.51.100.7', dhclient_running=False)])
        self.assertEqual(len(harness.actor.calls), count)

    def test_a_requested_action_whose_client_vanished_is_repaired_once_confirmed_gone(self):
        harness = Harness()
        harness.tick()
        harness.tick()
        self.assertTrue(harness.tracker()['owned'])
        self.assertFalse(harness.tracker()['repair_due'])
        harness.tick(rows=[interface(dhclient_running=False)], manual={'opt2'})
        self.assertEqual(harness.actor.calls[-1], ('restore', 'opt2'))
        self.assertEqual(harness.tracker()['last_manual']['result'], 'refused:repairing')

    def test_an_old_client_that_ignored_term_is_watched_until_it_is_seen_again(self):
        harness = Harness(results=['failed:old-client'])
        harness.tick()
        harness.tick()
        self.assertTrue(harness.tracker()['owned'])
        self.assertFalse(harness.tracker()['repair_due'])
        harness.tick()
        self.assertFalse(harness.tracker()['owned'])
        harness = Harness(results=['failed:old-client'])
        harness.tick()
        harness.tick()
        # It exited late after all: no client is left, so the repair takes over.
        harness.tick(rows=[interface(dhclient_running=False)])
        self.assertEqual(harness.actor.calls[-1], ('restore', 'opt2'))

    def test_a_client_we_did_not_stop_is_never_repaired(self):
        harness = Harness()
        for _ in range(20):
            harness.tick(rows=[interface(address='198.51.100.7', dhclient_running=False)])
        harness.tick(rows=[interface(dhclient_running=False)])
        self.assertEqual(harness.actor.calls, [])

    def test_repair_waits_for_the_end_of_boot(self):
        harness = Harness(results=['failed:no-client'])
        harness.tick()
        harness.tick()
        for _ in range(3):
            harness.tick(booting=True, rows=[interface(dhclient_running=False)])
        self.assertEqual([call[0] for call in harness.actor.calls], ['redhcp'])

    def test_the_corrupt_state_cooldown_blocks_automatic_actions_only(self):
        harness = Harness()
        harness.state['cooldown_until'] = harness.clock.now + guard.CORRUPT_COOLDOWN
        for _ in range(8):
            harness.tick()
        self.assertEqual(harness.actions(), [])
        harness.tick(manual={'opt2'})
        self.assertEqual(len(harness.actions()), 1)
        harness.state['interfaces'].clear()
        harness.tick(100)
        harness.tick()
        self.assertEqual(len(harness.actions()), 2)

    def test_each_action_writes_one_line_before_and_one_after(self):
        harness = Harness(results=['requested', 'failed:old-client'])
        for _ in range(4):
            harness.tick()
        self.assertEqual(len(harness.actions()), 2)
        before = harness.log.having('re-requesting IPv4 DHCP on opt2 (vtnet3)')
        after = [line for line in harness.log if line[1].startswith('opt2: result')]
        self.assertEqual(len(before), 2)
        self.assertEqual(len(after), 2)
        self.assertIn('attempt 1, trigger auto, address 10.0.3.15 is in 10.0.3.0/24', before[0][1])
        self.assertIn('attempt 2, trigger auto', before[1][1])
        self.assertEqual(after[0], ('notice', 'opt2: result requested, next retry in 60 s'))
        self.assertEqual(after[1], ('error', 'opt2: result failed:old-client, next retry in 120 s'))

    def test_the_action_is_persisted_before_the_helper_runs(self):
        seen = []

        class Recording(Actor):
            def redhcp(inner, name, address, reason):
                tracker = harness.tracker()
                seen.append((list(tracker['actions']), tracker['owned'], tracker['repair_due'], harness.saves))
                return super().redhcp(name, address, reason)

        harness = Harness()
        harness.actor = harness.guard.actor = Recording()
        harness.tick()
        harness.tick()
        self.assertEqual(harness.saves, 1)
        # A daemon that dies in the middle leaves a record that repairs the
        # client if it is gone, and forgets the claim once a client is seen.
        self.assertEqual(seen, [([harness.clock.now], True, True, 1)])
        self.assertEqual((harness.tracker()['owned'], harness.tracker()['repair_due']), (True, False))

    def test_a_helper_call_that_raises_counts_as_a_failed_action(self):
        class Raising(Actor):
            def redhcp(inner, name, address, reason):
                inner.calls.append(('redhcp', name, address, reason))
                raise UnicodeDecodeError('utf-8', b'\xff', 0, 1, 'invalid start byte')

        harness = Harness()
        harness.actor = harness.guard.actor = Raising()
        harness.tick()
        harness.tick()
        tracker = harness.tracker()
        self.assertEqual((tracker['stage'], len(tracker['actions']), tracker['next_retry'] - harness.clock.now),
                         (1, 1, 60))
        self.assertEqual((tracker['owned'], tracker['repair_due']), (True, True))
        self.assertEqual(tracker['last_action']['result'], 'failed:helper')
        self.assertEqual(len(harness.log.having('the helper call failed: UnicodeDecodeError')), 1)
        harness.tick(rows=[interface(dhclient_running=False)])
        self.assertEqual(harness.actor.calls[-1], ('restore', 'opt2'))

    def test_refused_and_busy_results_claim_no_client(self):
        for result in ['busy', 'refused:address-changed']:
            with self.subTest(result=result):
                harness = Harness(results=[result])
                harness.tick()
                harness.tick()
                self.assertEqual(len(harness.actions()), 1)
                self.assertEqual((harness.tracker()['owned'], harness.tracker()['repair_due']), (False, False))
                harness.tick(rows=[interface(dhclient_running=False)])
                self.assertEqual([call[0] for call in harness.actor.calls], ['redhcp'])

    def test_a_stopping_daemon_starts_no_action(self):
        harness = Harness()
        harness.guard.stopping = lambda: True
        harness.tick()
        harness.tick()
        harness.tick(manual={'opt2'})
        self.assertEqual(harness.actor.calls, [])
        self.assertEqual(harness.tracker()['last_manual']['result'], 'refused:stopping')
        self.assertEqual(len(harness.log.having('manual retry on opt2 refused: the service is stopping')), 1)

    def test_a_stopping_daemon_leaves_the_repair_to_the_next_start(self):
        harness = Harness(results=['failed:no-client'])
        harness.tick()
        harness.tick()
        stopping = [True]
        harness.guard.stopping = lambda: stopping[0]
        harness.tick(400, rows=[interface(dhclient_running=False)])
        self.assertEqual([call[0] for call in harness.actor.calls], ['redhcp'])
        self.assertTrue(harness.tracker()['owned'] and harness.tracker()['repair_due'])
        stopping[0] = False
        harness.tick(rows=[interface(dhclient_running=False)])
        self.assertEqual(harness.actor.calls[-1], ('restore', 'opt2'))

    def test_display_states(self):
        now = 5000.0
        cases = [((False, True, False, True, guard.UNWANTED, True, True, None), 'disabled'),
                 ((True, False, False, True, guard.UNWANTED, True, True, None), 'stopped'),
                 ((True, True, True, True, guard.UNWANTED, True, True, None), 'booting'),
                 ((True, True, False, False, guard.NONE, True, True, None), 'ignored'),
                 ((True, True, False, True, guard.NONE, True, True, None), 'no_address'),
                 ((True, True, False, True, guard.WANTED, True, True, None), 'ok'),
                 ((True, True, False, True, guard.WANTED, True, False, None), 'ok'),
                 ((True, True, False, True, guard.UNWANTED, False, True, None), 'no_carrier'),
                 ((True, True, False, True, guard.UNWANTED, True, False, None), 'no_client'),
                 ((True, True, False, True, guard.UNWANTED, True, True, {'stage': 0, 'actions': []}), 'confirming'),
                 ((True, True, False, True, guard.UNWANTED, True, True, {'stage': 2, 'actions': [now - 10]}), 'backoff'),
                 ((True, True, False, True, guard.UNWANTED, True, True, {'stage': 5, 'actions': [now - 10] * 8}),
                  'rate_limited')]
        for arguments, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(guard.display_state(*arguments, now), expected)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = os.path.join(self.directory.name, 'db', 'state.json')

    def populated(self):
        harness = Harness(results=['requested'])
        harness.tick(manual={'opt2'})
        return harness.state

    def test_save_is_atomic_private_and_round_trips(self):
        store = guard.Store(self.path, '1:1')
        state = self.populated()
        store.save(state)
        info = os.stat(self.path)
        self.assertEqual(info.st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(os.path.dirname(self.path)).st_mode & 0o777, 0o700)
        self.assertEqual(os.listdir(os.path.dirname(self.path)), ['state.json'])
        loaded, status = store.load()
        self.assertEqual(status, 'loaded')
        self.assertEqual(loaded, json.loads(json.dumps(state)))

    def test_absent_state_is_a_fresh_start_without_cooldown(self):
        state, status = guard.Store(self.path, '1:1').load()
        self.assertEqual(status, 'fresh')
        self.assertIsNone(state['cooldown_until'])

    def test_state_from_another_boot_is_discarded(self):
        guard.Store(self.path, '1:1').save(self.populated())
        state, status = guard.Store(self.path, '2:2').load()
        self.assertEqual(status, 'reboot')
        self.assertEqual(state['interfaces'], {})
        self.assertTrue(os.path.exists(self.path))

    def corrupt(self, prepare):
        store = guard.Store(self.path, '1:1')
        store.save(self.populated())
        prepare()
        with self.assertRaises((ValueError, OSError)):
            store.read()
        self.assertTrue(os.path.lexists(self.path))
        state, status = store.load()
        self.assertTrue(status.startswith('corrupt'), status)
        self.assertEqual(state['interfaces'], {})
        self.assertFalse(os.path.lexists(self.path))
        self.assertTrue(os.path.lexists(self.path + '.bad'))

    def test_a_symlink_is_rejected(self):
        def prepare():
            target = os.path.join(self.directory.name, 'elsewhere.json')
            os.replace(self.path, target)
            os.symlink(target, self.path)
        self.corrupt(prepare)

    def test_a_group_or_world_accessible_file_is_rejected(self):
        self.corrupt(lambda: os.chmod(self.path, 0o644))

    def test_an_oversized_file_is_rejected(self):
        def prepare():
            with open(self.path, 'a') as output:
                output.write(' ' * guard.STATE_MAX)
        self.corrupt(prepare)

    def test_wrong_shapes_are_rejected(self):
        state = self.populated()
        tracker = state['interfaces']['opt2']
        variants = [
            'not json', '[]', json.dumps(dict(state, schema=2)), json.dumps(dict(state, extra=1)),
            json.dumps(dict(state, interfaces={'OPT2': tracker})),
            json.dumps(dict(state, interfaces={'opt2': dict(tracker, streak=True)})),
            json.dumps(dict(state, interfaces={'opt2': dict(tracker, stage=-1)})),
            json.dumps(dict(state, interfaces={'opt2': dict(tracker, actions=['x'])})),
            json.dumps(dict(state, interfaces={'opt2': dict(tracker, actions=[1.0] * 65)})),
            json.dumps(dict(state, interfaces={'opt2': dict(tracker, device='bad device')})),
            json.dumps(dict(state, interfaces={'opt2': dict(tracker, last_action={'nested': {}})})),
            json.dumps(dict(state, interfaces={'opt2': {k: v for k, v in tracker.items() if k != 'owned'}})),
            json.dumps({k: v for k, v in state.items() if k != 'recent'}),
            json.dumps(dict(state, recent={'opt2': ['x']})),
            json.dumps(dict(state, recent={'OPT2': [1.0]})),
            json.dumps(dict(state, recent={'opt2': [1.0] * 65})),
            json.dumps(dict(state, recent=[])),
        ]
        for text in variants:
            with self.subTest(text=text[:60]):
                def prepare(text=text):
                    with open(self.path, 'w') as output:
                        output.write(text)
                self.corrupt(prepare)
                os.unlink(self.path + '.bad')

    def test_state_survives_a_restart_without_an_immediate_action(self):
        harness = Harness()
        harness.tick()
        harness.tick()
        store = guard.Store(self.path, '1:1')
        store.save(harness.state)
        loaded, _ = store.load()
        restarted = Harness()
        restarted.clock.now = harness.clock.now
        restarted.state.update(loaded)
        for _ in range(1):
            restarted.tick()
        self.assertEqual(restarted.actions(), [])
        restarted.tick()
        self.assertEqual(len(restarted.actions()), 1)
        self.assertEqual(restarted.tracker()['stage'], 2)


if __name__ == '__main__':
    unittest.main()
