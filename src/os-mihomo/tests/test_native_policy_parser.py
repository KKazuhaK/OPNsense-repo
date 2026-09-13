"""Keep genuine core log variants from obscuring device-policy assertions."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).parent / 'native/test-device-policy.py'
spec = importlib.util.spec_from_file_location('native_policy_logs', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NativePolicyLogTests(unittest.TestCase):
    def test_both_native_inverted_rule_formats_are_classified_as_device_policy(self):
        case = module.DevicePolicyTests()
        for rule in ['NOT((SrcIPCIDR,192.0.2.77/32))', 'NOT/(!(SrcIPCIDR,192.0.2.77/32))']:
            text = f'[TCP] dial DIRECT (match {rule}) 127.0.0.1:12345 --> 192.0.2.1:80 error: refused'
            parsed = case.rule(text)
            self.assertEqual(rule, parsed)
            self.assertTrue(case.steered(parsed))

    def test_successful_dial_keeps_subscription_rules_distinct_from_source_policy(self):
        case = module.DevicePolicyTests()
        for rule, expected in [('SrcIPCIDR(127.0.0.1/32)', True), ('MATCH', False)]:
            parsed = case.rule(f'[TCP] 127.0.0.1:12345 --> 192.0.2.1:80 match {rule} using Proxy[DIRECT]')
            self.assertEqual(rule, parsed)
            self.assertEqual(expected, case.steered(parsed))

    def test_missing_core_connection_is_a_failure_instead_of_default_rule_match(self):
        with self.assertRaisesRegex(AssertionError, 'no connection reached the core'):
            module.DevicePolicyTests.rule('core startup only')
