"""Run the full queue contract with the genuine FreeBSD detached daemon."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_queue_contract


@unittest.skipUnless(sys.platform.startswith('freebsd'), 'requires native FreeBSD daemon and PHP')
class NativeQueueContractTests(test_queue_contract.QueueContractTests):
    native_daemon = True


if __name__ == '__main__':
    unittest.main()
