#!/usr/bin/env python3
"""Run every package suite, including Python tests in nested native directories."""
import argparse
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

# Native PHP contracts require genuine Core or FreeBSD request-file ownership.
PORTABLE_PHP = {
    'shared': [('tests/native/test-utility-api-contract.php',),
               ('tests/native/test-small-api-contract.php',)],
    'os-staticarp': [('src/os-staticarp/tests/native/test-settings.php',),
                     ('src/os-staticarp/tests/native/test-controller.php',)],
    'os-pftop': [('src/os-pftop/tests/native/test-controller.php',)],
    'os-speedtest': [('src/os-speedtest/tests/native/test-api.php',
                     'src/os-speedtest/src/usr/local/opnsense/mvc/app/controllers/OPNsense/Speedtest/Api')],
    'os-sing-box': [('src/os-sing-box/tests/native/test-api-contract.php',
                    'src/os-sing-box/src/usr/local/opnsense/mvc/app/controllers/OPNsense/SingBox/Api'),
                    ('src/os-sing-box/tests/native/test-routing-context.php',)],
    'os-mihomo': [('src/os-mihomo/tests/native/test-backup-fields.php',),
                  ('src/os-mihomo/tests/native/test-routing-context.php',),
                  ('src/os-mihomo/tests/native/test-tun-rule-ownership.php',)],
    'os-frp': [('src/os-frp/tests/native/test-backup-fields.php',)],
}
NATIVE_PHP = {
    'common': [('src/common/tests/native/test-backup-cas.php',),
               ('src/common/tests/native/test-backup-model.php',)],
    'os-mihomo': [('src/os-mihomo/tests/native/test-integration-lock.php',),
                  ('src/os-mihomo/tests/native/test-service-repair.php',)],
    'os-speedtest': [('src/os-speedtest/tests/native/test-backup-cas.php',)],
    'os-sing-box': [('src/os-sing-box/tests/native/test-config-setup.php',),
                    ('src/os-sing-box/tests/native/test-settings.php',
                     'src/os-sing-box/src/usr/local/opnsense/scripts/singbox/singbox.php')],
    'os-kazuha-repo': [('src/os-kazuha-repo/tests/native/test-manifest-lock.php',)],
}
NATIVE_PYTHON = {
    'shared': ['tests/native/test-utility-upgrade.py'],
    'os-pftop': ['src/os-pftop/tests/native/test-live-snapshot.py'],
}


def suites(packages, python_only=False, native=False, device_policy=False, bandwidth=False, kernel_route=False):
    commands = []
    for package, directory in packages.items():
        files = sorted(directory.rglob('test_*.py'))
        if not files:
            raise ValueError(f'{package} has no Python test suite: {directory}')
        # unittest discovery does not descend into directories without __init__.py.
        for parent in sorted({path.parent for path in files}):
            commands.append((package, [sys.executable, '-B', '-m', 'unittest', 'discover',
                                       '-s', str(parent.relative_to(ROOT)), '-p', 'test_*.py', '-v']))
        if not python_only:
            for arguments in PORTABLE_PHP.get(package, []):
                commands.append((package, ['php', *arguments]))
            if native:
                for arguments in NATIVE_PHP.get(package, []):
                    commands.append((package, ['php', *arguments]))
        if native:
            for script in NATIVE_PYTHON.get(package, []):
                commands.append((package, [sys.executable, '-B', script, '-v']))
        if device_policy and package == 'os-mihomo':
            commands.append((package, [sys.executable, '-B',
                                      'src/os-mihomo/tests/native/test-device-policy.py', '-v']))
        if kernel_route and package == 'os-mihomo':
            commands.append((package, [sys.executable, '-B',
                                      'src/os-mihomo/tests/native/test-native-route.py', '--run']))
        if bandwidth and package == 'os-speedtest':
            commands.append((package, [sys.executable, '-B',
                                      'src/os-speedtest/tests/native/test-live-speedtest.py', '-v']))
    if native and not python_only:
        sources = [str(ROOT / 'src' / name) for name in packages if name.startswith('os-')]
        if sources:
            commands.append(('MVC views', ['php', 'tests/native/check-views.php', *sources]))
    return commands


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', action='append', help='Package directory name; repeat to select several')
    parser.add_argument('--python-only', action='store_true', help='Omit explicit PHP contracts on hosts without PHP')
    parser.add_argument('--native', action='store_true', help='Also run isolated genuine Core/FreeBSD contracts')
    parser.add_argument('--device-policy', action='store_true', help='Also exercise a private loopback Mihomo core')
    parser.add_argument('--bandwidth', action='store_true', help='Also run the real Internet bandwidth test on FreeBSD')
    parser.add_argument('--kernel-route', action='store_true',
                        help='Also clone real kernel routes inside a disposable VNET jail')
    parser.add_argument('--list', action='store_true', help='Print the complete plan without running tests')
    args = parser.parse_args(argv)
    packages = {path.name: path / 'tests' for path in sorted((ROOT / 'src').glob('os-*')) if path.is_dir()}
    packages.update({'common': ROOT / 'src/common/tests', 'shared': ROOT / 'tests'})
    if args.package:
        unknown = set(args.package) - packages.keys()
        if unknown:
            parser.error('Unknown packages: ' + ', '.join(sorted(unknown)))
        packages = {name: directory for name, directory in packages.items() if name in args.package}
    for requested, package in [(args.device_policy, 'os-mihomo'), (args.kernel_route, 'os-mihomo'),
                               (args.bandwidth, 'os-speedtest')]:
        if requested and package not in packages:
            parser.error(f'The requested live test requires selecting {package}')
    try:
        commands = suites(packages, args.python_only, args.native, args.device_policy,
                          args.bandwidth, args.kernel_route)
    except ValueError as error:
        parser.error(str(error))
    if not args.list:
        if not args.python_only and not shutil.which('php'):
            parser.error('PHP is required; install it or use --python-only for a partial local run')
        if args.native and (platform.system() != 'FreeBSD' or
                            not Path('/usr/local/opnsense/mvc/script/load_phalcon.php').is_file()):
            parser.error('--native requires genuine OPNsense on FreeBSD')
        if args.device_policy and not Path('/usr/local/bin/mihomo').is_file():
            parser.error('--device-policy requires an installed Mihomo core')
        if args.bandwidth and platform.system() != 'FreeBSD':
            parser.error('--bandwidth requires native FreeBSD')
        # The fixture rewrites kernel routing state, so a host that owns real
        # traffic must never be its target; only a throwaway VNET qualifies.
        if args.kernel_route and (platform.system() != 'FreeBSD' or subprocess.run(
                ['/sbin/sysctl', '-n', 'security.jail.jailed'], capture_output=True).stdout.strip() != b'1'):
            parser.error('--kernel-route requires a disposable FreeBSD VNET jail, never a router')
    failures = []
    for package, command in commands:
        print(f'[{package}] ' + ' '.join(command), flush=True)
        if not args.list:
            result = subprocess.run(command, cwd=ROOT)
            if result.returncode:
                failures.append((package, command, result.returncode))
    print(f'{len(packages)} package/shared groups; {len(commands)} suite commands', flush=True)
    if failures:
        for package, command, code in failures:
            print(f'FAILED ({code}) [{package}] ' + ' '.join(command), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
