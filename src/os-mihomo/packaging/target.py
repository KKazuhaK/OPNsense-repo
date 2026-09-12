"""Resolve native build targets and reproduce their packaged file contents."""
import argparse
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys

PYTHON_PATH = re.compile(rb'/usr/local/bin/python3(?:\.[0-9]+)?\b')
VERSION_PATH = '/usr/local/opnsense/version/mihomo'


def target_values(abi, product_abi, python, native_freebsd=None, repository=None,
                  profile='explicit'):
    """Validate a target without claiming that its runtime has been tested."""
    match = re.fullmatch(r'FreeBSD:([1-9][0-9]*):amd64', abi or '')
    if not match:
        raise ValueError('Target ABI must be FreeBSD:<major>:amd64.')
    if not re.fullmatch(r'[0-9]{2}\.(?:1|7)', product_abi or ''):
        raise ValueError('Target product ABI must be an OPNsense CE series such as 26.7.')
    if not re.fullmatch(r'3\.[1-9][0-9]*', python or ''):
        raise ValueError('Target Python must be a Python 3 minor version.')
    if native_freebsd is not None and not re.fullmatch(r'[1-9][0-9]*\.[0-9]+', native_freebsd):
        raise ValueError('Native FreeBSD release must contain a major and minor version.')
    major = match.group(1)
    if native_freebsd is not None and native_freebsd.split('.')[0] != major:
        raise ValueError('Native FreeBSD release differs from the target ABI.')
    repository = repository or 'repo/' + abi + '/' + product_abi
    parts = PurePosixPath(repository).parts
    if (parts not in [('repo', abi), ('repo', abi, product_abi)] or
            str(PurePosixPath(repository)) != repository):
        raise ValueError('Target repository must belong to its ABI and product series.')
    suffix = python.replace('.', '')
    return {'abi': abi, 'arch': 'freebsd:' + major + ':x86:64',
            'product_abi': product_abi, 'python': python,
            'python_package': 'python' + suffix, 'pyyaml_package': 'py' + suffix + '-pyyaml',
            'native_freebsd': native_freebsd, 'repository': repository, 'profile': profile}


def recipes(project):
    value = json.loads((Path(project) / 'packaging/targets.json').read_text())
    if value.get('schema_version') != 1 or value.get('default') not in value.get('targets', {}):
        raise ValueError('Invalid committed target recipes.')
    return value


def enabled_targets(project):
    """Only complete, explicitly enabled recipes enter the publishing matrix."""
    value = recipes(project)
    result = []
    for profile, item in value['targets'].items():
        if item.get('enabled') is True:
            if not item.get('native_freebsd') or not item.get('repository'):
                raise ValueError('An enabled target has no native release or repository.')
            if not re.fullmatch(r'8\.[0-9]+', item.get('php') or ''):
                raise ValueError('An enabled target has no supported PHP version.')
            target = target_values(item.get('abi'), item.get('product_abi'), item.get('python'),
                                   item['native_freebsd'], item['repository'], profile)
            target['php'] = item['php']
            expected_repository = 'https://pkg.opnsense.org/' + target['abi'] + '/' + target['product_abi'] + '/latest'
            if item.get('dependency_repository') != expected_repository:
                raise ValueError('An enabled target has no matching official dependency repository.')
            fingerprint = item.get('dependency_fingerprint') or ''
            if not re.fullmatch(r'packaging/OPNsense/trusted/pkg\.opnsense\.org\.[0-9]{8}', fingerprint):
                raise ValueError('An enabled target has no committed official dependency fingerprint.')
            target['dependency_repository'] = expected_repository
            target['dependency_fingerprint'] = fingerprint
            result.append(target)
    if not result:
        raise ValueError('No complete build targets are enabled.')
    for target in result:
        fingerprint_file = Path(project) / target['dependency_fingerprint']
        if (not fingerprint_file.is_file() or fingerprint_file.is_symlink() or
                not re.fullmatch(r'function: "sha256"\nfingerprint: "[0-9a-f]{64}"\n?', fingerprint_file.read_text())):
            raise ValueError('An enabled target has an invalid official dependency fingerprint.')
    return result


def resolve_target(project, environment=None):
    environment = os.environ if environment is None else environment
    value = recipes(project)
    profile = environment.get('TARGET_PROFILE') or value['default']
    item = value['targets'].get(profile)
    if not item or item.get('enabled') is not True:
        raise ValueError('Target profile is not ready for building: ' + profile)
    configured = target_values(item.get('abi'), item.get('product_abi'), item.get('python'),
                               item.get('native_freebsd'), item.get('repository'), profile)
    abi = environment.get('TARGET_ABI') or environment.get('ABI') or configured['abi']
    product_abi = environment.get('TARGET_PRODUCT_ABI') or configured['product_abi']
    python = environment.get('TARGET_PYTHON') or configured['python']
    if (abi, product_abi, python) == (configured['abi'], configured['product_abi'], configured['python']):
        return configured
    if abi != configured['abi'] and not environment.get('TARGET_PRODUCT_ABI'):
        raise ValueError('A different target ABI requires an explicit TARGET_PRODUCT_ABI.')
    return target_values(abi, product_abi, python)


def product_metadata(project, target, version):
    if not re.fullmatch(r'[0-9][0-9A-Za-z._,+]*', version):
        raise ValueError('Invalid package version.')
    value = json.loads((Path(project) / 'src' / VERSION_PATH.lstrip('/')).read_text())
    value.update(product_abi=target['product_abi'], product_arch='amd64', product_version=version)
    if value.get('product_id') != 'os-mihomo':
        raise ValueError('Incorrect plugin product metadata.')
    return value


def transform_content(content, target):
    """Pin runtime entry points and child processes to the declared interpreter."""
    if b'/usr/local/bin/python3' not in content:
        return content
    try:
        content.decode('utf-8')
    except UnicodeDecodeError:
        return content
    return PYTHON_PATH.sub(('/usr/local/bin/python' + target['python']).encode(), content)


def transform_hook(project, phase, target):
    phase = '+' + phase.upper().replace('-', '_').lstrip('+')
    return transform_content((Path(project) / 'packaging/freebsd' / phase).read_bytes(), target).decode()


def staged_files(project, target, version):
    project = Path(project)
    source = project / 'src'
    result = {}
    for path in sorted(source.rglob('*')):
        parts = path.relative_to(source).parts
        if (path.is_file() and path.suffix not in {'.xz', '.pyc', '.pyo'} and
                '__pycache__' not in parts and not any(p == '.DS_Store' or p.startswith('._') for p in parts)):
            result['/' + str(path.relative_to(source))] = transform_content(path.read_bytes(), target)
    result['/usr/local/bin/mihomo'] = lzma.decompress(
        (source / 'usr/local/bin/clash-meta-freebsd-amd64.xz').read_bytes())
    result[VERSION_PATH] = (json.dumps(product_metadata(project, target, version), sort_keys=True,
                                       separators=(',', ':')) + '\n').encode()
    return result


def command(arguments):
    return subprocess.check_output(arguments, text=True).strip()


def check_build(project):
    target = resolve_target(project)
    actual_python = '.'.join(map(str, sys.version_info[:2]))
    if actual_python != target['python']:
        raise ValueError('The build interpreter must be Python ' + target['python'] + ', matching ' + target['python_package'])
    if command(['uname', '-s']) != 'FreeBSD' or command(['uname', '-m']) != 'amd64':
        raise ValueError('Build on native FreeBSD amd64.')
    release = command(['freebsd-version', '-u'])
    match = re.match(r'([1-9][0-9]*)\.([0-9]+)(?:-|$)', release)
    if not match:
        raise ValueError('Cannot determine the native FreeBSD userland release.')
    native_release = '.'.join(match.groups())
    native_abi = 'FreeBSD:' + match.group(1) + ':amd64'
    kernel_version = command(['uname', '-K'])
    if not kernel_version.isdigit() or int(kernel_version) // 100000 != int(match.group(1)):
        raise ValueError('Build kernel and userland must match the native target ABI.')
    if native_abi != target['abi'] or command(['pkg', 'config', 'ABI']) != native_abi:
        raise ValueError('Target, native FreeBSD and pkg ABI must match; relabeling a foreign ABI is not supported.')
    if target['native_freebsd'] and target['native_freebsd'] != native_release:
        raise ValueError('Native FreeBSD release differs from the committed target recipe.')
    native_product_abi = None
    if shutil.which('opnsense-version'):
        native_product_abi = command(['opnsense-version', '-x'])
        if native_product_abi != target['product_abi']:
            raise ValueError('Native OPNsense product ABI differs from the target product ABI.')
    dependencies = {}
    origins = {'curl': 'ftp/curl', target['python_package']: 'lang/' + target['python_package'],
               target['pyyaml_package']: 'devel/py-pyyaml'}
    for name, origin in origins.items():
        fields = command(['pkg', 'query', '%o %v %q', name]).split()
        if len(fields) != 3 or fields[0] != origin or fields[2] not in {native_abi, 'FreeBSD:*:amd64', 'FreeBSD:*:*'}:
            raise ValueError('Missing or incompatible native build dependency: ' + name)
        dependencies[name] = {'origin': fields[0], 'version': fields[1]}
    python_version = dependencies[target['python_package']]['version'].split('_', 1)[0].split(',', 1)[0]
    if python_version != '.'.join(map(str, sys.version_info[:3])):
        raise ValueError('The build interpreter version differs from the ' + target['python_package'] + ' package dependency')
    try:
        import yaml
    except ImportError as error:
        raise ValueError('Native PyYAML for Python ' + target['python'] + ' is required.') from error
    yaml_version = dependencies[target['pyyaml_package']]['version'].split('_', 1)[0].split(',', 1)[0]
    if yaml.__version__ != yaml_version:
        raise ValueError('Imported PyYAML differs from the native package dependency.')
    return {'target': target, 'deps': dependencies, 'native_abi': native_abi, 'native_release': release,
            'native_product_abi': native_product_abi}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix', action='store_true')
    parser.add_argument('--check-build', action='store_true')
    parser.add_argument('project', nargs='?', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        value = {'include': enabled_targets(args.project)} if args.matrix else check_build(args.project) if args.check_build else resolve_target(args.project)
        print(json.dumps(value, sort_keys=True))
    except (ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, 'error: ' + str(error) + '\n')
