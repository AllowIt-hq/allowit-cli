#!/usr/bin/env python3
"""Bind the SDK facade and every first-party vendor to immutable Cargo inputs."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import parse_qs, urlsplit

# The caller supplies the legacy verifier's audited Git/blob helpers.
SCHEMA = 2
CANONICAL = {
    'https://github.com/AllowIt-hq/allowit-sdk.git',
    'https://github.com/AllowIt-hq/allowit-contracts-tempo.git',
    'https://github.com/AllowIt-hq/allowit-contracts-solana.git',
}
PACKAGES = {
    'allowit-client': ('https://github.com/AllowIt-hq/allowit-sdk.git', 'client'),
    'allowit-client-core': ('https://github.com/AllowIt-hq/allowit-sdk.git', 'client-core'),
    'allowit-sdk': ('https://github.com/AllowIt-hq/allowit-sdk.git', ''),
    'allowit-native': ('https://github.com/AllowIt-hq/allowit-sdk.git', 'native-rust'),
    'allowit-stellar-wallet': ('https://github.com/AllowIt-hq/allowit-sdk.git', 'stellar-rust'),
    'allowit-tempo': ('https://github.com/AllowIt-hq/allowit-contracts-tempo.git', 'rust'),
    'allowit-solana-vendor': ('https://github.com/AllowIt-hq/allowit-contracts-solana.git', 'crates/solana-vendor'),
}
LICENSES = ('LICENSE', 'THIRD_PARTY_NOTICES.md', 'licenses/Aeneas-Apache-2.0.txt')


def metadata(root, *config):
    args = ['cargo', 'metadata', '--locked', '--format-version', '1']
    for value in config:
        args += ['--config', value]
    process = subprocess.run(args, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process.returncode:
        raise ValueError('Cargo could not resolve the locked dependency graph')
    return json.loads(process.stdout)


def source_identity(source):
    if not isinstance(source, str) or not source.startswith('git+'):
        raise ValueError('Vendor source must be an exact canonical Git dependency')
    parsed = urlsplit(source[4:])
    repository = f'{parsed.scheme}://{parsed.netloc}{parsed.path}'
    query = parse_qs(parsed.query, strict_parsing=True)
    if (repository not in CANONICAL or set(query) != {'rev'}
            or query['rev'] != [parsed.fragment]
            or not re.fullmatch(r'[0-9a-f]{40}', parsed.fragment)):
        raise ValueError('Vendor source must pin a full canonical Git revision')
    return repository, parsed.fragment


def regular(root, relative):
    current = root
    for part in Path(relative).parts:
        current /= part
        if current.is_symlink():
            raise ValueError('Vendor input path must not contain symlinks')
    return current


def package_sources(helper, repo, commit, directory):
    """Bind every source/test input, manifest and package-local discovery file."""
    crate = regular(repo, directory) if directory else repo
    if not crate.is_dir():
        raise ValueError('Vendor package directory is missing')
    if directory:
        paths = [directory]
    else:
        # The core policy package shares a repository with independently bound packages.
        paths = ['Cargo.toml', 'Cargo.lock', '.cargo', 'src', 'tests', 'examples', 'templates', 'benches']
    raw = helper.pinned(repo, commit, *paths)
    blobs = {name[len(directory) + 1:] if directory else name: data for name, data in raw.items()}
    if not {'Cargo.toml', 'src/lib.rs'}.issubset(blobs):
        raise ValueError('Vendor package source is incomplete')
    if 'build.rs' in blobs or os.path.lexists(crate / 'build.rs'):
        raise ValueError('Vendor package must not have a build script')
    present = set()
    if directory:
        present = helper.inventory(crate)
    else:
        for name in paths:
            candidate = regular(repo, name)
            if candidate.is_dir():
                present.update(name + '/' + item for item in helper.inventory(candidate))
            elif candidate.is_file():
                present.add(name)
            elif os.path.lexists(candidate):
                raise ValueError('Vendor input must be a regular file')
    if present != set(blobs):
        raise ValueError('Vendor source file set differs from its pinned commit')
    helper.unchanged(crate, blobs, 'Vendor', 'its pinned commit')
    return {name: helper.digest(data) for name, data in sorted(blobs.items())}


def discovery_sources(helper, repo, commit, directory):
    """Cargo sees config in each ancestor between a package and its repository."""
    directories = ['']
    if directory:
        parts = Path(directory).parts
        directories += [Path(*parts[:i]).as_posix() for i in range(1, len(parts))]
    paths = [str(Path(directory, name)) for directory in directories for name in helper.DISCOVERY]
    helper.discovery(repo, commit, paths, 'Vendor', 'its pinned commit')
    return {name: helper.digest(data) for name, data in sorted(helper.pinned(repo, commit, *paths).items())}


def git_checkout(helper, package, sdk, sdk_commit):
    name = package['name']
    repository, directory = PACKAGES[name]
    manifest = Path(package['manifest_path'])
    if package.get('source') is None:
        if repository != helper.URL or name == 'allowit-client-core':
            raise ValueError('Cargo resolves an unexpected local vendor package')
        repo, commit = sdk, sdk_commit
    else:
        actual_repository, commit = source_identity(package['source'])
        if actual_repository != repository:
            raise ValueError('Cargo resolves vendor from a foreign repository')
        top = helper.git(manifest.parent, 'rev-parse', '--show-toplevel').strip()
        repo = Path(top)
        if helper.git(repo, 'rev-parse', 'HEAD').strip() != commit:
            raise ValueError('Cargo vendor checkout differs from its exact Git source')
    crate = regular(repo, directory) if directory else repo
    libraries = [target for target in package['targets'] if {'lib', 'rlib'} & set(target['kind'])]
    if (manifest != crate / 'Cargo.toml' or manifest.is_symlink()
            or len(libraries) != 1 or Path(libraries[0]['src_path']) != crate / 'src/lib.rs'
            or any('custom-build' in target['kind'] for target in package['targets'])
            or package.get('links') is not None):
        raise ValueError('Cargo does not build ' + name + ' from its pinned vendor source')
    status = helper.git(repo, 'status', '--porcelain', '--untracked-files=all').splitlines()
    # Cargo writes an untracked completion marker outside the package inputs.
    marker = repo / '.cargo-ok'
    if '?? .cargo-ok' in status and marker.is_file() and not marker.is_symlink():
        status.remove('?? .cargo-ok')
    if status:
        raise ValueError('Vendor checkout must be clean')
    return repo, commit, directory


def graph(root, helper, *config):
    root = Path(root).resolve()
    sdk = helper.checkout(root)
    sdk_commit = helper.git(sdk, 'rev-parse', 'HEAD').strip()
    value = metadata(root, *config)
    packages = [package for package in value['packages']
                if package.get('source') is None or package['name'].startswith('allowit-')
                or str(package.get('source', '')).startswith('git+')]
    cli = [package for package in packages if package['name'] == 'allowit-cli']
    vendors = [package for package in packages if package['name'] != 'allowit-cli']
    if (len(cli) != 1 or cli[0].get('source') is not None
            or Path(cli[0]['manifest_path']) != root / 'Cargo.toml'
            or len(vendors) != len(PACKAGES) or {p['name'] for p in vendors} != set(PACKAGES)):
        raise ValueError('Cargo resolves unexpected first-party packages')
    nodes = {node['id']: node for node in value['resolve']['nodes']}
    direct = {dep['name'] for dep in nodes[cli[0]['id']]['deps']}
    # Cargo dev-dependencies are part of the development lock but cannot add a vendor path.
    runtime = [dep for dep in nodes[cli[0]['id']]['deps']
               if any(kind['kind'] is None for kind in dep['dep_kinds'])]
    if [dep['name'] for dep in runtime] != ['allowit_client'] or not direct:
        raise ValueError('CLI runtime must depend only on the SDK client facade')
    identities = {p['id']: p['name'] for p in packages}
    for package in vendors:
        dependencies = {identities[dep['pkg']] for dep in nodes[package['id']]['deps'] if dep['pkg'] in identities}
        if package['name'] != 'allowit-client' and 'allowit-client' in dependencies:
            raise ValueError('Vendor and core packages must not depend on the facade')
        if package['name'] in {'allowit-sdk', 'allowit-client-core'} and dependencies:
            raise ValueError('Core packages must not depend on vendor packages')
    result = []
    for package in sorted(vendors, key=lambda p: p['name']):
        name = package['name']
        repo, commit, directory = git_checkout(helper, package, sdk, sdk_commit)
        legal = helper.pinned(repo, commit, *LICENSES)
        if 'LICENSE' not in legal:
            raise ValueError('Vendor license is missing')
        helper.unchanged(repo, legal, 'Vendor license', 'its pinned commit')
        result.append({
            'package': name, 'version': package['version'],
            'repository': PACKAGES[name][0][:-4], 'commit': commit, 'path': directory,
            'source': package.get('source'), 'features': sorted(nodes[package['id']]['features']),
            'dependencies': sorted(identities[dep['pkg']] for dep in nodes[package['id']]['deps'] if dep['pkg'] in identities),
            'files': package_sources(helper, repo, commit, directory),
            'discovery': discovery_sources(helper, repo, commit, directory),
            'licenses': {name: helper.digest(data) for name, data in sorted(legal.items())},
        })
    return result


def describe(root, helper):
    if os.environ.get('ALLOWIT_TEMPO_REVIEW_MANIFEST'):
        raise ValueError('Tempo worktree review cannot produce release provenance or packaging')
    root = Path(root).resolve()
    sdk = helper.checkout(root)
    commit = helper.git(sdk, 'rev-parse', 'HEAD').strip()
    helper.parent(root, *helper.INTERMEDIATE)
    return {'schemaVersion': SCHEMA, 'repository': helper.REPOSITORY, 'commit': commit,
            'submodule': {'path': helper.SUBMODULE, 'url': helper.URL}, 'packages': graph(root, helper)}


def verify(root, helper, *config):
    root = Path(root).resolve()
    recorded = json.loads((root / helper.METADATA).read_text())
    expected = describe(root, helper)
    if helper.git(root, 'ls-files', '--stage', '-z', '--', helper.SUBMODULE).split('\0') != [f'160000 {recorded["commit"]} 0\t{helper.SUBMODULE}', '']:
        raise ValueError('Parent Git index must pin the SDK submodule at its recorded commit')
    modules = helper.command(root, 'config', '--file', '.gitmodules', '--get-regexp', r'^submodule\.', capture_output=True, text=True).stdout.split('\n')
    if sorted(filter(None, modules)) != [f'submodule.{helper.SUBMODULE}.path {helper.SUBMODULE}', f'submodule.{helper.SUBMODULE}.url {helper.URL}']:
        raise ValueError('.gitmodules must name only the canonical SDK submodule')
    if config:
        expected['packages'] = graph(root, helper, *config)
    if recorded != expected:
        raise ValueError('SDK vendor graph differs from its recorded immutable inputs or features')
    return recorded


def resolved(root, helper, *config):
    return verify(root, helper, *config)


def source_roots(root, helper):
    """Verified package repositories for notice packaging, never serialized host paths."""
    verify(root, helper)
    sdk = helper.checkout(Path(root))
    commit = helper.git(sdk, 'rev-parse', 'HEAD').strip()
    return {p['name']: git_checkout(helper, p, sdk, commit)[0]
            for p in metadata(root)['packages'] if p['name'] in PACKAGES}
