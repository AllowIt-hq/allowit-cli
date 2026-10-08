#!/usr/bin/env python3
"""Pin, update and verify the native Rust SDK Git submodule; no credentials.

Builds, provenance and license packaging share `verify`. `update` checks out an
exact SDK commit; `pin` records the checked-out commit. Both stage the gitlink
and metadata for review; neither commits.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess

SUBMODULE = 'repos/AllowIt-hq--allowit-sdk'
CRATE = 'native-rust'
URL = 'https://github.com/AllowIt-hq/allowit-sdk.git'
REPOSITORY = URL[:-len('.git')]
DEPENDENCY = f'allowit-native = {{ path = "{SUBMODULE}/{CRATE}" }}'
METADATA = 'vendor/native-sdk.json'
LICENSES = ('LICENSE', 'THIRD_PARTY_NOTICES.md', 'licenses/Aeneas-Apache-2.0.txt')
REQUIRED = {'Cargo.toml', 'Cargo.lock', 'src/lib.rs', 'src/release.json'}
COPIES = ('vendor/allowit-native', 'vendor/native-sdk-licenses')


def environment():
    """Inherited GIT_* variables (GIT_DIR, GIT_INDEX_FILE, ...) could redirect Git
    to another repository, index or object store; replace refs could swap objects."""
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env['GIT_NO_REPLACE_OBJECTS'] = '1'
    return env


def command(repo, *args, **options):
    return subprocess.run(['git', '-C', str(repo), *args], env=environment(), **options)


def git(repo, *args):
    return command(repo, *args, stdout=subprocess.PIPE, check=True, text=True).stdout


def listed(repo, *paths):
    return [name for name in git(repo, 'ls-files', '-z', '--', *paths).split('\0') if name]


def pinned(repo, commit, *paths):
    """Bytes of the regular-file blobs under PATHS in COMMIT's tree.

    Read from Git's object store, not the index or checkout, which
    assume-unchanged, skip-worktree or filters can make disagree with the commit.
    """
    blobs = {}
    for entry in filter(None, git(repo, 'ls-tree', '-r', '-z', '--full-tree', commit, '--', *paths).split('\0')):
        info, name = entry.split('\t', 1)
        mode, kind, obj = info.split()
        if not any(name == path or name.startswith(path + '/') for path in paths):
            continue
        if kind != 'blob' or mode not in ('100644', '100755'):
            raise ValueError('SDK source must contain only regular files')
        blobs[name] = command(repo, 'cat-file', 'blob', obj, stdout=subprocess.PIPE, check=True).stdout
    return blobs


def crate_blobs(sdk, commit):
    return {name[len(CRATE) + 1:]: data for name, data in pinned(sdk, commit, CRATE).items()}


def digest(data):
    """Hash canonical text: a clean core.autocrlf checkout's CRLF counts as LF.

    Every other byte is hashed, so content changed by an edit or a local Git
    filter still differs from the pin. Like Git, a NUL in the first 8000 bytes
    marks a binary file, which is hashed raw.
    """
    if b'\0' not in data[:8000]:
        data = data.replace(b'\r\n', b'\n')
    return hashlib.sha256(data).hexdigest()


def sha256(path):
    return digest(path.read_bytes())


def unchanged(directory, blobs):
    """Refuse checkout bytes that differ from the commit's blobs, even when Git status hides it."""
    for name, data in blobs.items():
        path = directory / name
        if path.is_symlink() or not path.is_file() or sha256(path) != digest(data):
            raise ValueError('SDK checkout differs from its pinned commit: ' + name)


def consumed(name):
    """Whether Cargo builds or tests the CLI dependency from this crate file."""
    if name in {'Cargo.toml', 'Cargo.lock', 'LICENSE', 'LICENSE.md'} or name.startswith('src/'):
        return True
    if name.startswith('tests/'):
        # Reference-authoring JS is SDK tooling, not a Rust dependency input.
        return PurePosixPath(name).suffix in {'.rs', '.json'}
    raise ValueError('Unexpected SDK crate file: ' + name)


def inventory(crate):
    """Every file Cargo could see, including untracked and ignored files."""
    names = set()
    for directory, subdirs, files in os.walk(crate):
        for name in subdirs + files:
            path = Path(directory, name)
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise ValueError('SDK source must contain only regular files')
        names.update(Path(directory, name).relative_to(crate).as_posix() for name in files)
    return names


def checkout(root):
    """Return the initialized submodule worktree, never the parent repository."""
    sdk = root / SUBMODULE
    top = command(sdk, 'rev-parse', '--show-toplevel', capture_output=True, text=True) if sdk.is_dir() else None
    if not top or top.returncode or Path(top.stdout.strip()).resolve() != sdk.resolve():
        raise ValueError('SDK submodule is not initialized; run git submodule update --init --recursive')
    if git(sdk, 'status', '--porcelain', '--untracked-files=all'):
        raise ValueError('SDK submodule must be clean')
    return sdk


def verify(root):
    """Check the parent pin, clean submodule source and license bytes; return the metadata."""
    root = Path(root).resolve()
    sdk = json.loads((root / METADATA).read_text())
    commit = sdk.get('commit')
    if not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('SDK pin must be a full commit')
    if sdk.get('repository') != REPOSITORY or sdk.get('crate') != CRATE or sdk.get('submodule') != {'path': SUBMODULE, 'url': URL}:
        raise ValueError('SDK metadata must name the canonical submodule')
    module = command(root, 'config', '--file', '.gitmodules', '--get-regexp', r'^submodule\.', capture_output=True, text=True).stdout.split('\n')
    if sorted(filter(None, module)) != [f'submodule.{SUBMODULE}.path {SUBMODULE}', f'submodule.{SUBMODULE}.url {URL}']:
        raise ValueError('.gitmodules must name only the canonical SDK submodule')
    if DEPENDENCY not in (root / 'Cargo.toml').read_text().splitlines():
        raise ValueError('Cargo must build the SDK from its submodule')
    if listed(root, *COPIES):
        raise ValueError('Tracked SDK source copies must be removed')
    if git(root, 'ls-files', '--stage', '-z', '--', SUBMODULE).split('\0') != [f'160000 {commit} 0\t{SUBMODULE}', '']:
        raise ValueError('Parent Git index must pin the SDK submodule at its recorded commit')
    sdk_root = checkout(root)
    if git(sdk_root, 'rev-parse', 'HEAD').strip() != commit:
        raise ValueError('SDK submodule HEAD differs from its pin')

    files, unconsumed = sdk.get('files'), sdk.get('unconsumed', [])
    if not isinstance(files, dict) or not isinstance(unconsumed, list) or not REQUIRED.issubset(files):
        raise ValueError('SDK source file set differs from its pin')
    for name in [*files, *unconsumed]:
        relative = PurePosixPath(name) if isinstance(name, str) else None
        if not relative or relative.is_absolute() or '..' in relative.parts or consumed(name) != (name in files):
            raise ValueError('Invalid SDK source path')
    # Metadata and checkout are each bound to the pinned commit's tree and blobs.
    expected = set(files) | set(unconsumed)
    crate = sdk_root / CRATE
    source = crate_blobs(sdk_root, commit)
    tracked = {name[len(CRATE) + 1:] for name in listed(sdk_root, CRATE)}
    if len(expected) != len(files) + len(unconsumed) or set(source) != expected or tracked != expected or inventory(crate) != expected:
        raise ValueError('SDK source file set differs from its pin')
    for name, value in files.items():
        if digest(source[name]) != value:
            raise ValueError('SDK source differs from its pin: ' + name)
    unchanged(crate, source)

    licenses = sdk.get('licenses')
    if not isinstance(licenses, dict) or 'LICENSE' not in licenses:
        raise ValueError('Pinned SDK license is missing')
    if any(name not in LICENSES for name in licenses):
        raise ValueError('SDK license path is invalid')
    legal = pinned(sdk_root, commit, *LICENSES)
    if set(licenses) != set(legal) or set(licenses) != set(listed(sdk_root, *LICENSES)):
        raise ValueError('SDK license set differs from its pin')
    for name, value in licenses.items():
        if digest(legal[name]) != value:
            raise ValueError('SDK license notice is missing or changed')
    unchanged(sdk_root, legal)
    return sdk


def describe(root):
    """Metadata for the checked-out submodule commit, hashed from its Git blobs.

    The checkout Cargo reads must hold those same bytes, so a change hidden from
    git status (assume-unchanged, skip-worktree) is never recorded under the
    commit's clean gitlink.
    """
    sdk = checkout(root)
    commit = git(sdk, 'rev-parse', 'HEAD').strip()
    crate = sdk / CRATE
    source = crate_blobs(sdk, commit)
    tracked = sorted(source)
    if set(tracked) != inventory(crate) or set(tracked) != {name[len(CRATE) + 1:] for name in listed(sdk, CRATE)}:
        raise ValueError('SDK source file set differs from its commit')
    if not REQUIRED.issubset(tracked):
        raise ValueError('Native Rust SDK source missing')
    legal = pinned(sdk, commit, *LICENSES)
    if set(legal) != set(listed(sdk, *LICENSES)):
        raise ValueError('SDK license set differs from its commit')
    unchanged(crate, source)
    unchanged(sdk, legal)
    return {
        'repository': REPOSITORY,
        'commit': commit,
        'crate': CRATE,
        'submodule': {'path': SUBMODULE, 'url': URL},
        'files': {name: digest(source[name]) for name in tracked if consumed(name)},
        'unconsumed': [name for name in tracked if not consumed(name)],
        'licenses': {name: digest(legal[name]) for name in LICENSES if name in legal},
    }


def pin(root):
    (root / METADATA).write_text(json.dumps(describe(root), indent=2) + '\n')
    git(root, 'add', '--', SUBMODULE, METADATA)
    return verify(root)


def update(root, revision):
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('Revision must be a full exact commit SHA')
    sdk = checkout(root)
    present = command(sdk, 'cat-file', '-e', revision + '^{commit}', capture_output=True)
    if present.returncode:
        git(sdk, 'fetch', '--quiet', 'origin', revision)
    git(sdk, 'checkout', '--quiet', '--detach', revision)
    return pin(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('verify', help='check the pinned, clean SDK submodule (default for builds)')
    commands.add_parser('pin', help='record and stage the checked-out SDK submodule commit')
    commands.add_parser('update', help='check out, record and stage an exact SDK commit').add_argument('revision')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        sdk = update(root, args.revision) if args.command == 'update' else pin(root) if args.command == 'pin' else verify(root)
    except ValueError as error:
        parser.exit(1, f'{error}\n')
    verb = 'Verified' if args.command == 'verify' else 'Staged'
    print(f'{verb} native Rust SDK submodule {SUBMODULE} at {sdk["commit"]}')


if __name__ == '__main__':
    main()
