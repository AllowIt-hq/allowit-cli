#!/usr/bin/env python3
"""Pin, update and verify the canonical SDK Git submodule; no credentials.

One gitlink supplies four Cargo path dependencies: the native Rust crate, its
PaySH interface crate, the root policy SDK crate with canonical typed workflow
types and the Tempo execution verifier.

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
# Root policy crate: no compiler, oracle ledger or binary; only `std` and the
# host `typed-workflow` evaluator (which the compiler would otherwise imply).
POLICY_PACKAGE = 'allowit-sdk'
POLICY_FEATURES = ['std', 'typed-workflow']
POLICY_DEPENDENCY = (f'allowit-policy-sdk = {{ package = "{POLICY_PACKAGE}", path = "{SUBMODULE}", '
                     f'default-features = false, features = {json.dumps(POLICY_FEATURES)} }}')
TEMPO_CRATE = 'tempo-rust'
TEMPO_PACKAGE = 'allowit-tempo'
TEMPO_DEPENDENCY = f'{TEMPO_PACKAGE} = {{ path = "{SUBMODULE}/{TEMPO_CRATE}" }}'
TEMPO_REVIEW_PIN = '7431732a2d3c35eb6b124e761b9cac1e7a4630e9'
INTERFACE = 'crates/paysh-interface'
METADATA = 'vendor/native-sdk.json'
LICENSES = ('LICENSE', 'THIRD_PARTY_NOTICES.md', 'licenses/Aeneas-Apache-2.0.txt')
REQUIRED = {'Cargo.toml', 'Cargo.lock', 'src/lib.rs', 'src/release.json'}
COPIES = ('vendor/allowit-native', 'vendor/crates', 'vendor/native-sdk-licenses')
# Inputs Cargo discovers in each directory above a crate: workspace manifest, lockfile, config.
DISCOVERY = ('Cargo.toml', 'Cargo.lock', '.cargo')
# CLI-owned directories between the CLI root and the SDK root, e.g. repos.
INTERMEDIATE = tuple(path.as_posix() for path in reversed(PurePosixPath(SUBMODULE).parents) if path.parts)


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


def crate_blobs(sdk, commit, crate=CRATE):
    return {name[len(crate) + 1:]: data for name, data in pinned(sdk, commit, crate).items()}


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


def unchanged(directory, blobs, owner='SDK', against='its pinned commit'):
    """Refuse checkout bytes that differ from the commit's blobs, even when Git status hides it."""
    for name, data in blobs.items():
        path = directory / name
        if path.is_symlink() or not path.is_file() or sha256(path) != digest(data):
            raise ValueError(f'{owner} checkout differs from {against}: {name}')


def consumed(name):
    """Whether Cargo builds or tests the CLI dependency from this crate file."""
    if name in {'Cargo.toml', 'Cargo.lock', 'LICENSE', 'LICENSE.md'} or name.startswith('src/'):
        return True
    if name.startswith('tests/'):
        # Reference-authoring JS is SDK tooling, not a Rust dependency input.
        return PurePosixPath(name).suffix in {'.rs', '.json'}
    raise ValueError('Unexpected SDK crate file: ' + name)


def interface_consumed(name):
    """The PaySH interface crate has no tooling; every file is a build or lock input."""
    if name in {'Cargo.toml', 'Cargo.lock'} or name.startswith('src/'):
        return True
    raise ValueError('Unexpected SDK PaySH interface file: ' + name)


def policy_sources(sdk, commit):
    """Root policy crate inputs: its manifest and `src/`, bound to COMMIT's blobs.

    The root also holds other packages and documentation that Cargo does not
    build for this library. A root build script would run, so none may exist.
    """
    if pinned(sdk, commit, 'build.rs') or os.path.lexists(sdk / 'build.rs'):
        raise ValueError('SDK policy crate must not have a build script')
    blobs = pinned(sdk, commit, 'Cargo.toml', 'src')
    present = {'src/' + name for name in inventory(sdk / 'src')} if (sdk / 'src').is_dir() and not (sdk / 'src').is_symlink() else set()
    if (sdk / 'Cargo.toml').is_file() and not (sdk / 'Cargo.toml').is_symlink():
        present.add('Cargo.toml')
    if not {'Cargo.toml', 'src/lib.rs', 'src/typed_workflow.rs'}.issubset(blobs) or present != set(blobs) or set(listed(sdk, 'Cargo.toml', 'src')) != set(blobs):
        raise ValueError('SDK policy crate file set differs from its pinned commit')
    unchanged(sdk, blobs)
    return blobs


def interface_sources(sdk, commit):
    blobs = crate_blobs(sdk, commit, INTERFACE)
    tracked = {name[len(INTERFACE) + 1:] for name in listed(sdk, INTERFACE)}
    if not {'Cargo.toml', 'src/lib.rs'}.issubset(blobs) or set(blobs) != tracked or inventory(sdk / INTERFACE) != tracked:
        raise ValueError('SDK PaySH interface file set differs from its pinned commit')
    for name in blobs:
        interface_consumed(name)
    unchanged(sdk / INTERFACE, blobs)
    return blobs


def tempo_sources(sdk, commit):
    """The complete published Tempo crate, bound to regular immutable Git blobs.

    Keep Cargo discovery closed inside this independent crate: no build script,
    nested Cargo config, symlink or unrecorded input can alter a release build.
    """
    crate = sdk / TEMPO_CRATE
    if crate.is_symlink() or not crate.is_dir():
        raise ValueError('SDK Tempo crate must be a real directory')
    if pinned(sdk, commit, TEMPO_CRATE + '/build.rs') or os.path.lexists(crate / 'build.rs'):
        raise ValueError('SDK Tempo crate must not have a build script')
    blobs = crate_blobs(sdk, commit, TEMPO_CRATE)
    tracked = {name[len(TEMPO_CRATE) + 1:] for name in listed(sdk, TEMPO_CRATE)}
    if not {'Cargo.toml', 'Cargo.lock', 'src/lib.rs'}.issubset(blobs) or set(blobs) != tracked or inventory(crate) != tracked:
        raise ValueError('SDK Tempo crate file set differs from its pinned commit')
    for name in blobs:
        if name not in {'Cargo.toml', 'Cargo.lock', 'LICENSE', 'LICENSE.md'} and not re.fullmatch(r'(?:src/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.rs|tests/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.(?:rs|json))', name):
            raise ValueError('Unexpected SDK Tempo crate file: ' + name)
    unchanged(crate, blobs)
    return blobs


def recorded(value, sources, label):
    """Compare a metadata {file: digest} map with the commit's blobs."""
    if not isinstance(value, dict) or set(value) != set(sources):
        raise ValueError(f'SDK {label} file set differs from its pin')
    for name, expected in value.items():
        if digest(sources[name]) != expected:
            raise ValueError(f'SDK {label} differs from its pin: {name}')


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


def tempo_review(root):
    """Opt-in local review overlay. Distribution verification stays pinned by default.

    The manifest is supplied outside the repository by the reviewer and binds
    both first-party Cargo inputs and the complete new crate file set. It never
    permits modifications to any existing pinned SDK source or discovery input.
    """
    selected = os.environ.get('ALLOWIT_TEMPO_REVIEW_MANIFEST')
    if not selected:
        return None
    manifest = Path(selected)
    if not manifest.is_absolute() or manifest.is_symlink() or not manifest.is_file():
        raise ValueError('Tempo review requires an explicit regular manifest file')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate Tempo review manifest field')
            result[key] = value
        return result
    try:
        review = json.loads(manifest.read_text(), object_pairs_hook=unique)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError('Invalid Tempo review manifest') from error
    if (not isinstance(review, dict) or set(review) != {'version', 'kind', 'baseCommit', 'crate', 'package', 'files', 'parentFiles'}
            or review['version'] != 1 or review['kind'] != 'tempo-sdk-worktree-review' or review['baseCommit'] != TEMPO_REVIEW_PIN
            or review['crate'] != 'tempo-rust' or review['package'] != {'name': 'allowit-tempo', 'features': []}):
        raise ValueError('Tempo review manifest identity differs from the reviewed overlay')
    root = Path(root).resolve()
    for relative in [SUBMODULE, SUBMODULE + '/tempo-rust']:
        current = root
        for part in PurePosixPath(relative).parts:
            current /= part
            if current.is_symlink() or not current.is_dir():
                raise ValueError('Tempo review directory must not be a symlink')
    crate = root / SUBMODULE / 'tempo-rust'
    files, parents = review['files'], review['parentFiles']
    if (not isinstance(files, dict) or not {'Cargo.toml', 'Cargo.lock', 'src/lib.rs'}.issubset(files)
            or not isinstance(parents, dict) or set(parents) != {'Cargo.toml', 'Cargo.lock'}):
        raise ValueError('Tempo review manifest omits build inputs')
    for name in files:
        if name not in {'Cargo.toml', 'Cargo.lock'} and not re.fullmatch(r'src/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.rs', name):
            raise ValueError('Unreviewed Tempo crate file')
    if inventory(crate) != set(files):
        raise ValueError('Tempo review crate file set changed')
    for directory, expected in [(crate, files), (root, parents)]:
        for name, fingerprint in expected.items():
            candidate = directory / name
            if (not isinstance(fingerprint, str) or not re.fullmatch(r'[0-9a-f]{64}', fingerprint)
                    or candidate.is_symlink() or not candidate.is_file() or sha256(candidate) != fingerprint):
                raise ValueError('Tempo review input changed: ' + name)
    return review


def discovery(repo, commit, paths=DISCOVERY, owner='SDK', against='its pinned commit'):
    """Bind REPO's Cargo discovery inputs at PATHS to COMMIT's tree and blobs.

    Cargo reads them whether they are ignored, untracked or hidden by
    skip-worktree/assume-unchanged, so the checkout's files and the index's
    tracked files must both equal the pinned set, byte for byte. A path named
    `.cargo` is a config directory; the others are files.
    """
    blobs = pinned(repo, commit, *paths)
    present = set()
    for name in paths:
        path = repo / name
        if not os.path.lexists(path):
            continue
        config = PurePosixPath(name).name == '.cargo'
        if path.is_symlink() or not (path.is_dir() if config else path.is_file()):
            raise ValueError(f'{owner} Cargo discovery input must be a regular file or directory: {name}')
        if config:
            present.update(f'{name}/{file}' for file in inventory(path))
        else:
            present.add(name)
    if present != set(blobs) or set(listed(repo, *paths)) != set(blobs):
        raise ValueError(f'{owner} Cargo discovery file set differs from {against}')
    unchanged(repo, blobs, owner, against)


def parent(root, *directories):
    """Bind the CLI's Cargo discovery inputs in DIRECTORIES ('' is the root) to its HEAD.

    Each directory must be a real directory under ROOT, so no input resolves
    outside the CLI checkout.
    """
    for directory in filter(None, directories):
        path = root / directory
        if path.is_symlink() or not path.is_dir():
            raise ValueError('CLI Cargo discovery directory must be a real directory: ' + directory)
    paths = [str(PurePosixPath(directory, name)) for directory in directories for name in DISCOVERY]
    discovery(root, 'HEAD', paths, 'CLI', 'its committed HEAD')


def checkout(root):
    """Return the initialized submodule worktree, never the parent repository."""
    sdk = root / SUBMODULE
    top = command(sdk, 'rev-parse', '--show-toplevel', capture_output=True, text=True) if sdk.is_dir() else None
    if not top or top.returncode or Path(top.stdout.strip()).resolve() != sdk.resolve():
        raise ValueError('SDK submodule is not initialized; run git submodule update --init --recursive')
    status = git(sdk, 'status', '--porcelain', '--untracked-files=all', '--ignored')
    review = tempo_review(root)
    if review:
        if pinned(sdk, review['baseCommit'], 'tempo-rust') or listed(sdk, 'tempo-rust'):
            raise ValueError('Tempo review may add only a new untracked crate')
        if any(line[:2] not in {'??', '!!'} or not line[3:].startswith('tempo-rust/') for line in status.splitlines()):
            raise ValueError('Tempo review cannot modify pinned SDK files')
    elif status:
        raise ValueError('SDK submodule must be clean')
    return sdk


def verify(root, allow_review=False):
    """Check the parent pin, clean submodule source, license bytes and the Cargo
    discovery inputs from the SDK root up to, not including, the CLI root; return the metadata."""
    root = Path(root).resolve()
    if os.environ.get('ALLOWIT_TEMPO_REVIEW_MANIFEST') and not allow_review:
        raise ValueError('Tempo worktree review cannot produce release provenance or packaging')
    sdk = json.loads((root / METADATA).read_text())
    commit = sdk.get('commit')
    review = tempo_review(root)
    if review and review['baseCommit'] != commit:
        raise ValueError('Tempo review differs from the pinned SDK commit')
    if not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('SDK pin must be a full commit')
    if sdk.get('repository') != REPOSITORY or sdk.get('crate') != CRATE or sdk.get('submodule') != {'path': SUBMODULE, 'url': URL}:
        raise ValueError('SDK metadata must name the canonical submodule')
    module = command(root, 'config', '--file', '.gitmodules', '--get-regexp', r'^submodule\.', capture_output=True, text=True).stdout.split('\n')
    if sorted(filter(None, module)) != [f'submodule.{SUBMODULE}.path {SUBMODULE}', f'submodule.{SUBMODULE}.url {URL}']:
        raise ValueError('.gitmodules must name only the canonical SDK submodule')
    # Exactly the three direct dependency lines may name the SDK, so no other line can add
    # a feature (for example `allowit-policy-sdk/compiler`) through unification.
    mentions = [line for line in (root / 'Cargo.toml').read_text().splitlines()
                if any(name in line for name in (SUBMODULE, 'allowit-native', 'allowit-policy-sdk', POLICY_PACKAGE, TEMPO_PACKAGE))]
    expected_dependencies = [DEPENDENCY, POLICY_DEPENDENCY, TEMPO_DEPENDENCY]
    if sorted(mentions) != sorted(expected_dependencies):
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
    interface = sdk.get('payshInterface')
    if not isinstance(interface, dict) or any(not isinstance(name, str) or interface_consumed(name) is not True for name in interface):
        raise ValueError('SDK PaySH interface file set differs from its pin')
    recorded(interface, interface_sources(sdk_root, commit), 'PaySH interface')
    policy = sdk.get('policySdk')
    if not isinstance(policy, dict) or {key: value for key, value in policy.items() if key != 'files'} != policy_identity():
        raise ValueError('SDK policy crate identity differs from the Cargo dependency')
    recorded(policy.get('files'), policy_sources(sdk_root, commit), 'policy crate')
    tempo = sdk.get('tempoSdk')
    if review:
        if tempo is not None:
            raise ValueError('Tempo review cannot replace a published SDK crate')
    else:
        if not isinstance(tempo, dict) or tempo.get('defaultFeatures') is not True or {key: value for key, value in tempo.items() if key != 'files'} != tempo_identity():
            raise ValueError('SDK Tempo crate identity differs from the Cargo dependency')
        recorded(tempo.get('files'), tempo_sources(sdk_root, commit), 'Tempo crate')
    discovery(sdk_root, commit)
    # The CLI root's own Cargo inputs are first-party development files; only
    # binary provenance binds them. Directories in between are bound here.
    parent(root, *INTERMEDIATE)

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
    interface = interface_sources(sdk, commit)
    policy = policy_sources(sdk, commit)
    tempo = tempo_sources(sdk, commit)
    discovery(sdk, commit)
    parent(root, *INTERMEDIATE)
    return {
        'repository': REPOSITORY,
        'commit': commit,
        'crate': CRATE,
        'submodule': {'path': SUBMODULE, 'url': URL},
        'files': {name: digest(source[name]) for name in tracked if consumed(name)},
        'unconsumed': [name for name in tracked if not consumed(name)],
        'payshInterface': {name: digest(interface[name]) for name in sorted(interface)},
        'policySdk': {**policy_identity(), 'files': {name: digest(policy[name]) for name in sorted(policy)}},
        'tempoSdk': {**tempo_identity(), 'files': {name: digest(tempo[name]) for name in sorted(tempo)}},
        'licenses': {name: digest(legal[name]) for name in LICENSES if name in legal},
    }


# Cargo package name -> (crate directory in the SDK, enabled features).
RESOLVED = {
    'allowit-native': (CRATE, []),
    'allowit-paysh-interface': (INTERFACE, []),
    POLICY_PACKAGE: ('', POLICY_FEATURES),
    TEMPO_PACKAGE: (TEMPO_CRATE, []),
}


def resolved(root, *config):
    """Check the dependency graph Cargo actually resolves in this environment.

    Cargo configuration outside the checked files (`paths` overrides in a parent
    directory's `.cargo/`, `CARGO_HOME`, `--config`) can replace a path
    dependency without changing any bound byte. Cargo's own resolution must name
    the submodule's manifests and library roots, no build script or `links`, and
    exactly the pinned features. CONFIG passes extra `--config` values (tests).
    """
    root = Path(root).resolve()
    args = ['cargo', 'metadata', '--locked', '--format-version', '1']
    for value in config:
        args += ['--config', value]
    result = subprocess.run(args, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if result.returncode:
        raise ValueError('Cargo could not resolve the locked dependency graph')
    metadata = json.loads(result.stdout)
    local = {p['name']: p for p in metadata['packages'] if p.get('source') is None}
    expected = dict(RESOLVED)
    if set(local) != {'allowit-cli', *expected}:
        raise ValueError('Cargo resolves unexpected local packages')
    features = {node['id']: sorted(node.get('features', [])) for node in metadata['resolve']['nodes']}
    sdk = root / SUBMODULE
    for name, (directory, enabled) in expected.items():
        package = local[name]
        crate = (sdk / directory).resolve()
        libraries = [t for t in package['targets'] if {'lib', 'rlib'} & set(t['kind'])]
        if (Path(package['manifest_path']).resolve() != crate / 'Cargo.toml'
                or len(libraries) != 1 or Path(libraries[0]['src_path']).resolve() != crate / 'src/lib.rs'
                or any('custom-build' in t['kind'] for t in package['targets']) or package.get('links') is not None):
            raise ValueError(f'Cargo does not build {name} from the pinned SDK submodule')
        if features.get(package['id']) != sorted(enabled):
            raise ValueError(f'Cargo enables unpinned features of {name}')


def policy_identity():
    return {'path': '.', 'package': POLICY_PACKAGE, 'defaultFeatures': False, 'features': POLICY_FEATURES}


def tempo_identity():
    return {'path': TEMPO_CRATE, 'package': TEMPO_PACKAGE, 'defaultFeatures': True, 'features': []}


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
    commands.add_parser('verify', help="check the pinned, clean SDK submodule and Cargo's resolution of it (default for builds)")
    commands.add_parser('pin', help='record and stage the checked-out SDK submodule commit')
    commands.add_parser('update', help='check out, record and stage an exact SDK commit').add_argument('revision')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        if os.environ.get('ALLOWIT_TEMPO_REVIEW_MANIFEST') and args.command != 'verify':
            raise ValueError('Tempo worktree review cannot change SDK pins')
        sdk = update(root, args.revision) if args.command == 'update' else pin(root) if args.command == 'pin' else verify(root, allow_review=True)
        resolved(root)
    except ValueError as error:
        parser.exit(1, f'{error}\n')
    verb = 'Verified' if args.command == 'verify' else 'Staged'
    print(f'{verb} canonical SDK submodule {SUBMODULE} at {sdk["commit"]}')
    if os.environ.get('ALLOWIT_TEMPO_REVIEW_MANIFEST'):
        print('Tempo uses an explicit hash-bound worktree overlay; this is review evidence, not release provenance.')


if __name__ == '__main__':
    main()
