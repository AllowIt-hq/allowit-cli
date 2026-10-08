"""Test fixture: a local parent checkout with the pinned SDK as a real submodule.

The submodule is cloned from this checkout's initialized SDK submodule, so tests
use the real pinned commit, metadata and source bytes without network access.
"""
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SDK = 'repos/AllowIt-hq--allowit-sdk'
IDENTITY = ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false']


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *IDENTITY, *args], text=True).strip()


def commit(repo, message):
    git(repo, 'add', '-A')
    git(repo, 'commit', '-qm', message)


def create(repo, files):
    """Copy parent FILES into REPO and add the SDK submodule at its pinned commit."""
    pin = json.loads((ROOT / 'vendor/native-sdk.json').read_text())['commit']
    repo.mkdir()
    for name in files:
        source, target = ROOT / name, repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            shutil.copyfile(source, target)
    git(repo, 'init', '-q')
    git(repo, '-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', str(ROOT / SDK), SDK)
    git(repo / SDK, 'checkout', '-q', '--detach', pin)
    shutil.copyfile(ROOT / '.gitmodules', repo / '.gitmodules')  # canonical URL
    commit(repo, 'fixture')


def repin(repo, message='repin'):
    """Record the submodule's current HEAD in the gitlink and metadata, as a reviewer would."""
    path = repo / 'vendor/native-sdk.json'
    value = json.loads(path.read_text())
    value['commit'] = git(repo / SDK, 'rev-parse', 'HEAD')
    path.write_text(json.dumps(value, indent=2) + '\n')
    commit(repo, message)


def autocrlf(repo):
    """Re-check out the SDK as a Windows core.autocrlf clone does: CRLF text, clean status."""
    sdk = repo / SDK
    git(sdk, 'config', 'core.autocrlf', 'true')
    for name in filter(None, git(sdk, 'ls-files', '-z').split('\0')):
        (sdk / name).unlink()
    git(sdk, 'checkout', '-q', '--', '.')
    return sdk


def exclude(repo, pattern):
    """Ignore PATTERN inside the submodule without changing tracked files."""
    path = repo / SDK / git(repo / SDK, 'rev-parse', '--git-path', 'info/exclude')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a') as handle:
        handle.write(pattern + '\n')
