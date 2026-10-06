#!/usr/bin/env python3
"""Copy the narrow native Rust crate from an exact SDK commit; no credentials."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

parser = argparse.ArgumentParser()
parser.add_argument('sdk_repo', type=Path)
parser.add_argument('revision')
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
revision = subprocess.check_output(['git', '-C', str(args.sdk_repo), 'rev-parse', args.revision + '^{commit}'], text=True).strip()
if args.revision != revision:
    parser.error('revision must be a full exact commit SHA')
archive = subprocess.check_output(['git', '-C', str(args.sdk_repo), 'archive', revision, 'native-rust'])
files = {}
with tarfile.open(fileobj=io.BytesIO(archive)) as source:
    for entry in source:
        if entry.isdir() or entry.type == tarfile.XGLTYPE:
            continue
        parts = Path(entry.name).parts
        if not entry.isfile() or not parts or parts[0] != 'native-rust' or '..' in parts:
            raise SystemExit('unsafe SDK archive entry')
        name = Path(*parts[1:]).as_posix()
        if not (name in {'Cargo.toml', 'Cargo.lock', 'LICENSE', 'LICENSE.md'} or name.startswith(('src/', 'tests/'))):
            raise SystemExit('unexpected SDK crate file: ' + name)
        if name.startswith('tests/') and Path(name).suffix not in {'.rs', '.json'}:
            continue  # Reference-authoring JS is SDK tooling, not a Rust dependency.
        files[name] = source.extractfile(entry).read()
if 'Cargo.toml' not in files or 'src/lib.rs' not in files:
    raise SystemExit('native Rust SDK source missing')
root = Path(__file__).resolve().parents[1]
vendored = root / 'vendor' / 'allowit-native'
manifest = {'repository': 'https://github.com/ackrate/AllowIt-sdk', 'commit': revision, 'crate': 'native-rust', 'files': {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}}
manifest_text = json.dumps(manifest, indent=2) + '\n'
if args.check:
    if (root / 'vendor' / 'native-sdk.json').read_text() != manifest_text:
        raise SystemExit('SDK source manifest differs')
    actual = {p.relative_to(vendored).as_posix(): p.read_bytes() for p in vendored.rglob('*') if p.is_file()}
    if actual != files:
        raise SystemExit('vendored SDK source differs from pinned commit')
else:
    # Remove only tracked-snapshot files from the old manifest, never walk-delete
    # a working directory, build output or a developer's unrelated files.
    old_manifest = root / 'vendor' / 'native-sdk.json'
    old = json.loads(old_manifest.read_text())['files'] if old_manifest.exists() else {}
    for name in set(old) - set(files):
        path = vendored / name
        if '..' in Path(name).parts or Path(name).is_absolute():
            raise SystemExit('unsafe old SDK manifest')
        path.unlink(missing_ok=True)
    for name, data in files.items():
        path = vendored / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    old_manifest.parent.mkdir(parents=True, exist_ok=True)
    old_manifest.write_text(manifest_text)
print('Verified native Rust SDK snapshot ' + revision if args.check else 'Pinned native Rust SDK snapshot ' + revision)
