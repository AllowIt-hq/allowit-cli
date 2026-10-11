#!/usr/bin/env python3
"""Validate original dependency notices and package them beside native binaries."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import shutil
import sys

# Loading the shared verifier must not leave bytecode in the checkout.
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location('native_sdk', pathlib.Path(__file__).with_name('sync-native-sdk.py'))
native_sdk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(native_sdk)


def lock_packages(text):
    # Cargo generates flat package identity fields. Ignore dependency arrays;
    # decode the string fields strictly so this build helper also works on 3.9.
    blocks = re.split(r'(?m)^\[\[package\]\]\s*$', text)[1:]
    if not blocks:
        raise ValueError('Cargo lockfile has no package records')
    packages = []
    for block in blocks:
        package = {}
        for line in block.splitlines():
            match = re.match(r'^(name|version|source|checksum)\s*=\s*(.+)$', line)
            if match:
                key, value = match.groups()
                if key in package:
                    raise ValueError('Duplicate Cargo lockfile identity field')
                package[key] = json.loads(value)
                if not isinstance(package[key], str):
                    raise ValueError('Invalid Cargo lockfile identity field')
        if not package.get('name') or not package.get('version'):
            raise ValueError('Cargo lockfile package identity missing')
        packages.append(package)
    return packages


def validate(root):
    sdk = native_sdk.verify(root)
    directory = root / 'THIRD_PARTY_LICENSES'
    records = json.loads((directory / 'registry-index.json').read_text())
    found = {}
    for record in records:
        identity = (record['name'], record['version'])
        if identity in found or record['status'] != 'covered' or not record['files']:
            raise ValueError('Duplicate or uncovered dependency notices')
        if record['crateSha256'] != record['cargoChecksum']:
            raise ValueError('Original crate checksum differs')
        for item in record['files']:
            relative = pathlib.PurePosixPath(item['path'])
            if relative.is_absolute() or '..' in relative.parts or relative.parts[:2] != identity:
                raise ValueError('Notice path escapes its package')
            file = directory / 'crates' / relative
            if file.is_symlink() or hashlib.sha256(file.read_bytes()).hexdigest() != item['sha256']:
                raise ValueError('Notice file is missing or changed')
        found[identity] = record
    for label, lock in [('Current', root / 'Cargo.lock'), ('SDK Tempo', root / native_sdk.SUBMODULE / native_sdk.TEMPO_CRATE / 'Cargo.lock')]:
        for package in lock_packages(lock.read_text()):
            if package.get('source', '').startswith('registry+'):
                record = found.get((package['name'], package['version']))
                if not record or package['checksum'] != record['cargoChecksum']:
                    raise ValueError(label + ' lockfile dependency has no matching notices')
    for file in ['LICENSE', 'THIRD_PARTY_LICENSES/README.md', 'THIRD_PARTY_LICENSES/toolchain-index.json']:
        if not (root / file).is_file() or (root / file).is_symlink():
            raise ValueError('Required binary license material is missing')
    for item in json.loads((directory / 'toolchain-index.json').read_text()):
        relative = pathlib.PurePosixPath(item['path'])
        if relative.is_absolute() or '..' in relative.parts or relative.parts[0] != 'toolchains':
            raise ValueError('Toolchain notice path escapes its directory')
        file = directory / relative
        if file.is_symlink() or hashlib.sha256(file.read_bytes()).hexdigest() != item['sha256']:
            raise ValueError('Toolchain notice is missing or changed')
    return sdk


def package(root, dist):
    sdk = validate(root)
    dist.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(root / 'LICENSE', dist / 'LICENSE')
    shutil.copytree(root / 'THIRD_PARTY_LICENSES', dist / 'THIRD_PARTY_LICENSES', dirs_exist_ok=True)
    # SDK notices come from the verified submodule's upstream root, byte for byte.
    for name in sdk['licenses']:
        target = dist / 'THIRD_PARTY_LICENSES/AllowIt-sdk' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / native_sdk.SUBMODULE / name, target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dist', type=pathlib.Path)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[1]
    if args.dist:
        package(root, args.dist)
    else:
        validate(root)
    print('Binary license notices verified')


if __name__ == '__main__':
    main()
