#!/usr/bin/env python3
"""Catch missing license coverage and corrupted binary companion material."""
import importlib.util
import json
import pathlib
import shutil
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODULE = load('package_licenses', 'package-licenses.py')
FIXTURE = load('native_sdk_fixture', 'native-sdk-fixture.py')


class LicenseMaterial(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = tempfile.TemporaryDirectory()
        FIXTURE.create(pathlib.Path(cls.template.name) / 'repo', ['LICENSE', 'Cargo.lock', 'Cargo.toml', 'THIRD_PARTY_LICENSES', 'vendor/native-sdk.json'])

    @classmethod
    def tearDownClass(cls):
        cls.template.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name) / 'repo'
        shutil.copytree(pathlib.Path(self.template.name) / 'repo', self.root, symlinks=True)
        self.sdk = self.root / FIXTURE.SDK

    def tearDown(self):
        self.temp.cleanup()

    def test_complete_current_and_historical_coverage(self):
        MODULE.validate(self.root)

    def test_policy_sdk_dependencies_have_authentic_notices(self):
        index = {(r['name'], r['version']): r for r in json.loads((self.root / 'THIRD_PARTY_LICENSES/registry-index.json').read_text())}
        lock = {(p['name'], p['version']) for p in MODULE.lock_packages((self.root / 'Cargo.lock').read_text()) if p.get('source', '').startswith('registry+')}
        # Root policy crate dependencies, including its Solana-target-only hasher chain.
        for identity in [('unicode-normalization', '0.1.25'), ('unicode-script', '0.5.8'), ('solana-sha256-hasher', '2.3.0'), ('five8', '0.2.1')]:
            self.assertIn(identity, lock)
            self.assertEqual(index[identity]['status'], 'covered')
        for record in index.values():
            if 'licenseSource' in record and 'raw.githubusercontent.com' in record['licenseSource']:
                # Archives without license files cite upstream LICENSE at the crate's VCS commit.
                commit = record['licenseSource'].split('/')[-2]
                self.assertRegex(commit, r'^[0-9a-f]{40}$')
                self.assertIn(commit, record['noticeBasis'][0])

    def test_new_dependency_requires_its_own_notice(self):
        lock = self.root / 'Cargo.lock'
        lock.write_text(lock.read_text() + '\n[[package]]\nname="unknown-example"\nversion="1.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="' + '0' * 64 + '"\n')
        with self.assertRaisesRegex(ValueError, 'Current lockfile'):
            MODULE.validate(self.root)

    def test_corrupted_copyright_is_rejected(self):
        index = json.loads((self.root / 'THIRD_PARTY_LICENSES/registry-index.json').read_text())
        file = self.root / 'THIRD_PARTY_LICENSES/crates' / index[0]['files'][0]['path']
        file.write_text('truncated license')
        with self.assertRaisesRegex(ValueError, 'missing or changed'):
            MODULE.validate(self.root)

    def test_package_path_cannot_escape(self):
        file = self.root / 'THIRD_PARTY_LICENSES/registry-index.json'
        index = json.loads(file.read_text())
        index[0]['files'][0]['path'] = '../../LICENSE'
        file.write_text(json.dumps(index))
        with self.assertRaisesRegex(ValueError, 'escapes'):
            MODULE.validate(self.root)

    def test_runtime_copyright_is_checked(self):
        file = self.root / 'THIRD_PARTY_LICENSES/toolchains/Go-BSD-3-Clause.txt'
        file.write_text('missing attribution')
        with self.assertRaisesRegex(ValueError, 'Toolchain notice'):
            MODULE.validate(self.root)

    def test_sdk_notices_are_packaged_from_the_submodule(self):
        dist = pathlib.Path(self.temp.name) / 'dist'
        MODULE.package(self.root, dist)
        licenses = json.loads((self.root / 'vendor/native-sdk.json').read_text())['licenses']
        packaged = dist / 'THIRD_PARTY_LICENSES/AllowIt-sdk'
        self.assertEqual(sorted(p.relative_to(packaged).as_posix() for p in packaged.rglob('*') if p.is_file()), sorted(licenses))
        for name in licenses:
            self.assertEqual((packaged / name).read_bytes(), (self.sdk / name).read_bytes())
        self.assertFalse((self.root / 'vendor/native-sdk-licenses').exists())

    def test_autocrlf_sdk_notices_are_packaged_as_checked_out(self):
        FIXTURE.autocrlf(self.root)
        self.assertIn(b'\r\n', (self.sdk / 'LICENSE').read_bytes())
        dist = pathlib.Path(self.temp.name) / 'dist'
        MODULE.package(self.root, dist)
        for name in json.loads((self.root / 'vendor/native-sdk.json').read_text())['licenses']:
            self.assertEqual((dist / 'THIRD_PARTY_LICENSES/AllowIt-sdk' / name).read_bytes(), (self.sdk / name).read_bytes())

    def test_sdk_license_is_checked(self):
        (self.sdk / 'LICENSE').write_text('changed attribution')
        with self.assertRaisesRegex(ValueError, 'submodule must be clean'):
            MODULE.validate(self.root)
        FIXTURE.commit(self.sdk, 'license drift')
        FIXTURE.repin(self.root)
        with self.assertRaisesRegex(ValueError, 'SDK license notice'):
            MODULE.package(self.root, pathlib.Path(self.temp.name) / 'dist')

    def test_hidden_sdk_license_change_is_not_packaged(self):
        FIXTURE.hide(self.root, 'LICENSE', b'changed attribution\n', '--assume-unchanged')
        dist = pathlib.Path(self.temp.name) / 'dist'
        with self.assertRaisesRegex(ValueError, 'checkout differs from its pinned commit: LICENSE'):
            MODULE.package(self.root, dist)
        self.assertFalse(dist.exists())

    def test_sdk_notice_path_cannot_escape(self):
        path = self.root / 'vendor/native-sdk.json'
        value = json.loads(path.read_text())
        value['licenses']['../../LICENSE'] = value['licenses']['LICENSE']
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'license path is invalid'):
            MODULE.validate(self.root)

    def test_uninitialized_sdk_submodule_is_rejected(self):
        FIXTURE.git(self.root, 'submodule', 'deinit', '-q', '-f', FIXTURE.SDK)
        with self.assertRaisesRegex(ValueError, 'not initialized'):
            MODULE.validate(self.root)


if __name__ == '__main__':
    unittest.main()
