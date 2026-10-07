#!/usr/bin/env python3
"""Catch missing license coverage and corrupted binary companion material."""
import importlib.util
import json
import pathlib
import shutil
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('package_licenses', ROOT / 'scripts/package-licenses.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LicenseMaterial(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        for name in ['LICENSE', 'Cargo.lock']:
            shutil.copyfile(ROOT / name, self.root / name)
        shutil.copytree(ROOT / 'THIRD_PARTY_LICENSES', self.root / 'THIRD_PARTY_LICENSES')
        shutil.copytree(ROOT / 'vendor', self.root / 'vendor')

    def tearDown(self):
        self.temp.cleanup()

    def test_complete_current_and_historical_coverage(self):
        MODULE.validate(self.root)

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

    def test_sdk_license_is_checked(self):
        (self.root / 'vendor/native-sdk-licenses/LICENSE').write_text('changed attribution')
        with self.assertRaisesRegex(ValueError, 'SDK license notice'):
            MODULE.validate(self.root)


if __name__ == '__main__':
    unittest.main()
