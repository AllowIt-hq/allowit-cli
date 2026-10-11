#!/usr/bin/env python3
"""Review-only source-binding tests. No Git changes or network requests."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location('sdk_sync', Path(__file__).with_name('sync-native-sdk.py'))
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


class TempoReviewTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / 'cli'
        self.crate = self.root / sync.SUBMODULE / 'tempo-rust'
        (self.crate / 'src').mkdir(parents=True)
        for path, content in [(self.root / 'Cargo.toml', 'parent manifest'), (self.root / 'Cargo.lock', 'parent lock'),
                              (self.crate / 'Cargo.toml', 'crate manifest'), (self.crate / 'Cargo.lock', 'crate lock'),
                              (self.crate / 'src/lib.rs', 'pub fn reviewed() {}')]:
            path.write_text(content)
        self.review = {'version': 1, 'kind': 'tempo-sdk-worktree-review', 'baseCommit': sync.TEMPO_REVIEW_PIN,
                       'crate': 'tempo-rust', 'package': {'name': 'allowit-tempo', 'features': []},
                       'files': {name: sync.sha256(self.crate / name) for name in ['Cargo.toml', 'Cargo.lock', 'src/lib.rs']},
                       'parentFiles': {name: sync.sha256(self.root / name) for name in ['Cargo.toml', 'Cargo.lock']}}
        self.manifest = Path(self.temporary.name) / 'review.json'
        self.save()
        self.environment = patch.dict(os.environ, {'ALLOWIT_TEMPO_REVIEW_MANIFEST': str(self.manifest)})
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.temporary.cleanup()

    def save(self):
        self.manifest.write_text(json.dumps(self.review))

    def test_default_has_no_overlay(self):
        with patch.dict(os.environ, {'ALLOWIT_TEMPO_REVIEW_MANIFEST': ''}):
            self.assertIsNone(sync.tempo_review(self.root))

    def test_exact_sources_and_parent_inputs_are_accepted(self):
        self.assertEqual(sync.tempo_review(self.root), self.review)

    def test_review_cannot_be_used_by_release_provenance(self):
        with self.assertRaisesRegex(ValueError, 'release provenance'):
            sync.verify(self.root)

    def test_source_and_parent_drift_are_rejected(self):
        for path in [self.crate / 'src/lib.rs', self.crate / 'Cargo.lock', self.root / 'Cargo.toml', self.root / 'Cargo.lock']:
            with self.subTest(path=path):
                before = path.read_bytes()
                path.write_bytes(before + b'changed')
                with self.assertRaisesRegex(ValueError, 'input changed'):
                    sync.tempo_review(self.root)
                path.write_bytes(before)

    def test_build_script_and_unlisted_inputs_are_rejected(self):
        for name in ['build.rs', 'src/extra.rs', '.cargo/config.toml']:
            with self.subTest(name=name):
                path = self.crate / name
                path.parent.mkdir(exist_ok=True)
                path.write_text('unreviewed')
                with self.assertRaisesRegex(ValueError, 'file set changed'):
                    sync.tempo_review(self.root)
                path.unlink()

    def test_manifest_cannot_bless_build_script_or_escape(self):
        for name in ['build.rs', '../native-rust/src/lib.rs', '/absolute.rs']:
            with self.subTest(name=name):
                self.review['files'][name] = 'a' * 64
                self.save()
                with self.assertRaisesRegex(ValueError, 'Unreviewed Tempo crate file'):
                    sync.tempo_review(self.root)
                del self.review['files'][name]

    def test_pin_and_features_cannot_change(self):
        self.review['baseCommit'] = 'b' * 40
        self.save()
        with self.assertRaisesRegex(ValueError, 'identity'):
            sync.tempo_review(self.root)
        self.review['baseCommit'] = sync.TEMPO_REVIEW_PIN
        self.review['package']['features'] = ['compiler']
        self.save()
        with self.assertRaisesRegex(ValueError, 'identity'):
            sync.tempo_review(self.root)

    @unittest.skipIf(os.name == 'nt', 'POSIX source-binding run exercises symlinks')
    def test_symlink_source_or_manifest_is_rejected(self):
        path = self.crate / 'src/lib.rs'
        path.unlink()
        path.symlink_to(self.root / 'Cargo.toml')
        with self.assertRaises(ValueError):
            sync.tempo_review(self.root)
        link = Path(self.temporary.name) / 'link.json'
        link.symlink_to(self.manifest)
        with patch.dict(os.environ, {'ALLOWIT_TEMPO_REVIEW_MANIFEST': str(link)}):
            with self.assertRaisesRegex(ValueError, 'regular manifest'):
                sync.tempo_review(self.root)


if __name__ == '__main__':
    unittest.main()
