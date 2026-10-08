#!/usr/bin/env python3
"""Provenance contract tests; no network or compiled binaries required."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


provenance = load("provenance", "binary-provenance.py")
fixture = load("native_sdk_fixture", "native-sdk-fixture.py")


class ProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = tempfile.TemporaryDirectory()
        fixture.create(Path(cls.template.name) / "repo", ["Cargo.toml", "vendor/native-sdk.json"])

    @classmethod
    def tearDownClass(cls):
        cls.template.cleanup()

    def setUp(self):
        environment = patch.dict(os.environ, {"GITHUB_RUN_ID": "", "GITHUB_RUN_ATTEMPT": ""})
        environment.start(); self.addCleanup(environment.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / "repo"
        shutil.copytree(Path(self.template.name) / "repo", self.repo, symlinks=True)
        self.sdk = self.repo / fixture.SDK
        self.binary = Path(self.tmp.name) / "allowit"
        self.binary.write_bytes(b"\xcf\xfa\xed\xfe" + (0x100000C).to_bytes(4, "little") + b"synthetic-test-only")

    def git(self, *args):
        return fixture.git(self.repo, *args)

    def manifest(self, target="aarch64-apple-darwin"):
        return provenance.manifest(self.repo, self.binary, target)

    def metadata(self, change):
        path = self.repo / "vendor/native-sdk.json"
        value = json.loads(path.read_text()); change(value)
        path.write_text(json.dumps(value))
        fixture.commit(self.repo, "metadata")

    def test_exact_binary_source_and_sdk_release_identity(self):
        result = self.manifest()
        self.assertEqual(result["cli"]["commit"], self.git("rev-parse", "HEAD"))
        self.assertEqual(result["cli"]["sourceTree"], self.git("rev-parse", "HEAD^{tree}"))
        self.assertEqual(result["binary"]["sha256"], hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.assertEqual(result["sdk"], json.loads((self.repo / "vendor/native-sdk.json").read_text()))
        self.assertEqual(result["sdk"]["commit"], fixture.git(self.sdk, "rev-parse", "HEAD"))
        self.assertEqual(result["sdk"]["submodule"], {"path": fixture.SDK, "url": "https://github.com/AllowIt-hq/allowit-sdk.git"})
        self.assertEqual(result["nativeRelease"]["sourceBundle"], json.loads((self.sdk / "native-rust/src/release.json").read_text())["sourceBundle"])
        self.assertNotIn("sources", result["nativeRelease"])

    def test_accepts_clean_autocrlf_sdk_checkout(self):
        fixture.autocrlf(self.repo)
        self.assertIn(b"\r\n", (self.sdk / "native-rust/src/lib.rs").read_bytes())
        self.assertIn(b"\r\n", (self.sdk / "LICENSE").read_bytes())
        self.assertEqual(fixture.git(self.sdk, "status", "--porcelain", "--untracked-files=all"), "")
        self.assertEqual(self.manifest()["sdk"], json.loads((self.repo / "vendor/native-sdk.json").read_text()))

    def test_refuses_changed_sdk_source_in_autocrlf_checkout(self):
        fixture.autocrlf(self.repo)
        lib = self.sdk / "native-rust/src/lib.rs"
        lib.write_bytes(lib.read_bytes() + b"// drift\r\n")
        fixture.commit(self.sdk, "drift")
        fixture.repin(self.repo)
        with self.assertRaisesRegex(ValueError, "source differs from its pin"):
            self.manifest()

    def test_refuses_ignored_sdk_build_script_in_autocrlf_checkout(self):
        fixture.autocrlf(self.repo)
        fixture.exclude(self.repo, "/native-rust/build.rs")
        (self.sdk / "native-rust/build.rs").write_bytes(b"fn main() {}\r\n")
        self.assertEqual(fixture.git(self.sdk, "status", "--porcelain", "--untracked-files=all"), "")
        with self.assertRaisesRegex(ValueError, "file set"):
            self.manifest()

    def test_refuses_uncommitted_source(self):
        with (self.repo / "Cargo.toml").open("a") as handle:
            handle.write("\n# edited\n")
        with self.assertRaisesRegex(ValueError, "committed"):
            self.manifest()

    def test_refuses_dirty_sdk_submodule(self):
        with (self.sdk / "native-rust/src/lib.rs").open("a") as handle:
            handle.write("\n// drift\n")
        with self.assertRaisesRegex(ValueError, "submodule must be clean"):
            self.manifest()

    def test_refuses_missing_sdk_submodule(self):
        self.git("submodule", "deinit", "-q", "-f", fixture.SDK)
        with self.assertRaisesRegex(ValueError, "not initialized"):
            self.manifest()
        self.sdk.rmdir()
        with self.assertRaisesRegex(ValueError, "not initialized"):
            self.manifest()

    def test_refuses_sdk_change_committed_only_in_submodule(self):
        with (self.sdk / "native-rust/src/lib.rs").open("a") as handle:
            handle.write("\n// drift\n")
        fixture.commit(self.sdk, "drift")
        with self.assertRaisesRegex(ValueError, "HEAD differs from its pin"):
            self.manifest()
        # Moving the parent pin does not legitimize source with recorded hashes.
        fixture.repin(self.repo)
        with self.assertRaisesRegex(ValueError, "source differs from its pin"):
            self.manifest()

    def test_refuses_metadata_that_differs_from_gitlink(self):
        self.metadata(lambda value: value.update(commit="0" * 40))
        with self.assertRaisesRegex(ValueError, "index must pin"):
            self.manifest()

    def test_refuses_non_canonical_submodule_url(self):
        self.git("config", "--file", ".gitmodules", f"submodule.{fixture.SDK}.url", "https://example.invalid/allowit-sdk.git")
        fixture.commit(self.repo, "mirror")
        with self.assertRaisesRegex(ValueError, "canonical"):
            self.manifest()

    def test_refuses_tracked_sdk_source_copy(self):
        copy = self.repo / "vendor/allowit-native/src/lib.rs"
        copy.parent.mkdir(parents=True)
        shutil.copyfile(self.sdk / "native-rust/src/lib.rs", copy)
        fixture.commit(self.repo, "copy")
        with self.assertRaisesRegex(ValueError, "copies"):
            self.manifest()

    def test_refuses_changed_sdk_license_attribution(self):
        (self.sdk / "LICENSE").write_text("changed attribution\n")
        fixture.commit(self.sdk, "license drift")
        fixture.repin(self.repo)
        with self.assertRaisesRegex(ValueError, "license notice is missing or changed"):
            self.manifest()

    def test_refuses_invalid_sdk_notice_paths(self):
        digest = json.loads((self.repo / "vendor/native-sdk.json").read_text())["licenses"]["LICENSE"]
        for name in ["../LICENSE", "/LICENSE", "native-rust/Cargo.toml"]:
            with self.subTest(name=name):
                self.metadata(lambda value: value["licenses"].update({name: digest}))
                with self.assertRaisesRegex(ValueError, "license path is invalid"):
                    self.manifest()
                self.metadata(lambda value: value["licenses"].pop(name))
        self.metadata(lambda value: value["licenses"].pop("THIRD_PARTY_NOTICES.md"))
        with self.assertRaisesRegex(ValueError, "license set differs"):
            self.manifest()

    def test_refuses_wrong_binary_architecture(self):
        with self.assertRaisesRegex(ValueError, "architecture"):
            self.manifest("x86_64-apple-darwin")
        with self.assertRaisesRegex(ValueError, "format"):
            self.manifest("x86_64-unknown-linux-musl")

    def test_refuses_unlisted_committed_sdk_build_script(self):
        (self.sdk / "native-rust/build.rs").write_text("fn main() {}\n")
        fixture.commit(self.sdk, "extra")
        fixture.repin(self.repo)
        with self.assertRaisesRegex(ValueError, "file set"):
            self.manifest()

    def test_refuses_ignored_sdk_build_script(self):
        fixture.exclude(self.repo, "/native-rust/build.rs")
        (self.sdk / "native-rust/build.rs").write_text("fn main() {}\n")
        self.assertEqual(fixture.git(self.sdk, "status", "--porcelain", "--untracked-files=all"), "")
        with self.assertRaisesRegex(ValueError, "file set"):
            self.manifest()

    def test_refuses_empty_sdk_source_set(self):
        self.metadata(lambda value: value.update(files={}))
        with self.assertRaisesRegex(ValueError, "file set"):
            self.manifest()

    def test_ci_build_metadata_accepts_github_repository_case(self):
        context = {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_REPOSITORY": "allowit-hq/ALLOWIT-CLI", "GITHUB_SHA": self.git("rev-parse", "HEAD")}
        with patch.dict(os.environ, context):
            result = self.manifest()
            self.assertEqual(result["build"]["githubRunURL"], "https://github.com/AllowIt-hq/allowit-cli/actions/runs/123")

    def test_ci_build_metadata_binds_actual_checkout(self):
        context = {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_REPOSITORY": "AllowIt-hq/allowit-cli", "GITHUB_SHA": self.git("rev-parse", "HEAD"), "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main"}
        with patch.dict(os.environ, context):
            result = self.manifest()
            self.assertEqual(result["build"]["event"], "workflow_dispatch")
            self.assertEqual(result["build"]["sha"], result["cli"]["commit"])
            with patch.dict(os.environ, {"GITHUB_SHA": "0" * 40}):
                with self.assertRaisesRegex(ValueError, "revision differs"):
                    self.manifest()


if __name__ == "__main__":
    unittest.main()
