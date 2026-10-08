#!/usr/bin/env python3
"""Provenance contract tests; no network or compiled binaries required."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
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

    def test_refuses_hidden_sdk_source_change(self):
        lib = "native-rust/src/lib.rs"
        original = (self.sdk / lib).read_bytes()
        for flag in ["--skip-worktree", "--assume-unchanged"]:
            with self.subTest(flag=flag):
                fixture.hide(self.repo, lib, original + b"// hidden\n", flag)
                with self.assertRaisesRegex(ValueError, "checkout differs from its pinned commit: src/lib.rs"):
                    self.manifest()
                fixture.git(self.sdk, "update-index", flag.replace("--", "--no-", 1), "--", lib)
                (self.sdk / lib).write_bytes(original)
        self.manifest()

    def test_refuses_metadata_rehashed_to_hidden_sdk_source(self):
        lib = "native-rust/src/lib.rs"
        hidden = (self.sdk / lib).read_bytes() + b"// hidden\n"
        fixture.hide(self.repo, lib, hidden)
        self.metadata(lambda value: value["files"].update({"src/lib.rs": provenance.native_sdk.digest(hidden)}))
        self.assertEqual(fixture.git(self.sdk, "rev-parse", "HEAD"), json.loads((self.repo / "vendor/native-sdk.json").read_text())["commit"])
        with self.assertRaisesRegex(ValueError, "source differs from its pin: src/lib.rs"):
            self.manifest()

    def test_pin_and_describe_refuse_hidden_sdk_source(self):
        metadata = (self.repo / "vendor/native-sdk.json").read_bytes()
        gitlink = self.git("ls-files", "--stage", "--", fixture.SDK)
        fixture.hide(self.repo, "native-rust/src/lib.rs", b"pub fn hidden() {}\n")
        for action in [provenance.native_sdk.describe, provenance.native_sdk.pin]:
            with self.subTest(action=action.__name__):
                with self.assertRaisesRegex(ValueError, "checkout differs from its pinned commit: src/lib.rs"):
                    action(self.repo)
        self.assertEqual((self.repo / "vendor/native-sdk.json").read_bytes(), metadata)
        self.assertEqual(self.git("ls-files", "--stage", "--", fixture.SDK), gitlink)
        self.assertEqual(self.git("status", "--porcelain"), "")

    def test_pin_ignores_replace_objects_for_hidden_sdk_source(self):
        lib = "native-rust/src/lib.rs"
        original = fixture.git(self.sdk, "rev-parse", f"HEAD:{lib}")
        fixture.hide(self.repo, lib, b"pub fn hidden() {}\n")
        fixture.git(self.sdk, "replace", original, fixture.git(self.sdk, "hash-object", "-w", lib))
        with self.assertRaisesRegex(ValueError, "checkout differs from its pinned commit: src/lib.rs"):
            provenance.native_sdk.pin(self.repo)

    def test_refuses_hidden_sdk_license_change(self):
        fixture.hide(self.repo, "LICENSE", b"changed attribution\n", "--assume-unchanged")
        with self.assertRaisesRegex(ValueError, "checkout differs from its pinned commit: LICENSE"):
            self.manifest()
        with self.assertRaisesRegex(ValueError, "checkout differs from its pinned commit: LICENSE"):
            provenance.native_sdk.describe(self.repo)

    def test_pin_rerecords_unchanged_sdk_bytes(self):
        path = self.repo / "vendor/native-sdk.json"
        recorded = json.loads(path.read_text())
        self.assertEqual(provenance.native_sdk.describe(self.repo), recorded)
        fixture.autocrlf(self.repo)
        self.assertEqual(provenance.native_sdk.pin(self.repo), recorded)
        self.assertEqual(json.loads(path.read_text()), recorded)

    def test_ignores_inherited_git_environment(self):
        commit = fixture.git(self.sdk, "rev-parse", "HEAD")
        missing = str(Path(self.tmp.name) / "missing")
        redirect = {"GIT_DIR": missing, "GIT_WORK_TREE": missing, "GIT_INDEX_FILE": missing, "GIT_OBJECT_DIRECTORY": missing}
        with patch.dict(os.environ, redirect):
            self.assertEqual(provenance.native_sdk.verify(self.repo)["commit"], commit)
            self.assertEqual(self.manifest()["sdk"]["commit"], commit)

    def test_native_builds_verify_sdk_first(self):
        verify = "python3 scripts/sync-native-sdk.py verify"
        workflow = (fixture.ROOT / ".github/workflows/binaries.yml").read_text()
        self.assertLess(workflow.index(verify), workflow.index("cargo build"))
        recipes = [recipe for recipe in re.split(r"(?m)^(?=[\w.-]+:)", (fixture.ROOT / "Makefile").read_text()) if "$(CARGO) build" in recipe]
        self.assertEqual(sorted(recipe.split(":", 1)[0] for recipe in recipes), ["build", "dist", "parity"])
        for recipe in recipes:
            with self.subTest(target=recipe.split(":", 1)[0]):
                self.assertIn(verify, recipe)
                self.assertLess(recipe.index(verify), recipe.index("$(CARGO) build"))

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
