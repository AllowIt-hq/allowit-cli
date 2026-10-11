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
# The CLI root's committed Cargo discovery inputs, copied into each fixture.
ROOT_CARGO = ["Cargo.toml", "Cargo.lock", ".cargo/config.toml"]
INJECTED = '[build]\nrustflags = ["--cfg", "injected"]\n'


class ProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = tempfile.TemporaryDirectory()
        fixture.create(Path(cls.template.name) / "repo", [*ROOT_CARGO, "vendor/native-sdk.json"])

    @classmethod
    def tearDownClass(cls):
        cls.template.cleanup()

    def setUp(self):
        environment = patch.dict(os.environ, {"GITHUB_RUN_ID": "", "GITHUB_RUN_ATTEMPT": ""})
        environment.start(); self.addCleanup(environment.stop)
        # Fixtures hold no buildable CLI source; ResolvedTests covers Cargo resolution.
        resolution = patch.object(provenance.native_sdk, "resolved", lambda root: None)
        resolution.start(); self.addCleanup(resolution.stop)
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
        with self.assertRaisesRegex(ValueError, "submodule must be clean"):
            self.manifest()

    def test_refuses_uncommitted_source(self):
        with (self.repo / "Cargo.toml").open("a") as handle:
            handle.write("\n# edited\n")
        with self.assertRaisesRegex(ValueError, "committed"):
            self.manifest()

    def test_refuses_untracked_parent_cargo_config_hidden_by_status_config(self):
        self.git("config", "status.showUntrackedFiles", "no")
        # Cargo also reads the legacy extensionless name beside the tracked config.toml.
        (self.repo / ".cargo/config").write_text(INJECTED)
        self.assertEqual(self.git("status", "--porcelain"), "")
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

    def test_records_policy_sdk_typed_workflow_and_interface_sources(self):
        result = self.manifest()["sdk"]
        commit = fixture.git(self.sdk, "rev-parse", "HEAD")
        digest = provenance.native_sdk.digest
        blob = lambda name: digest(provenance.native_sdk.pinned(self.sdk, commit, name)[name])
        policy = result["policySdk"]
        self.assertEqual({k: v for k, v in policy.items() if k != "files"}, {"path": ".", "package": "allowit-sdk", "defaultFeatures": False, "features": ["std", "typed-workflow"]})
        self.assertEqual(policy["files"]["src/typed_workflow.rs"], blob("src/typed_workflow.rs"))
        self.assertEqual(sorted(policy["files"]), sorted(fixture.git(self.sdk, "ls-files", "--", "Cargo.toml", "src").split("\n")))
        self.assertEqual(result["payshInterface"]["src/lib.rs"], blob("crates/paysh-interface/src/lib.rs"))

    def test_records_published_tempo_sources_without_changing_native_release(self):
        result = self.manifest()
        tempo = result["sdk"]["tempoSdk"]
        self.assertEqual({k: v for k, v in tempo.items() if k != "files"}, {
            "path": "tempo-rust", "package": "allowit-tempo", "defaultFeatures": True, "features": []})
        commit = fixture.git(self.sdk, "rev-parse", "HEAD")
        blobs = provenance.native_sdk.crate_blobs(self.sdk, commit, "tempo-rust")
        self.assertEqual(tempo["files"], {name: provenance.native_sdk.digest(raw) for name, raw in blobs.items()})
        self.assertTrue({"Cargo.toml", "Cargo.lock", "src/lib.rs"}.issubset(tempo["files"]))
        release = json.loads((self.sdk / "native-rust/src/release.json").read_text())
        self.assertEqual(result["nativeRelease"], {key: release[key] for key in ["contractRevision", "sourceBundle", "artifacts"]})

    def test_refuses_tempo_source_change_committed_and_repinned(self):
        path = self.sdk / "tempo-rust/src/lib.rs"
        path.write_text(path.read_text() + "\n// changed verifier\n")
        fixture.commit(self.sdk, "Tempo source drift")
        fixture.repin(self.repo)
        with self.assertRaisesRegex(ValueError, "SDK Tempo crate differs from its pin: src/lib.rs"):
            self.manifest()

    def test_refuses_hidden_tempo_source_and_lockfile_changes(self):
        for name in ["tempo-rust/src/lib.rs", "tempo-rust/Cargo.lock"]:
            original = (self.sdk / name).read_bytes()
            for flag in ["--skip-worktree", "--assume-unchanged"]:
                with self.subTest(name=name, flag=flag):
                    fixture.hide(self.repo, name, original + b"\n// hidden\n", flag)
                    for action in [self.manifest, lambda: provenance.native_sdk.describe(self.repo)]:
                        with self.assertRaisesRegex(ValueError, "checkout differs from its pinned commit"):
                            action()
                    fixture.git(self.sdk, "update-index", flag.replace("--", "--no-", 1), "--", name)
                    (self.sdk / name).write_bytes(original)
        self.manifest()

    def test_refuses_tempo_identity_missing_metadata_and_hash_drift(self):
        changes = [lambda v: v.pop("tempoSdk"), lambda v: v["tempoSdk"].update(package="other-package"),
                   lambda v: v["tempoSdk"].update(path="../other"), lambda v: v["tempoSdk"].update(features=["compiler"]),
                   lambda v: v["tempoSdk"].update(defaultFeatures=False), lambda v: v["tempoSdk"].update(defaultFeatures=1)]
        for change in changes:
            with self.subTest(change=change):
                original = (self.repo / "vendor/native-sdk.json").read_text()
                self.metadata(change)
                with self.assertRaisesRegex(ValueError, "Tempo crate identity"):
                    self.manifest()
                (self.repo / "vendor/native-sdk.json").write_text(original)
                fixture.commit(self.repo, "restore Tempo identity")
        self.metadata(lambda v: v["tempoSdk"]["files"].update({"src/lib.rs": "0" * 64}))
        with self.assertRaisesRegex(ValueError, "Tempo crate differs from its pin"):
            self.manifest()

    def test_refuses_tempo_dependency_alias_path_and_features(self):
        path = self.repo / "Cargo.toml"
        original = path.read_text()
        expected = provenance.native_sdk.TEMPO_DEPENDENCY
        self.assertIn(expected, original)
        for replacement in [expected.replace("tempo-rust", "../other"), expected.replace("allowit-tempo =", "other-tempo ="),
                            expected.replace(" }", ', features = ["compiler"] }'), ""]:
            with self.subTest(replacement=replacement):
                path.write_text(original.replace(expected, replacement))
                with self.assertRaisesRegex(ValueError, "Cargo must build the SDK from its submodule"):
                    provenance.native_sdk.verify(self.repo)
        path.write_text(original)
        path.write_text(original + '\n[features]\nextra = ["allowit-tempo/compiler"]\n')
        with self.assertRaisesRegex(ValueError, "Cargo must build the SDK from its submodule"):
            provenance.native_sdk.verify(self.repo)

    def test_refuses_unrecorded_tempo_build_and_discovery_inputs(self):
        for name in ["build.rs", "src/injected.rs", ".cargo/config.toml"]:
            with self.subTest(name=name):
                relative = "tempo-rust/" + name
                fixture.exclude(self.repo, "/" + relative)
                path = self.sdk / relative
                path.parent.mkdir(exist_ok=True)
                path.write_text("fn main() {}\n")
                with self.assertRaisesRegex(ValueError, "submodule must be clean"):
                    self.manifest()
                with patch.object(provenance.native_sdk, "checkout", lambda root: root / fixture.SDK):
                    with self.assertRaisesRegex(ValueError, "build script" if name == "build.rs" else "Tempo crate file set"):
                        provenance.native_sdk.verify(self.repo)
                path.unlink()
        self.manifest()

    def test_refuses_tempo_library_symlink_hidden_from_status(self):
        name = "tempo-rust/src/lib.rs"
        fixture.git(self.sdk, "update-index", "--skip-worktree", "--", name)
        path = self.sdk / name
        path.unlink()
        path.symlink_to(self.sdk / "native-rust/src/lib.rs")
        self.assertEqual(fixture.git(self.sdk, "status", "--porcelain", "--untracked-files=all", "--ignored"), "")
        with self.assertRaisesRegex(ValueError, "regular files"):
            self.manifest()

    def test_release_provenance_cannot_use_local_tempo_review(self):
        with patch.dict(os.environ, {"ALLOWIT_TEMPO_REVIEW_MANIFEST": str(Path(self.tmp.name) / "review.json")}):
            with self.assertRaisesRegex(ValueError, "release provenance"):
                self.manifest()

    def test_refuses_policy_sdk_change_committed_and_repinned(self):
        typed = self.sdk / "src/typed_workflow.rs"
        typed.write_text(typed.read_text() + "\n// drift\n")
        fixture.commit(self.sdk, "typed drift")
        fixture.repin(self.repo)
        with self.assertRaisesRegex(ValueError, "SDK policy crate differs from its pin: src/typed_workflow.rs"):
            self.manifest()

    def test_refuses_hidden_policy_sdk_source_change(self):
        name = "src/typed_workflow.rs"
        fixture.hide(self.repo, name, (self.sdk / name).read_bytes() + b"// hidden\n")
        for action in [self.manifest, lambda: provenance.native_sdk.describe(self.repo)]:
            with self.assertRaisesRegex(ValueError, "checkout differs from its pinned commit: src/typed_workflow.rs"):
                action()

    def test_refuses_policy_sdk_build_script_and_extra_source(self):
        for name in ["build.rs", "src/injected.rs"]:
            with self.subTest(name=name):
                fixture.exclude(self.repo, "/" + name)
                (self.sdk / name).write_text("fn main() {}\n")
                with self.assertRaisesRegex(ValueError, "submodule must be clean"):
                    self.manifest()
                with patch.object(provenance.native_sdk, "checkout", lambda root: root / fixture.SDK):
                    with self.assertRaisesRegex(ValueError, "build script" if name == "build.rs" else "policy crate file set"):
                        provenance.native_sdk.verify(self.repo)
                (self.sdk / name).unlink()
        self.manifest()

    def test_refuses_policy_sdk_identity_or_dependency_drift(self):
        for change in [lambda v: v["policySdk"].update(features=["std", "typed-workflow", "compiler"]), lambda v: v["policySdk"].update(features=["std"]), lambda v: v["policySdk"].update(defaultFeatures=True), lambda v: v.pop("policySdk")]:
            with self.subTest():
                original = (self.repo / "vendor/native-sdk.json").read_text()
                self.metadata(change)
                with self.assertRaisesRegex(ValueError, "policy crate identity"):
                    self.manifest()
                (self.repo / "vendor/native-sdk.json").write_text(original)
                fixture.commit(self.repo, "restore")
        manifest = self.repo / "Cargo.toml"
        original = manifest.read_text()
        for old, new in [('default-features = false', 'default-features = true'), ('features = ["std", "typed-workflow"]', 'features = ["std", "typed-workflow", "compiler"]'), ('features = ["std", "typed-workflow"]', 'features = ["std"]'), ('repos/AllowIt-hq--allowit-sdk", default', '../paysh-policy-sdk", default')]:
            with self.subTest(new=new):
                self.assertIn(old, original)
                manifest.write_text(original.replace(old, new, 1))
                with self.assertRaisesRegex(ValueError, "Cargo must build the SDK from its submodule"):
                    provenance.native_sdk.verify(self.repo)
        for extra in ['\n[features]\nfull = ["allowit-policy-sdk/compiler"]\n', '\n[dev-dependencies]\nsdk-compiler = { package = "allowit-sdk", path = "repos/AllowIt-hq--allowit-sdk", features = ["compiler"] }\n']:
            with self.subTest(extra=extra):
                manifest.write_text(original + extra)
                with self.assertRaisesRegex(ValueError, "Cargo must build the SDK from its submodule"):
                    provenance.native_sdk.verify(self.repo)
        manifest.write_text(original)
        provenance.native_sdk.verify(self.repo)

    def test_refuses_paysh_interface_change_or_extra_file(self):
        lib = self.sdk / "crates/paysh-interface/src/lib.rs"
        fixture.hide(self.repo, "crates/paysh-interface/src/lib.rs", lib.read_bytes() + b"// hidden\n")
        with self.assertRaisesRegex(ValueError, "checkout differs from its pinned commit: src/lib.rs"):
            self.manifest()
        fixture.git(self.sdk, "update-index", "--no-skip-worktree", "--", "crates/paysh-interface/src/lib.rs")
        fixture.git(self.sdk, "checkout", "-q", "--", "crates/paysh-interface/src/lib.rs")
        fixture.exclude(self.repo, "/crates/paysh-interface/build.rs")
        (self.sdk / "crates/paysh-interface/build.rs").write_text("fn main() {}\n")
        with patch.object(provenance.native_sdk, "checkout", lambda root: root / fixture.SDK):
            with self.assertRaisesRegex(ValueError, "PaySH interface file set"):
                provenance.native_sdk.verify(self.repo)
        (self.sdk / "crates/paysh-interface/build.rs").unlink()
        lib.write_text(lib.read_text() + "\n// drift\n")
        fixture.commit(self.sdk, "interface drift")
        fixture.repin(self.repo)
        with self.assertRaisesRegex(ValueError, "SDK PaySH interface differs from its pin: src/lib.rs"):
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
        with self.assertRaisesRegex(ValueError, "submodule must be clean"):
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

    def discovery(self):
        return provenance.native_sdk.discovery(self.sdk, fixture.git(self.sdk, "rev-parse", "HEAD"))

    def test_refuses_ignored_sdk_root_cargo_config(self):
        self.assertFalse(os.path.lexists(self.sdk / ".cargo"))
        fixture.exclude(self.repo, "/.cargo/")
        config = self.sdk / ".cargo/config.toml"
        config.parent.mkdir()
        config.write_text('[build]\nrustflags = ["--cfg", "injected"]\n')
        self.assertEqual(fixture.git(self.sdk, "status", "--porcelain", "--untracked-files=all"), "")
        for action in [self.manifest, lambda: provenance.native_sdk.describe(self.repo)]:
            with self.assertRaisesRegex(ValueError, "submodule must be clean"):
                action()
        with self.assertRaisesRegex(ValueError, "Cargo discovery file set"):
            self.discovery()

    def test_refuses_sdk_root_cargo_config_symlink(self):
        target = Path(self.tmp.name) / "config"
        target.mkdir()
        (target / "config.toml").write_text('[build]\nrustflags = ["--cfg", "injected"]\n')
        fixture.exclude(self.repo, "/.cargo")
        (self.sdk / ".cargo").symlink_to(target, target_is_directory=True)
        self.assertEqual(fixture.git(self.sdk, "status", "--porcelain", "--untracked-files=all"), "")
        with self.assertRaisesRegex(ValueError, "submodule must be clean"):
            self.manifest()
        with self.assertRaisesRegex(ValueError, "regular file or directory: .cargo"):
            self.discovery()

    def test_refuses_hidden_sdk_workspace_manifest(self):
        original = (self.sdk / "Cargo.toml").read_bytes()
        workspace = original + b'\n[workspace]\nmembers = ["native-rust"]\n'
        for flag in ["--skip-worktree", "--assume-unchanged"]:
            with self.subTest(flag=flag):
                fixture.hide(self.repo, "Cargo.toml", workspace, flag)
                with self.assertRaisesRegex(ValueError, "checkout differs from its pinned commit: Cargo.toml"):
                    self.manifest()
                fixture.git(self.sdk, "update-index", flag.replace("--", "--no-", 1), "--", "Cargo.toml")
                (self.sdk / "Cargo.toml").write_bytes(original)
        self.manifest()

    def test_refuses_hidden_sdk_lockfile_change_or_removal(self):
        self.assertEqual(fixture.git(self.sdk, "ls-files", "--", "Cargo.lock"), "Cargo.lock")
        lock = self.sdk / "Cargo.lock"
        original = lock.read_bytes()
        fixture.hide(self.repo, "Cargo.lock", original + b"\n# hidden\n", "--assume-unchanged")
        with self.assertRaisesRegex(ValueError, "checkout differs from its pinned commit: Cargo.lock"):
            self.manifest()
        fixture.git(self.sdk, "update-index", "--no-assume-unchanged", "--", "Cargo.lock")
        lock.write_bytes(original)
        fixture.git(self.sdk, "update-index", "--skip-worktree", "--", "Cargo.lock")
        lock.unlink()
        self.assertEqual(fixture.git(self.sdk, "status", "--porcelain", "--untracked-files=all", "--ignored"), "")
        with self.assertRaisesRegex(ValueError, "Cargo discovery file set"):
            self.manifest()

    def test_pin_and_describe_refuse_hidden_sdk_workspace_manifest(self):
        metadata = (self.repo / "vendor/native-sdk.json").read_bytes()
        gitlink = self.git("ls-files", "--stage", "--", fixture.SDK)
        workspace = (self.sdk / "Cargo.toml").read_bytes() + b'\n[workspace]\nmembers = ["native-rust"]\n'
        fixture.hide(self.repo, "Cargo.toml", workspace)
        for action in [provenance.native_sdk.describe, provenance.native_sdk.pin]:
            with self.subTest(action=action.__name__):
                with self.assertRaisesRegex(ValueError, "checkout differs from its pinned commit: Cargo.toml"):
                    action(self.repo)
        self.assertEqual((self.repo / "vendor/native-sdk.json").read_bytes(), metadata)
        self.assertEqual(self.git("ls-files", "--stage", "--", fixture.SDK), gitlink)
        self.assertEqual(self.git("status", "--porcelain"), "")

    def test_refuses_hidden_tracked_sdk_cargo_config(self):
        # Fixture-local SDK commit with a tracked config; the production pin is unchanged.
        config = self.sdk / ".cargo/config.toml"
        config.parent.mkdir()
        config.write_text("[net]\noffline = true\n")
        fixture.commit(self.sdk, "cargo config")
        fixture.repin(self.repo)
        recorded = json.loads((self.repo / "vendor/native-sdk.json").read_text())
        self.assertEqual(self.manifest()["sdk"], recorded)
        self.assertEqual(provenance.native_sdk.describe(self.repo), recorded)

        fixture.hide(self.repo, ".cargo/config.toml", b'[build]\nrustflags = ["--cfg", "hidden"]\n')
        for action in [self.manifest, lambda: provenance.native_sdk.describe(self.repo)]:
            with self.assertRaisesRegex(ValueError, "checkout differs from its pinned commit: .cargo/config.toml"):
                action()

        # Hidden removal of the tracked config changes the discovered file set.
        config.unlink()
        self.assertEqual(fixture.git(self.sdk, "status", "--porcelain", "--untracked-files=all", "--ignored"), "")
        for action in [self.manifest, lambda: provenance.native_sdk.pin(self.repo)]:
            with self.assertRaisesRegex(ValueError, "Cargo discovery file set"):
                action()
        fixture.git(self.sdk, "update-index", "--no-skip-worktree", "--", ".cargo/config.toml")
        fixture.git(self.sdk, "checkout", "-q", "--", ".cargo/config.toml")
        self.assertEqual(self.manifest()["sdk"], recorded)

        # An ignored nested config is an extra discovery input.
        fixture.exclude(self.repo, "/.cargo/nested/")
        nested = self.sdk / ".cargo/nested/config.toml"
        nested.parent.mkdir()
        nested.write_text('[build]\nrustflags = ["--cfg", "nested"]\n')
        self.assertEqual(fixture.git(self.sdk, "status", "--porcelain", "--untracked-files=all"), "")
        with self.assertRaisesRegex(ValueError, "submodule must be clean"):
            self.manifest()
        with self.assertRaisesRegex(ValueError, "Cargo discovery file set"):
            self.discovery()

    def test_accepts_tracked_sdk_cargo_config_in_autocrlf_checkout(self):
        config = self.sdk / ".cargo/config.toml"
        config.parent.mkdir()
        config.write_text("[net]\noffline = true\n")
        fixture.commit(self.sdk, "cargo config")
        fixture.repin(self.repo)
        fixture.autocrlf(self.repo)
        self.assertIn(b"\r\n", config.read_bytes())
        self.assertEqual(self.manifest()["sdk"], json.loads((self.repo / "vendor/native-sdk.json").read_text()))

    def test_pin_rerecords_unchanged_sdk_bytes(self):
        path = self.repo / "vendor/native-sdk.json"
        recorded = json.loads(path.read_text())
        self.assertEqual(provenance.native_sdk.describe(self.repo), recorded)
        fixture.autocrlf(self.repo)
        self.assertEqual(provenance.native_sdk.pin(self.repo), recorded)
        self.assertEqual(json.loads(path.read_text()), recorded)

    def test_inventory_refuses_ignored_sdk_build_script_without_status(self):
        fixture.exclude(self.repo, "/native-rust/build.rs")
        (self.sdk / "native-rust/build.rs").write_text("fn main() {}\n")
        self.assertIn("build.rs", provenance.native_sdk.inventory(self.sdk / "native-rust"))
        # The file-set layer still refuses it if the clean-status check were bypassed.
        with patch.object(provenance.native_sdk, "checkout", lambda root: root / fixture.SDK):
            with self.assertRaisesRegex(ValueError, "SDK source file set differs from its pin"):
                provenance.native_sdk.verify(self.repo)
            with self.assertRaisesRegex(ValueError, "SDK source file set differs from its commit"):
                provenance.native_sdk.describe(self.repo)

    def test_refuses_ignored_intermediate_cargo_inputs(self):
        self.assertEqual(provenance.native_sdk.INTERMEDIATE, ("repos",))
        metadata = (self.repo / "vendor/native-sdk.json").read_bytes()
        gitlink = self.git("ls-files", "--stage", "--", fixture.SDK)
        sdk = provenance.native_sdk
        actions = [self.manifest, lambda: sdk.verify(self.repo), lambda: sdk.describe(self.repo), lambda: sdk.pin(self.repo)]
        for name in ["repos/Cargo.toml", "repos/Cargo.lock", "repos/.cargo/config.toml"]:
            with self.subTest(name=name):
                fixture.exclude(self.repo, "/" + name, within="")
                path = self.repo / name
                path.parent.mkdir(exist_ok=True)
                path.write_text('[workspace]\nmembers = ["AllowIt-hq--allowit-sdk/native-rust"]\n')
                self.assertEqual(self.git("status", "--porcelain", "--untracked-files=all"), "")
                for action in actions:
                    with self.assertRaisesRegex(ValueError, "CLI Cargo discovery file set differs from its committed HEAD"):
                        action()
                self.assertEqual((self.repo / "vendor/native-sdk.json").read_bytes(), metadata)
                self.assertEqual(self.git("ls-files", "--stage", "--", fixture.SDK), gitlink)
                path.unlink()
        self.manifest()

    def test_refuses_intermediate_cargo_config_symlink(self):
        target = Path(self.tmp.name) / "config"
        target.mkdir()
        (target / "config.toml").write_text(INJECTED)
        fixture.exclude(self.repo, "/repos/.cargo", within="")
        (self.repo / "repos/.cargo").symlink_to(target, target_is_directory=True)
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=all"), "")
        for action in [self.manifest, lambda: provenance.native_sdk.verify(self.repo)]:
            with self.assertRaisesRegex(ValueError, "regular file or directory: repos/.cargo"):
                action()

    def test_binds_committed_intermediate_cargo_config(self):
        # Fixture-only: a committed intermediate config is accepted only at its HEAD bytes.
        config = self.repo / "repos/.cargo/config.toml"
        config.parent.mkdir()
        config.write_text("[net]\noffline = true\n")
        fixture.commit(self.repo, "intermediate config")
        self.assertEqual(provenance.native_sdk.verify(self.repo)["commit"], fixture.git(self.sdk, "rev-parse", "HEAD"))
        self.manifest()
        fixture.hide(self.repo, "repos/.cargo/config.toml", INJECTED.encode(), within="")
        for action in [self.manifest, lambda: provenance.native_sdk.verify(self.repo), lambda: provenance.native_sdk.describe(self.repo)]:
            with self.assertRaisesRegex(ValueError, "CLI checkout differs from its committed HEAD: repos/.cargo/config.toml"):
                action()

    def test_accepts_committed_root_cargo_inputs_in_autocrlf_checkout(self):
        self.assertEqual(sorted(self.git("ls-files", "--", *ROOT_CARGO).split("\n")), sorted(ROOT_CARGO))
        self.git("config", "core.autocrlf", "true")
        for name in ROOT_CARGO:
            (self.repo / name).unlink()
        self.git("checkout", "-q", "--", *ROOT_CARGO)
        self.assertIn(b"\r\n", (self.repo / ".cargo/config.toml").read_bytes())
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=all"), "")
        self.assertEqual(self.manifest()["cli"]["commit"], self.git("rev-parse", "HEAD"))

    def test_sdk_verify_allows_root_cargo_development_that_provenance_refuses(self):
        for name in ROOT_CARGO:
            with (self.repo / name).open("a") as handle:
                handle.write("\n# local development\n")
        commit = fixture.git(self.sdk, "rev-parse", "HEAD")
        self.assertEqual(provenance.native_sdk.verify(self.repo)["commit"], commit)
        self.assertEqual(provenance.native_sdk.describe(self.repo)["commit"], commit)
        with self.assertRaisesRegex(ValueError, "committed"):
            self.manifest()

    def test_refuses_ignored_root_cargo_config_despite_clean_status(self):
        for name in [".cargo/config", ".cargo/nested/config.toml"]:
            with self.subTest(name=name):
                fixture.exclude(self.repo, "/" + name, within="")
                path = self.repo / name
                path.parent.mkdir(exist_ok=True)
                path.write_text(INJECTED)
                self.assertEqual(self.git("status", "--porcelain", "--untracked-files=all"), "")
                provenance.native_sdk.verify(self.repo)
                with self.assertRaisesRegex(ValueError, "CLI Cargo discovery file set differs from its committed HEAD"):
                    self.manifest()
                path.unlink()
        self.manifest()

    def test_refuses_hidden_tracked_root_cargo_inputs(self):
        for name in ROOT_CARGO:
            original = (self.repo / name).read_bytes()
            for flag in ["--skip-worktree", "--assume-unchanged"]:
                with self.subTest(name=name, flag=flag):
                    fixture.hide(self.repo, name, original + b"\n# hidden\n", flag, within="")
                    provenance.native_sdk.verify(self.repo)
                    with self.assertRaisesRegex(ValueError, "CLI checkout differs from its committed HEAD: " + re.escape(name)):
                        self.manifest()
                    self.git("update-index", flag.replace("--", "--no-", 1), "--", name)
                    (self.repo / name).write_bytes(original)
        # Hidden removal of the tracked root config changes the discovered file set.
        config = ".cargo/config.toml"
        self.git("update-index", "--skip-worktree", "--", config)
        (self.repo / config).unlink()
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=all"), "")
        with self.assertRaisesRegex(ValueError, "CLI Cargo discovery file set differs from its committed HEAD"):
            self.manifest()
        self.git("update-index", "--no-skip-worktree", "--", config)
        self.git("checkout", "-q", "--", config)
        self.manifest()

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


class ResolvedTests(unittest.TestCase):
    """Cargo's actual resolution in the real checkout, not only the bound files."""

    def test_real_checkout_resolves_pinned_submodule_crates(self):
        provenance.native_sdk.resolved(fixture.ROOT)

    def test_refuses_cargo_paths_override_from_config(self):
        sdk = fixture.ROOT / fixture.SDK
        with tempfile.TemporaryDirectory() as tmp:
            # Same names and versions outside the submodule, as an untrusted parent config could name.
            for name in ["native-rust", "crates/paysh-interface", "tempo-rust"]:
                shutil.copytree(sdk / name, Path(tmp) / name, ignore=shutil.ignore_patterns("target"))
            for crate, package in [("native-rust", "allowit-native"), ("crates/paysh-interface", "allowit-paysh-interface"), ("tempo-rust", "allowit-tempo")]:
                with self.subTest(package=package):
                    with self.assertRaisesRegex(ValueError, "does not build " + package):
                        provenance.native_sdk.resolved(fixture.ROOT, f'paths=["{Path(tmp) / crate}"]')

    def mutated(self, change):
        real = provenance.native_sdk.subprocess.run
        def run(args, **options):
            result = real(args, **options)
            if args[:2] == ["cargo", "metadata"]:
                value = json.loads(result.stdout); change(value)
                result.stdout = json.dumps(value).encode()
            return result
        return patch.object(provenance.native_sdk.subprocess, "run", run)

    def test_refuses_unpinned_features_build_scripts_and_links(self):
        def feature(value):
            for node in value["resolve"]["nodes"]:
                if "#allowit-sdk@" in node["id"]:
                    node["features"].append("compiler")
        def missing(value):
            for node in value["resolve"]["nodes"]:
                if "#allowit-sdk@" in node["id"]:
                    node["features"].remove("typed-workflow")
        def build(value):
            package = next(p for p in value["packages"] if p["name"] == "allowit-native")
            package["targets"].append({"kind": ["custom-build"], "src_path": "/tmp/build.rs"})
        def links(value):
            next(p for p in value["packages"] if p["name"] == "allowit-sdk")["links"] = "injected"
        def library(value):
            package = next(p for p in value["packages"] if p["name"] == "allowit-sdk")
            next(t for t in package["targets"] if "rlib" in t["kind"])["src_path"] = "/tmp/lib.rs"
        for change, message in [(feature, "unpinned features of allowit-sdk"), (missing, "unpinned features of allowit-sdk"), (build, "does not build allowit-native"), (links, "does not build allowit-sdk"), (library, "does not build allowit-sdk")]:
            with self.subTest(change=change.__name__), self.mutated(change):
                with self.assertRaisesRegex(ValueError, message):
                    provenance.native_sdk.resolved(fixture.ROOT)

    def test_refuses_tempo_resolution_identity_and_execution_inputs(self):
        def tempo(value):
            return next(p for p in value["packages"] if p["name"] == "allowit-tempo")
        def feature(value):
            package = tempo(value)
            next(n for n in value["resolve"]["nodes"] if n["id"] == package["id"])["features"].append("injected")
        def build(value):
            tempo(value)["targets"].append({"kind": ["custom-build"], "src_path": "/tmp/build.rs"})
        def links(value):
            tempo(value)["links"] = "injected"
        def manifest(value):
            tempo(value)["manifest_path"] = "/tmp/Cargo.toml"
        def library(value):
            next(t for t in tempo(value)["targets"] if {"lib", "rlib"} & set(t["kind"]))["src_path"] = "/tmp/lib.rs"
        for change in [feature, build, links, manifest, library]:
            with self.subTest(change=change.__name__), self.mutated(change):
                with self.assertRaisesRegex(ValueError, "unpinned features of allowit-tempo" if change == feature else "does not build allowit-tempo"):
                    provenance.native_sdk.resolved(fixture.ROOT)


if __name__ == "__main__":
    unittest.main()
