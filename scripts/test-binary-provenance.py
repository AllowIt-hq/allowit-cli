#!/usr/bin/env python3
"""Provenance contract tests; no network or compiled binaries required."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("provenance", Path(__file__).with_name("binary-provenance.py"))
provenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provenance)


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        source = Path(__file__).resolve().parent.parent
        shutil.copytree(source / "vendor", self.repo / "vendor")
        shutil.copyfile(source / "Cargo.toml", self.repo / "Cargo.toml")
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
        self.binary = Path(self.tmp.name) / "allowit"
        self.binary.write_bytes(b"\xcf\xfa\xed\xfe" + (0x100000C).to_bytes(4, "little") + b"synthetic-test-only")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], text=True).strip()

    def test_exact_binary_source_and_sdk_release_identity(self):
        result = provenance.manifest(self.repo, self.binary, "aarch64-apple-darwin")
        self.assertEqual(result["cli"]["commit"], self.git("rev-parse", "HEAD"))
        self.assertEqual(result["cli"]["sourceTree"], self.git("rev-parse", "HEAD^{tree}"))
        self.assertEqual(result["binary"]["sha256"], hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.assertEqual(result["sdk"], json.loads((self.repo / "vendor/native-sdk.json").read_text()))
        self.assertEqual(result["nativeRelease"]["sourceBundle"], json.loads((self.repo / "vendor/allowit-native/src/release.json").read_text())["sourceBundle"])
        self.assertNotIn("sources", result["nativeRelease"])

    def test_refuses_uncommitted_source(self):
        with (self.repo / "Cargo.toml").open("a") as handle:
            handle.write("\n# edited\n")
        with self.assertRaisesRegex(ValueError, "committed"):
            provenance.manifest(self.repo, self.binary, "aarch64-apple-darwin")

    def test_refuses_committed_sdk_drift(self):
        with (self.repo / "vendor/allowit-native/src/lib.rs").open("a") as handle:
            handle.write("\n// drift\n")
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "drift")
        with self.assertRaisesRegex(ValueError, "snapshot differs"):
            provenance.manifest(self.repo, self.binary, "aarch64-apple-darwin")

    def test_refuses_wrong_binary_architecture(self):
        with self.assertRaisesRegex(ValueError, "architecture"):
            provenance.manifest(self.repo, self.binary, "x86_64-apple-darwin")
        with self.assertRaisesRegex(ValueError, "format"):
            provenance.manifest(self.repo, self.binary, "x86_64-unknown-linux-musl")


if __name__ == "__main__":
    unittest.main()
