#!/usr/bin/env python3
"""Describe a CI-built native binary and its clean, pinned source checkout."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

TARGETS = {
    "x86_64-unknown-linux-musl": ("allowit-linux-amd64", b"\x7fELF", 62),
    "aarch64-apple-darwin": ("allowit-darwin-arm64", b"\xcf\xfa\xed\xfe", 0x100000C),
    "x86_64-apple-darwin": ("allowit-darwin-amd64", b"\xcf\xfa\xed\xfe", 0x1000007),
}


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def manifest(repo, binary, target):
    repo, binary = Path(repo).resolve(), Path(binary).resolve()
    if git(repo, "status", "--porcelain"):
        raise ValueError("Tracked source must be committed before recording provenance")
    asset, magic, cpu = TARGETS[target]
    raw = binary.read_bytes()
    if raw[:4] != magic:
        raise ValueError("Binary format does not match target")
    if magic == b"\x7fELF":
        if len(raw) < 20 or raw[4:6] != b"\x02\x01" or int.from_bytes(raw[18:20], "little") != cpu:
            raise ValueError("Binary architecture does not match target")
    elif len(raw) < 8 or int.from_bytes(raw[4:8], "little") != cpu:
        raise ValueError("Binary architecture does not match target")
    sdk = json.loads((repo / "vendor/native-sdk.json").read_text())
    if not re.fullmatch(r"[0-9a-f]{40}", sdk["commit"]):
        raise ValueError("SDK pin must be a full commit")
    tracked = {name.removeprefix("vendor/allowit-native/") for name in
               git(repo, "ls-files", "vendor/allowit-native").splitlines()}
    if set(sdk["files"]) != tracked or not {"Cargo.toml", "Cargo.lock", "src/lib.rs", "src/release.json"}.issubset(tracked):
        raise ValueError("SDK snapshot file set differs from its pin")
    for name, expected in sdk["files"].items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Invalid SDK snapshot path")
        source = repo / "vendor/allowit-native" / relative
        if source.is_symlink():
            raise ValueError("SDK source must be a regular snapshot file")
        if hashlib.sha256(source.read_bytes()).hexdigest() != expected:
            raise ValueError("SDK snapshot differs from its pin")
    for name, expected in sdk.get("licenses", {}).items():
        if name not in {"LICENSE", "THIRD_PARTY_NOTICES.md", "licenses/Aeneas-Apache-2.0.txt"}:
            raise ValueError("Invalid SDK license snapshot path")
        source = repo / "vendor/native-sdk-licenses" / name
        if source.is_symlink() or hashlib.sha256(source.read_bytes()).hexdigest() != expected:
            raise ValueError("SDK license snapshot differs from its pin")
    release = json.loads((repo / "vendor/allowit-native/src/release.json").read_text())
    version = re.search(r'^version = "([^"]+)"$', (repo / "Cargo.toml").read_text(), re.M)[1]
    value = {
        "schemaVersion": 1,
        "kind": "rust-native",
        "cli": {
            "repository": "https://github.com/AllowIt-hq/allowit-cli",
            "commit": git(repo, "rev-parse", "HEAD"),
            "sourceTree": git(repo, "rev-parse", "HEAD^{tree}"),
            "version": version,
        },
        "sdk": sdk,
        "binary": {
            "asset": asset, "target": target,
            "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
        },
        "nativeRelease": {
            key: release[key] for key in ["contractRevision", "sourceBundle", "artifacts"]
        },
    }
    run = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if run.isdigit() and attempt.isdigit() and os.environ.get("GITHUB_REPOSITORY", "").lower() == "allowit-hq/allowit-cli":
        value["build"] = {
            "githubRunURL": f"https://github.com/AllowIt-hq/allowit-cli/actions/runs/{run}",
            "runAttempt": int(attempt),
            "event": os.environ.get("GITHUB_EVENT_NAME", ""),
            "ref": os.environ.get("GITHUB_REF", ""),
            "sha": os.environ.get("GITHUB_SHA", ""),
        }
        if value["build"]["sha"] != value["cli"]["commit"]:
            raise ValueError("GitHub build revision differs from source HEAD")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(manifest(args.repo, args.binary, args.target), indent=2) + "\n")


if __name__ == "__main__":
    main()
