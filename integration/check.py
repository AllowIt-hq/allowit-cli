#!/usr/bin/env python3
"""Run the real CLI against pinned Go gateways, without editing their checkout."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-repo", type=Path, required=True,
                        help="AllowIt-app clone containing the pinned commits")
    parser.add_argument("--backend", choices=["customer-workspace", "typed-skill-runtime"])
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    backends = json.loads((root / "integration/backends.json").read_text())
    with tempfile.TemporaryDirectory(prefix="allowit-cli-contract-") as directory:
        temp = Path(directory)
        binary = temp / "allowit"
        run(["go", "build", "-trimpath", "-o", str(binary), "./cmd/allowit"], cwd=root)
        for backend in backends:
            if args.backend and backend["name"] != args.backend:
                continue
            revision = backend["revision"]
            actual = subprocess.check_output(
                ["git", "-C", str(args.app_repo), "rev-parse", revision + "^{commit}"],
                text=True).strip()
            if actual != revision:
                raise RuntimeError("backend revision must be an exact commit")
            app = temp / backend["name"]
            app.mkdir()
            archive = subprocess.check_output(
                ["git", "-C", str(args.app_repo), "archive", revision,
                 "go.mod", "go.sum", "server"])
            run(["tar", "-xf", "-", "-C", str(app)], input=archive)
            manifest = json.loads((app / "server/policywasm/manifest.json").read_text())
            digest = hashlib.sha256((app / "server/policywasm/allowit_sdk.wasm").read_bytes()).hexdigest()
            if digest != manifest["sha256"]:
                raise RuntimeError("pinned SDK WASM hash mismatch")
            expected = set()
            for test in backend["tests"]:
                source = root / "integration/testdata" / test
                expected.update(re.findall(r"^func (TestAlignment\w+)\(", source.read_text(), re.MULTILINE))
                shutil.copyfile(source, app / "server/app" / ("alignment_" + test))
            if not expected:
                raise RuntimeError("no integration tests selected")
            # Test wallets, sessions and allowance/chain adapters are generated
            # by the backend test helpers. No service credentials are needed.
            env = os.environ.copy()
            env["ALLOWIT_ALIGNMENT_BINARY"] = str(binary)
            print(f"{backend['name']}: app {revision}, SDK {manifest['commit']}, WASM {digest}", flush=True)
            result = subprocess.run(
                ["go", "test", "-race", "-count=1", "-run", "^TestAlignment", "-json", "./server/app"],
                cwd=app, env=env, stdout=subprocess.PIPE, text=True)
            passed = set()
            for line in result.stdout.splitlines():
                event = json.loads(line)
                if event.get("Output"):
                    print(event["Output"], end="", flush=True)
                if event.get("Action") == "pass" and event.get("Test"):
                    passed.add(event["Test"])
            result.check_returncode()
            if expected - passed:
                raise RuntimeError("integration tests did not pass: " + ", ".join(sorted(expected - passed)))
            print(f"Verified {len(expected)} named integration cases.", flush=True)


if __name__ == "__main__":
    main()
