#!/usr/bin/env python3
"""Adversarial vendor graph checks using local immutable Git fixture sources."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).parent

def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

helper = load('helper', 'sync-native-sdk.py')
graph = load('graph', 'vendor-graph.py')


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), '-c', 'user.name=Fixture',
        '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', *args],
        env=helper.environment(), text=True, stderr=subprocess.DEVNULL).strip()


def write(root, name, text):
    file = root / name
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(text)


class Sources(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repos = {}
        for url in graph.CANONICAL:
            repo = self.root / url.rsplit('/', 1)[1]
            repo.mkdir()
            git(repo, 'init', '-q')
            write(repo, 'LICENSE', 'MIT fixture\n')
            for name, (owner, directory) in graph.PACKAGES.items():
                if owner == url:
                    write(repo, str(Path(directory, 'Cargo.toml')), f'[package]\nname="{name}"\nversion="0.1.0"\nedition="2024"\n')
                    write(repo, str(Path(directory, 'src/lib.rs')), '// fixture\n')
            git(repo, 'add', '.')
            git(repo, 'commit', '-qm', 'fixture')
            self.repos[url] = repo
        self.sdk = self.repos[helper.URL]
        self.commit = git(self.sdk, 'rev-parse', 'HEAD')
        self.cli = self.root / 'cli'
        self.cli.mkdir()
        self.packages = [{'id':'cli', 'name':'allowit-cli', 'source':None,
                          'manifest_path':str(self.cli / 'Cargo.toml')}]
        self.nodes = [{'id':'cli', 'features':[], 'deps':[self.edge('allowit_client', 'allowit-client')]}]
        for name, (url, directory) in graph.PACKAGES.items():
            repo = self.repos[url]
            commit = git(repo, 'rev-parse', 'HEAD')
            crate = repo / directory
            source = None if url == helper.URL and name != 'allowit-client-core' else f'git+{url}?rev={commit}#{commit}'
            self.packages.append({'id':name, 'name':name, 'version':'0.1.0', 'source':source,
                'manifest_path':str(crate / 'Cargo.toml'), 'links':None,
                'targets':[{'kind':['lib'], 'src_path':str(crate / 'src/lib.rs')}]})
            self.nodes.append({'id':name, 'features':[], 'deps':[]})
        self.value = {'packages':self.packages, 'resolve':{'nodes':self.nodes}}
        metadata = patch.object(graph, 'metadata', lambda *args:self.value)
        metadata.start();self.addCleanup(metadata.stop)
        checkout = patch.object(helper, 'checkout', lambda root:self.sdk)
        checkout.start();self.addCleanup(checkout.stop)

    @staticmethod
    def edge(name, package):
        return {'name':name, 'pkg':package, 'dep_kinds':[{'kind':None}]}

    def describe(self):
        return graph.graph(self.cli, helper)

    def package(self, name):
        return next(p for p in self.packages if p['name'] == name)

    def test_binds_all_sources_features_and_notices(self):
        self.nodes[1]['features'] = ['z', 'a']
        result = self.describe()
        self.assertEqual({p['package'] for p in result}, set(graph.PACKAGES))
        for p in result:
            self.assertIn('Cargo.toml', p['files'])
            self.assertIn('src/lib.rs', p['files'])
            self.assertIn('LICENSE', p['licenses'])
            self.assertNotIn(str(self.root), json.dumps(p))
        self.assertEqual(next(p for p in result if p['package']=='allowit-client')['features'], ['a','z'])

    def test_accepts_only_regular_cargo_completion_marker(self):
        repo=self.repos[graph.PACKAGES['allowit-tempo'][0]]
        write(repo,'.cargo-ok','')
        self.describe()
        (repo/'.cargo-ok').unlink()
        (repo/'.cargo-ok').symlink_to(repo/'LICENSE')
        with self.assertRaisesRegex(ValueError, 'clean'):
            self.describe()

    def test_rejects_different_checkout_head(self):
        repo=self.repos[graph.PACKAGES['allowit-tempo'][0]]
        write(repo,'README.md','new revision\n')
        git(repo,'add','README.md');git(repo,'commit','-qm','unreviewed')
        with self.assertRaisesRegex(ValueError, 'exact Git source'):
            self.describe()

    def test_rejects_extra_or_duplicate_first_party_package(self):
        for p in [copy.deepcopy(self.packages[-1]), {'id':'extra','name':'allowit-foreign','source':None}]:
            self.packages.append(p)
            with self.assertRaisesRegex(ValueError, 'unexpected first-party'):
                self.describe()
            self.packages.pop()

    def test_rejects_direct_cli_vendor_dependency(self):
        self.nodes[0]['deps'].append(self.edge('tempo','allowit-tempo'))
        with self.assertRaisesRegex(ValueError, 'only on the SDK'):
            self.describe()

    def test_rejects_vendor_to_facade_dependency(self):
        next(n for n in self.nodes if n['id']=='allowit-tempo')['deps'].append(self.edge('client','allowit-client'))
        with self.assertRaisesRegex(ValueError, 'must not depend on the facade'):
            self.describe()

    def test_rejects_core_to_vendor_dependency(self):
        next(n for n in self.nodes if n['id']=='allowit-sdk')['deps'].append(self.edge('tempo','allowit-tempo'))
        with self.assertRaisesRegex(ValueError, 'Core packages'):
            self.describe()

    def test_rejects_foreign_git_and_mutable_revisions(self):
        p = self.package('allowit-tempo')
        for source in ['git+https://example.invalid/repo?rev='+'a'*40+'#'+'a'*40,
                'git+https://github.com/AllowIt-hq/allowit-contracts-tempo.git?branch=main#'+'a'*40,
                'git+https://github.com/AllowIt-hq/allowit-contracts-tempo.git?rev=main#'+'a'*40]:
            p['source'] = source
            with self.assertRaises(ValueError):self.describe()

    def test_rejects_local_vendor_override(self):
        self.package('allowit-tempo')['source'] = None
        with self.assertRaisesRegex(ValueError, 'unexpected local'):
            self.describe()

    def test_rejects_source_redirection_or_extra_target(self):
        p=self.package('allowit-tempo')
        p['targets'][0]['src_path']=str(self.root/'foreign.rs')
        with self.assertRaisesRegex(ValueError, 'pinned vendor source'):
            self.describe()

    def test_rejects_custom_build_and_links(self):
        p=self.package('allowit-tempo')
        p['targets'].append({'kind':['custom-build'],'src_path':'build.rs'})
        with self.assertRaises(ValueError):self.describe()
        p['targets'].pop();p['links']='native-library'
        with self.assertRaises(ValueError):self.describe()

    def test_rejects_hidden_source_drift(self):
        repo=self.repos[graph.PACKAGES['allowit-tempo'][0]]
        write(repo,'rust/src/lib.rs','// modified\n')
        git(repo,'update-index','--assume-unchanged','rust/src/lib.rs')
        with self.assertRaisesRegex(ValueError, 'checkout differs'):
            self.describe()

    def test_rejects_ignored_build_script(self):
        repo=self.repos[graph.PACKAGES['allowit-tempo'][0]]
        write(repo,'.git/info/exclude','rust/build.rs\n')
        write(repo,'rust/build.rs','fn main() {}\n')
        with self.assertRaisesRegex(ValueError, 'build script'):
            self.describe()

    def test_rejects_hidden_ancestor_cargo_configuration(self):
        repo=self.repos[graph.PACKAGES['allowit-tempo'][0]]
        write(repo,'.git/info/exclude','.cargo\n')
        write(repo,'.cargo/config.toml','[build]\nrustflags=["--cfg","foreign"]\n')
        with self.assertRaisesRegex(ValueError, 'discovery file set'):
            self.describe()

    def test_rejects_license_drift_hidden_from_status(self):
        repo=self.repos[graph.PACKAGES['allowit-tempo'][0]]
        write(repo,'LICENSE','changed\n')
        git(repo,'update-index','--skip-worktree','LICENSE')
        with self.assertRaisesRegex(ValueError, 'license checkout differs'):
            self.describe()

    def test_rejects_ignored_extra_source_file(self):
        repo=self.repos[graph.PACKAGES['allowit-tempo'][0]]
        write(repo,'.git/info/exclude','rust/src/extra.rs\n')
        write(repo,'rust/src/extra.rs','// injected\n')
        with self.assertRaisesRegex(ValueError, 'file set differs'):
            self.describe()


if __name__ == '__main__':unittest.main()
