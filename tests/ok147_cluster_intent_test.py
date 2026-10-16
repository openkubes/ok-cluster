#!/usr/bin/env python3
"""Actual CLI -> owning local renderer; no cluster/API/credential operations."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / '.tools/bin/ok'


class IntentRenderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.input = self.home / 'cluster.yaml'
        self.input.write_bytes((ROOT / 'examples/ok-cli-cluster.yaml').read_bytes())
        self.output = self.home / 'new-render'
        self.marker = self.home / 'forbidden-tool-executed'
        bin_dir = self.home / 'bin'
        bin_dir.mkdir()
        for tool in ('kubectl', 'talosctl', 'clusterctl'):
            path = bin_dir / tool
            path.write_text('#!/bin/sh\ntouch "$FORBIDDEN_TOOL_MARKER"\nexit 91\n')
            path.chmod(0o700)
        self.env = {**os.environ, 'HOME': str(self.home), 'XDG_CONFIG_HOME': str(self.home / '.config'),
            'PATH': str(bin_dir) + os.pathsep + os.environ['PATH'], 'FORBIDDEN_TOOL_MARKER': str(self.marker),
            'PYTHONDONTWRITEBYTECODE': '1', 'KUBECONFIG': str(self.home / 'must-not-read')}

    def render(self, extra=()):
        return subprocess.run([str(BINARY), 'up', 'render', '--file', str(self.input),
            '--output', str(self.output), '--lifecycle-root', str(ROOT),
            '--ok-linux-path', str(ROOT.parent / 'ok-linux'), *extra],
            capture_output=True, text=True, env=self.env, cwd=self.home, timeout=20)

    def test_actual_owner_render_is_private_no_go_and_create_only(self):
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt['state'], 'RENDERED_NO_GO')
        for field in ('apiContacted', 'authorizationConsumed', 'mutationAllowed', 'runnerReady', 'collisionChecked', 'generatedHelpersExecuted'):
            self.assertIs(receipt[field], False)
        config = yaml.safe_load((self.output / 'my-cluster/cluster-config.yaml').read_text())
        self.assertEqual(config['name'], 'my-cluster')
        self.assertEqual(config['controlPlane']['replicas'], 1)
        self.assertEqual(config['workers']['replicas'], 1)
        self.assertEqual(config['workers']['disk'], '20Gi')
        self.assertEqual(config['infraClusterSecretRef']['namespace'], 'my-cluster')
        self.assertIn('goldenImage', config['os'])
        manifest = list(yaml.safe_load_all((self.output / 'my-cluster/cluster-base.yaml').read_text()))
        self.assertTrue(any(obj and obj.get('kind') == 'Cluster' for obj in manifest))
        for relative, digest in receipt['files'].items():
            path = self.output / relative
            self.assertEqual('sha256:' + hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        before = {str(p.relative_to(self.output)): p.read_bytes() for p in self.output.rglob('*') if p.is_file()}
        repeated = self.render()
        self.assertNotEqual(repeated.returncode, 0)
        self.assertEqual(before, {str(p.relative_to(self.output)): p.read_bytes() for p in self.output.rglob('*') if p.is_file()})
        self.assertFalse(self.marker.exists())

    def test_invalid_profile_does_not_reserve_output(self):
        profiles = self.home / 'profiles'
        (profiles / 'profiles/kubevirt').mkdir(parents=True)
        (profiles / 'profiles/kubevirt/profile.yaml').write_text('talos: {}\n')
        result = self.render(('--ok-linux-path', str(profiles)))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.marker.exists())

    def test_yaml_prepare_and_live_cannot_open_owner_or_marker(self):
        for mode in ('--prepare', '--live'):
            result = subprocess.run([str(BINARY), 'up', '--file', str(self.input), mode],
                capture_output=True, text=True, env=self.env, cwd=self.home, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('NO-GO', result.stderr)
            self.assertEqual(result.stdout, '')
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.output.exists())

    def test_saved_paths_render_without_reading_any_kubeconfig(self):
        management, provider = self.home / 'management.yaml', self.home / 'provider.yaml'
        management.write_text('not a kubeconfig; must never be decoded')
        provider.write_text('not a kubeconfig; must never be decoded')
        initialized = subprocess.run([str(BINARY), 'config', 'init',
            '--lifecycle-root', str(ROOT), '--ok-linux-path', str(ROOT.parent / 'ok-linux'),
            '--clusters-dir', str(self.home), '--management-kubeconfig', str(management),
            '--provider-kubeconfig', str(provider)], capture_output=True, text=True,
            env=self.env, cwd=self.home, timeout=10)
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        management.unlink()
        provider.unlink()
        result = subprocess.run([str(BINARY), 'up', 'render', '--file', str(self.input),
            '--output', str(self.output)], capture_output=True, text=True, env=self.env,
            cwd=self.home, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIs(json.loads(result.stdout)['runnerReady'], False)
        self.assertFalse(self.marker.exists())

    def test_dry_run_writes_nothing_and_claims_no_preparation(self):
        before = sorted(str(p.relative_to(self.home)) for p in self.home.rglob('*'))
        result = subprocess.run([str(BINARY), 'up', '--file', str(self.input), '--dry-run'],
            capture_output=True, text=True, env=self.env, cwd=self.home, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt['state'], 'INTENT_VALIDATED_NO_GO')
        self.assertIs(receipt['runnerReady'], False)
        self.assertEqual(before, sorted(str(p.relative_to(self.home)) for p in self.home.rglob('*')))


if __name__ == '__main__':
    unittest.main(verbosity=2)
