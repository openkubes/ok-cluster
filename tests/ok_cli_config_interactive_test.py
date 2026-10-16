#!/usr/bin/env python3
"""Actual CLI terminal setup; isolated paths, no kubeconfig parsing or cluster."""
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get('OK_CLI_TEST_BINARY', ROOT / '.tools/bin/ok'))


class ConfigTerminalTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        root = self.home / 'trusted checkout'
        (root / 'scripts').mkdir(parents=True)
        (root / 'scripts/talos_golden_lifecycle.py').write_text('raise RuntimeError("must not execute")')
        profiles = self.home / 'profiles'
        clusters = self.home / 'rendered clusters'
        profiles.mkdir()
        clusters.mkdir()
        management, provider = self.home / 'management', self.home / 'provider'
        for path in (management, provider):
            path.write_text('not a kubeconfig: opaque private contents')
        self.paths = [root, profiles, clusters, management, provider]
        self.config = self.home / 'not-created/config.json'
        self.env = {**os.environ, 'HOME': str(self.home),
                    'XDG_CONFIG_HOME': str(self.home / '.config')}
        self.args = [str(BINARY), 'config', 'init', '--config', str(self.config)]

    def invoke_terminal(self, answer, partial=False):
        master, slave = pty.openpty()
        args = self.args + (['--interactive', '--lifecycle-root', str(self.paths[0])] if partial else [])
        process = subprocess.Popen(args, stdin=slave, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=self.env, cwd=self.home)
        os.close(slave)
        captured = b''

        def wait_for(text):
            nonlocal captured
            deadline = time.monotonic() + 15
            while text not in captured:
                self.assertLess(time.monotonic(), deadline, repr(captured))
                ready, _, _ = select.select([process.stderr], [], [], 0.2)
                if ready:
                    chunk = os.read(process.stderr.fileno(), 4096)
                    self.assertTrue(chunk, repr(captured))
                    captured += chunk

        try:
            wait_for(b'checkout: ')
            os.write(master, ('\n'.join(str(p) for p in self.paths[1 if partial else 0:]) + '\n').encode())
            wait_for(b'Type ok or no [no]: ')
            self.assertFalse(self.config.parent.exists(), 'created directory before confirmation')
            if answer is None:
                process.send_signal(signal.SIGINT)
            else:
                os.write(master, answer)
            stdout, stderr = process.communicate(timeout=15)
            return process.returncode, stdout, captured + stderr
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
            os.close(master)

    def test_confirmed_paths_only(self):
        code, stdout, stderr = self.invoke_terminal(b'ok\n')
        self.assertEqual(code, 0, stderr.decode())
        config = json.loads(self.config.read_text())
        self.assertEqual(config['format'], 'ok-cli-paths/v1')
        self.assertEqual([config[key] for key in ('lifecycleRoot', 'okLinuxPath', 'clustersDir',
                         'managementKubeconfig', 'providerKubeconfig')], list(map(str, self.paths)))
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.config.parent.stat().st_mode & 0o777, 0o700)
        self.assertNotIn(b'opaque private contents', self.config.read_bytes() + stdout + stderr)

    def test_partial_explicit_interactive(self):
        code, _, stderr = self.invoke_terminal(b'ok\n', partial=True)
        self.assertEqual(code, 0, stderr.decode())
        self.assertNotIn(b'Trusted ok-cluster checkout: ', stderr)

    def test_default_no(self):
        code, _, _ = self.invoke_terminal(b'\n')
        self.assertNotEqual(code, 0)
        self.assertFalse(self.config.parent.exists())

    def test_no(self):
        code, _, _ = self.invoke_terminal(b'no\n')
        self.assertNotEqual(code, 0)
        self.assertFalse(self.config.parent.exists())

    def test_eof(self):
        code, _, _ = self.invoke_terminal(b'\x04')
        self.assertNotEqual(code, 0)
        self.assertFalse(self.config.parent.exists())

    def test_interrupt(self):
        code, _, _ = self.invoke_terminal(None)
        self.assertNotEqual(code, 0)
        self.assertFalse(self.config.parent.exists())

    def test_piped_interactive_rejected(self):
        result = subprocess.run(self.args + ['--interactive'], input='ok\n', text=True,
                                capture_output=True, env=self.env, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('requires a terminal', result.stderr)
        self.assertFalse(self.config.parent.exists())

    def test_existing_config_preserved(self):
        self.config.parent.mkdir(mode=0o700)
        self.config.write_text('preserve existing bytes')
        result = subprocess.run(self.args + ['--interactive'], input='', text=True,
                                capture_output=True, env=self.env, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('never overwritten', result.stderr)
        self.assertEqual(self.config.read_text(), 'preserve existing bytes')


if __name__ == '__main__':
    unittest.main()
