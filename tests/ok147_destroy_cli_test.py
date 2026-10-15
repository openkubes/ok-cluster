#!/usr/bin/env python3
"""Real CLI + PTY + lifecycle, against independent fake API states only."""
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import time
import unittest

import ok147_split_teardown_test as fixtures

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / '.tools/bin/ok'


class DestroyCLIIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(BINARY.is_file(), 'build the CLI first with make ok-cli-build')
        self.fixture = fixtures.SplitTeardownTests('test_success_routes_and_preserves_evidence')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        box = self.fixture.box
        self.arguments = [str(BINARY), 'destroy', 'cluster', fixtures.CLUSTER,
            '--lifecycle-root', str(ROOT), '--cluster-dir', str(box.rendered),
            '--management-kubeconfig', str(box.infra),
            '--provider-kubeconfig', str(self.fixture.provider),
            '--ok-linux-path', str(ROOT.parent / 'ok-linux')]
        self.env = {**os.environ, 'HOME': str(box.home),
            'PATH': str(box.bin) + os.pathsep + os.environ['PATH'],
            'FAKE_LOG': str(box.log), 'FAKE_STATE': str(box.state_path),
            'FAKE_STATE_MAP': self.fixture.map, 'PYTHONDONTWRITEBYTECODE': '1'}

    def assert_no_owner_calls(self):
        log = self.fixture.box.log
        self.assertTrue(not log.exists() or not log.read_text())

    def invoke(self, answer):
        master, slave = pty.openpty()
        process = subprocess.Popen(self.arguments, stdin=slave, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=self.env)
        os.close(slave)
        output = b''
        try:
            deadline = time.monotonic() + 15
            while b'Type ok to delete' not in output:
                self.assertLess(time.monotonic(), deadline, 'confirmation prompt missing')
                ready, _, _ = select.select([process.stdout], [], [], 0.5)
                if ready:
                    chunk = os.read(process.stdout.fileno(), 4096)
                    self.assertTrue(chunk, 'CLI exited before confirmation prompt')
                    output += chunk
            # Not even read-only kubectl calls are permitted before confirmation.
            self.assert_no_owner_calls()
            if answer is None:
                process.send_signal(signal.SIGINT)
            else:
                os.write(master, answer.encode())
            stdout, stderr = process.communicate(timeout=30)
            return process.returncode, (output + stdout).decode(), stderr.decode()
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
            os.close(master)

    def test_no_cancels_without_starting_lifecycle(self):
        code, stdout, stderr = self.invoke('no\n')
        self.assertEqual(code, 0, stderr)
        self.assertIn('Cancelled', stdout)
        self.assert_no_owner_calls()
        self.fixture.assert_preserved()

    def test_invalid_answer_cannot_delete(self):
        code, _, stderr = self.invoke('yes\n')
        self.assertNotEqual(code, 0)
        self.assertIn('exactly ok or no', stderr)
        self.assert_no_owner_calls()

    def test_empty_answer_defaults_to_no(self):
        code, stdout, stderr = self.invoke('\n')
        self.assertEqual(code, 0, stderr)
        self.assertIn('Cancelled', stdout)
        self.assert_no_owner_calls()

    def test_eof_during_prompt_cannot_delete(self):
        code, _, _ = self.invoke('\x04')
        self.assertNotEqual(code, 0)
        self.assert_no_owner_calls()

    def test_ctrl_c_during_prompt_cannot_delete(self):
        code, _, _ = self.invoke(None)
        self.assertNotEqual(code, 0)
        self.assert_no_owner_calls()

    def test_piped_ok_is_rejected(self):
        result = subprocess.run(self.arguments, input='ok\n', capture_output=True,
                                text=True, env=self.env, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('interactive terminal', result.stderr)
        self.assert_no_owner_calls()

    def test_ok_delegates_to_real_lifecycle_and_keeps_evidence(self):
        code, stdout, stderr = self.invoke('ok\n')
        self.assertEqual(code, 0, stderr)
        self.assertIn('torn down', stdout)
        self.assertTrue(self.fixture.record()['complete'])
        self.assertIsNone(self.fixture.box.read_state()['namespace'])
        self.assertIsNone(self.fixture.provider_read()['namespace'])
        self.assertEqual(self.fixture.provider_read()['pvs'], [])
        self.fixture.assert_preserved()

    def test_owner_failure_stays_nonzero_and_is_not_retried(self):
        self.fixture.box.mutate(lambda state: state['faults'].update({'delete:cluster': 1}))
        code, _, stderr = self.invoke('ok\n')
        self.assertEqual(code, 1, stderr)
        self.assertIn('incomplete or interrupted', stderr)
        self.assertFalse(self.fixture.record()['complete'])
        calls = [json.loads(line) for line in self.fixture.box.log.read_text().splitlines()]
        deletes = [call for call in calls if call[0] == 'kubectl' and 'delete' in call
                   and any('/clusters/' in str(value) for value in call)]
        self.assertEqual(len(deletes), 1)
        self.assertIsNotNone(self.fixture.box.read_state()['namespace'])
        self.fixture.assert_preserved()


if __name__ == '__main__':
    unittest.main(verbosity=2)
