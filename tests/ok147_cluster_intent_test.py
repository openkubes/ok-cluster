#!/usr/bin/env python3
"""Actual CLI -> owning local renderer; no cluster/API/credential operations."""
import hashlib
import base64
import concurrent.futures
import json
import os
from pathlib import Path
import pty
import subprocess
import shutil
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get('OK_CLI_TEST_BINARY', ROOT / '.tools/bin/ok'))
PROFILES = Path(os.environ.get('OK_CLI_TEST_OK_LINUX_PATH', ROOT.parent / 'ok-linux'))


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
            '--ok-linux-path', str(PROFILES), *extra],
            capture_output=True, text=True, env=self.env, cwd=self.home, timeout=20)

    def test_actual_owner_render_is_private_no_go_and_create_only(self):
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt['state'], 'RENDERED_NO_GO')
        for name in ('execution-fixture.json', 'provider-access-policy.json', 'preparation-receipt.json'):
            self.assertFalse((self.output / name).exists())
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
            '--lifecycle-root', str(ROOT), '--ok-linux-path', str(PROFILES),
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
        self.output = self.home / 'saved-path-preparation'
        prepared = self.bind(self.reviewed_contract(), prepare=True, saved_paths=True)
        self.assertNotEqual(prepared.returncode, 0)
        self.assertIn('preparation incomplete (NO-GO)', prepared.stderr)
        self.assertEqual(json.loads(prepared.stdout)['state'], 'STATIC_PLAN_BOUND_NO_GO')
        self.assertFalse(management.exists())
        self.assertFalse(provider.exists())
        self.assertFalse(self.marker.exists())

    def reviewed_contract(self):
        # Static test input, never a live/historical Candidate or stage outcome.
        contract = yaml.safe_load((ROOT / 'internal/contract/testdata/ok141-contract-v5.yaml').read_text())
        contract['metadata'] = {'name': 'my-cluster', 'namespace': 'my-cluster'}
        spec = contract['spec']
        spec['kubernetesVersion'] = 'v1.34.1'
        access = spec['infrastructure']['providerAccess']
        access['secretRef']['name'] = 'external-infra-kubeconfig-my-cluster'
        access['secretRef']['namespace'] = access['targetNamespace'] = 'my-cluster'
        spec['topology']['workers']['machine']['disk'] = '20Gi'
        spec['connectivity']['podCIDR'] = '10.42.0.0/16'
        spec['connectivity']['serviceCIDR'] = '10.96.0.0/20'
        spec['platform']['revision'] = 'sha256:2956184005f4860607e91672fce82164095dee6ebcbe57e5af883951a199c427'
        return contract

    def bind(self, contract, *, prepare=False, canonical=False, saved_paths=False, runtime_inputs=None):
        source = self.home / 'reviewed-contract.yaml'
        source.write_text(yaml.safe_dump(contract, sort_keys=False))
        self.source_contract_raw = source.read_bytes()
        command = ['cluster', 'create'] if canonical else ['up']
        command += ['--prepare'] if prepare else ['bind']
        paths = [] if saved_paths else ['--lifecycle-root', str(ROOT), '--ok-linux-path', str(PROFILES)]
        if runtime_inputs is not None:
            paths += ['--runtime-inputs', str(runtime_inputs)]
        return subprocess.run([str(BINARY), *command, '--file', str(self.input),
            '--contract', str(source), '--output', str(self.output), *paths], capture_output=True, text=True,
            env=self.env, cwd=self.home, timeout=20)

    def synthetic_runtime_inputs(self):
        openssl = shutil.which('openssl')
        if not openssl:
            self.skipTest('local OpenSSL required for synthetic offline TLS trust')
        cert, key = self.home / 'authority.crt', self.home / 'authority-test.key'
        hostname = 'ok147-stage-authority.openkubes-execution-system.svc'
        subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=' + hostname, '-addext', 'subjectAltName=DNS:' + hostname,
            '-addext', 'extendedKeyUsage=serverAuth', '-keyout', str(key), '-out', str(cert)],
            capture_output=True, check=True, timeout=20, env=self.env)
        ca_digest = 'sha256:' + hashlib.sha256(cert.read_bytes()).hexdigest()
        def private(name, raw):
            path = self.home / name
            path.write_bytes(raw)
            path.chmod(0o600)
            return str(path)
        def authority(identity, host, token):
            return {'endpoint': 'https://' + host + ':6443', 'authorityIdentity': identity,
                'tokenFile': private(identity + '.token', token), 'caFile': str(cert), 'caBundleDigest': ca_digest}
        stage_key = private('stage.pub', base64.b64encode(bytes(range(32))) + b'\n')
        evidence_key = private('evidence.pub', base64.b64encode(bytes(range(32, 64))) + b'\n')
        kubeconfig = {'apiVersion': 'v1', 'kind': 'Config', 'current-context': 'default',
            'clusters': [{'name': 'provider', 'cluster': {'server': 'https://192.0.2.13:6443',
                'certificate-authority-data': base64.b64encode(cert.read_bytes()).decode()}}],
            'contexts': [{'name': 'default', 'context': {'cluster': 'provider', 'user': 'default', 'namespace': 'provider'}}],
            'users': [{'name': 'default', 'user': {'token': 'p' * 48}}]}
        inputs = {'format': 'ok-cli-cluster-runtime-inputs/v1',
            'infrastructure': authority('ok-infra', '192.0.2.13', b'i' * 48),
            'management': authority('ok-mgmt', '192.0.2.14', b'm' * 48),
            'ledger': {'endpoint': 'https://192.0.2.15:6443', 'namespace': 'openkubes-execution-system',
                'tokenFile': private('ledger.token', b'l' * 48), 'caFile': str(cert)},
            'authorization': {'endpoint': 'https://' + hostname + ':8443/v1/stage-authorizations',
                'tokenFile': private('authorization.token', b'a' * 48 + b'\n'), 'caFile': str(cert), 'publicKeyPath': stage_key},
            'providerAccessKubeconfigFile': private('provider.kubeconfig', yaml.safe_dump(kubeconfig).encode()),
            'independentEvidencePublicKeyPath': evidence_key}
        path = self.home / 'runtime-inputs.json'
        private(path.name, json.dumps(inputs).encode())
        return path, inputs

    def test_prepare_with_explicit_runtime_inputs_reaches_existing_manifest_verifier(self):
        runtime_path, inputs = self.synthetic_runtime_inputs()
        before = {str(p): p.read_bytes() for p in self.home.iterdir() if p.is_file()}
        result = self.bind(self.reviewed_contract(), prepare=True, runtime_inputs=runtime_path)
        self.assert_policy_denial(result)
        self.assertFalse((self.output / 'runner-handoff-receipt.json').exists())
        self.assertEqual(json.loads((self.output / 'preparation-receipt.json').read_text())['state'], 'STATIC_PLAN_BOUND_NO_GO')
        manifest_path = self.output / 'full-run-manifest.json'
        dry_run = subprocess.run([str(BINARY), 'up', '--file', str(manifest_path), '--dry-run'],
            capture_output=True, text=True, env=self.env, cwd=self.home, timeout=20)
        self.assert_policy_denial(dry_run)
        self.assertFalse((self.output / 'executor-terminal').exists())
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(manifest['providerAccess']['kubeconfigFile'], inputs['providerAccessKubeconfigFile'])
        self.assertEqual(manifest['providerPrerequisites']['authority'], inputs['infrastructure'])
        self.assertEqual(manifest['clusterLifecycle']['authority'], inputs['management'])
        verified = subprocess.run([str(BINARY), 'up', '--file', str(manifest_path), '--prepare'],
            capture_output=True, text=True, env=self.env, cwd=self.home, timeout=20)
        self.assert_policy_denial(verified)
        for name in ('runtime', 'receipts', 'authorizations'):
            self.assertEqual(list((self.output / name).iterdir()), [])
        for path in self.output.rglob('*'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)
            if path.is_file():
                self.assertNotIn(b'p' * 48, path.read_bytes())
                self.assertNotIn(b'i' * 48, path.read_bytes())
        for path, raw in before.items():
            self.assertEqual(Path(path).read_bytes(), raw)
        self.assertFalse(self.marker.exists())

    def assert_policy_denial(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertIn('client-certificate execution is disabled', result.stderr)
        self.assertFalse(self.marker.exists())

    def yaml_target_references(self, inputs, *, multiple=False, explicit=False):
        provider = yaml.safe_load(Path(inputs['providerAccessKubeconfigFile']).read_text())
        intent = yaml.safe_load(self.input.read_text())
        for role in ('management', 'infrastructure'):
            document = json.loads(json.dumps(provider))
            document['clusters'][0]['cluster']['server'] = inputs[role]['endpoint']
            document['contexts'][0]['name'] = role
            document['current-context'] = 'ignored-single-context'
            # These references are target identity only; plugin execution or
            # administrator credential import is forbidden.
            document['users'][0]['user'] = {'exec': {'command': 'touch',
                'args': [str(self.marker)], 'apiVersion': 'client.authentication.k8s.io/v1'}}
            if multiple:
                extra = json.loads(json.dumps(document['contexts'][0]))
                extra['name'] = 'other'
                document['contexts'].append(extra)
                document['current-context'] = 'other'
            path = self.home / (role + '-target.yaml')
            path.write_text(yaml.safe_dump(document))
            path.chmod(0o600)
            intent['spec'][role] = {'kubeconfig': './' + path.name}
            if explicit:
                intent['spec'][role]['context'] = role
        self.input.write_text(yaml.safe_dump(intent, sort_keys=False))

    def test_yaml_kubeconfig_targets_are_unique_readonly_and_bound_to_runner(self):
        runtime_path, inputs = self.synthetic_runtime_inputs()
        self.yaml_target_references(inputs)
        before = {str(p): p.read_bytes() for p in self.home.glob('*-target.yaml')}
        elsewhere = self.home / 'other-working-directory'
        elsewhere.mkdir()
        checked = subprocess.run([str(BINARY), 'up', '--file', str(self.input), '--dry-run'],
            capture_output=True, text=True, env=self.env, cwd=elsewhere, timeout=20)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        summary = json.loads(checked.stdout)
        self.assertEqual(summary['targets']['management']['context'], 'management')
        self.assertEqual(summary['targets']['infrastructure']['endpoint'], inputs['infrastructure']['endpoint'])
        self.assertIs(summary['apiContacted'], False)
        self.assertNotIn('exec', checked.stdout)
        prepared = self.bind(self.reviewed_contract(), prepare=True, runtime_inputs=runtime_path)
        self.assert_policy_denial(prepared)
        binding = json.loads((self.output / 'binding-receipt.json').read_text())
        self.assertEqual(binding['targets'], summary['targets'])
        command = [str(BINARY), 'up', '--file', str(self.input), '--prepared-dir', str(self.output), '--dry-run']
        verified = subprocess.run(command, capture_output=True, text=True, env=self.env, timeout=20)
        self.assert_policy_denial(verified)
        for path, raw in before.items():
            self.assertEqual(Path(path).read_bytes(), raw)
        # Context-label drift is rejected even when endpoint/trust stay equal.
        path = self.home / 'management-target.yaml'
        data = yaml.safe_load(path.read_text())
        data['contexts'][0]['name'] = 'different-label'
        path.write_text(yaml.safe_dump(data))
        rejected = subprocess.run(command, capture_output=True, text=True, env=self.env, timeout=20)
        self.assertNotEqual(rejected.returncode, 0)
        self.assert_policy_denial(rejected)  # Policy denial precedes target comparison.
        self.assertFalse(self.marker.exists())
        self.assertFalse((self.output / 'executor-terminal').exists())
        for name in ('runtime', 'receipts', 'authorizations'):
            self.assertEqual(list((self.output / name).iterdir()), [])

    def test_yaml_kubeconfig_multiple_contexts_require_explicit_choice(self):
        runtime_path, inputs = self.synthetic_runtime_inputs()
        self.yaml_target_references(inputs, multiple=True)
        rejected = self.bind(self.reviewed_contract(), prepare=True, runtime_inputs=runtime_path)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn('specify context explicitly', rejected.stderr)
        self.assertFalse(self.output.exists())
        self.yaml_target_references(inputs, multiple=True, explicit=True)
        prepared = self.bind(self.reviewed_contract(), prepare=True, runtime_inputs=runtime_path)
        self.assert_policy_denial(prepared)
        targets = json.loads((self.output / 'binding-receipt.json').read_text())['targets']
        self.assertEqual(targets['management']['context'], 'management')
        self.assertFalse(self.marker.exists())

    def test_yaml_kubeconfig_transport_and_provider_mismatch_fail_without_handoff(self):
        runtime_path, inputs = self.synthetic_runtime_inputs()
        self.yaml_target_references(inputs)
        mgmt = self.home / 'management-target.yaml'
        original_mgmt = mgmt.read_bytes()
        provider = Path(inputs['providerAccessKubeconfigFile'])
        original_provider = provider.read_bytes()
        for case in ('endpoint', 'trust', 'provider-access'):
            with self.subTest(case=case):
                mgmt.write_bytes(original_mgmt)
                provider.write_bytes(original_provider)
                path = provider if case == 'provider-access' else mgmt
                data = yaml.safe_load(path.read_text())
                if case == 'trust':
                    data['clusters'][0]['cluster']['certificate-authority-data'] = base64.b64encode(b'not a certificate').decode()
                else:
                    data['clusters'][0]['cluster']['server'] = 'https://foreign.example:6443'
                path.write_text(yaml.safe_dump(data))
                self.output = self.home / ('mismatch-' + case)
                result = self.bind(self.reviewed_contract(), prepare=True, runtime_inputs=runtime_path)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.output / 'runner-handoff-receipt.json').exists())
                self.assertFalse(self.marker.exists())

    def test_prepared_yaml_uses_existing_runner_and_rejects_drift_without_execution(self):
        runtime_path, inputs = self.synthetic_runtime_inputs()
        prepared = self.bind(self.reviewed_contract(), prepare=True, runtime_inputs=runtime_path)
        self.assert_policy_denial(prepared)
        manifest_digest = 'sha256:' + hashlib.sha256((self.output / 'full-run-manifest.json').read_bytes()).hexdigest()
        original = self.input.read_bytes()
        base = [str(BINARY), 'up', '--file', str(self.input), '--prepared-dir', str(self.output)]

        def invoke(suffix=('--dry-run',)):
            return subprocess.run([*base, *suffix], capture_output=True, text=True,
                                  env=self.env, cwd=self.home, timeout=20)

        # Changes to comments are not semantic drift.
        self.input.write_bytes(b'# same reviewed intent\n' + original)
        checked = invoke()
        self.assert_policy_denial(checked)

        live = ['--live', '--execute', '--expected-manifest-digest', manifest_digest,
                '--independent-evidence-public-key', inputs['independentEvidencePublicKeyPath'],
                '--terminal-marker', str(self.output / 'executor-terminal')]
        # Never invoke valid live arguments. Missing gate, wrong digest or
        # semantic/fixture drift must reject before any executor can be opened.
        missing_gate = [arg for arg in live if arg != '--execute']
        self.assertNotEqual(invoke(missing_gate).returncode, 0)
        wrong_digest = list(live)
        wrong_digest[3] = 'sha256:' + '0' * 64
        self.assertNotEqual(invoke(wrong_digest).returncode, 0)
        self.input.write_bytes(original.replace(b'192.0.2.10', b'192.0.2.11'))
        for suffix in (('--dry-run',), live):
            rejected = invoke(suffix)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn('differs from the prepared intent', rejected.stderr)
        self.input.write_bytes(original)

        for name in ('execution-fixture.json', 'binding-receipt.json'):
            path = self.output / name
            raw = path.read_bytes()
            path.write_bytes(raw + b'\n')  # Hash-bound bytes, not JSON semantics.
            rejected = invoke()
            self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
            path.write_bytes(raw)
        fixture_path = self.output / 'execution-fixture.json'
        fixture_path.chmod(0o644)
        self.assertNotEqual(invoke().returncode, 0)
        fixture_path.chmod(0o600)
        self.assertFalse((self.output / 'executor-terminal').exists())
        for name in ('runtime', 'receipts', 'authorizations'):
            self.assertEqual(list((self.output / name).iterdir()), [])
        self.assertFalse(self.marker.exists())

    def test_guided_up_denies_policy_before_confirmation_without_expert_flags(self):
        runtime_path, _ = self.synthetic_runtime_inputs()
        management, provider = self.home / 'management-path-only', self.home / 'provider-path-only'
        for path in (management, provider):
            path.write_text('opaque; only saved source paths may be used')
        config = subprocess.run([str(BINARY), 'config', 'init', '--lifecycle-root', str(ROOT),
            '--ok-linux-path', str(PROFILES), '--clusters-dir', str(self.home),
            '--management-kubeconfig', str(management), '--provider-kubeconfig', str(provider)],
            capture_output=True, text=True, env=self.env, timeout=10)
        self.assertEqual(config.returncode, 0, config.stderr)
        management.unlink()
        provider.unlink()  # Guided up must not infer credentials from general config.

        pending = self.automatic_prepare()
        self.assertNotEqual(pending.returncode, 0, pending.stderr)
        self.install_platform_handoff(json.loads(pending.stdout), runtime_path)

        def terminal_run():
            master, slave = pty.openpty()
            process = subprocess.Popen([str(BINARY), 'up', '--file', str(self.input)],
                stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env, cwd=self.home)
            os.close(slave)
            try:
                stdout, stderr = process.communicate(timeout=25)
                return process.returncode, stdout, stderr
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
                os.close(master)

        # Unsupported credentials must exit before even offering confirmation.
        code, stdout, prompts = terminal_run()
        self.assertNotEqual(code, 0)
        self.assertEqual(stdout, b'')
        self.assertIn(b'client-certificate execution is disabled', prompts)
        self.assertIn(b'Automatic workload-access setup is not enabled yet', prompts)
        self.assertIn(b'There is no user-side workaround', prompts)
        self.assertIn(b'do not switch to an administrator kubeconfig', prompts)
        self.assertIn(b'delete retained preparation, or retry the run', prompts)
        self.assertNotIn(b'Type ok to create', prompts)
        self.assertEqual(list(self.home.rglob('managed-preparation.json')), [])
        root = Path(json.loads(pending.stdout)['requestPath']).parent
        self.assertFalse((root / 'preparation/runner-handoff-receipt.json').exists())
        before = {str(p): p.read_bytes() for p in root.rglob('*') if p.is_file()}
        code, stdout, prompts = terminal_run()
        self.assertNotEqual(code, 0)
        self.assertEqual(stdout, b'')
        self.assertNotIn(b'Type ok to create', prompts)
        self.assertIn(b'already attempted', prompts)
        self.assertEqual(before, {str(p): p.read_bytes() for p in root.rglob('*') if p.is_file()})
        self.assertFalse((root / 'execution-started.json').exists())
        self.assertFalse((root / 'executor-terminal').exists())
        for name in ('runtime', 'receipts', 'authorizations'):
            self.assertEqual(list((root / 'preparation' / name).iterdir()), [])
        self.assertFalse(self.marker.exists())

    def automatic_config(self):
        management, provider = self.home / 'configured-management', self.home / 'configured-provider'
        for path in (management, provider):
            path.write_text('path-only config fixture; not credentials')
        result = subprocess.run([str(BINARY), 'config', 'init', '--lifecycle-root', str(ROOT),
            '--ok-linux-path', str(PROFILES), '--clusters-dir', str(self.home),
            '--management-kubeconfig', str(management), '--provider-kubeconfig', str(provider)],
            capture_output=True, text=True, env=self.env, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        management.unlink()
        provider.unlink()

    def automatic_prepare(self):
        return subprocess.run([str(BINARY), 'up', '--file', str(self.input), '--prepare'],
            capture_output=True, text=True, env=self.env, cwd=self.home, timeout=25)

    def test_interactive_missing_platform_access_is_readable_and_retains_json_mode(self):
        self.automatic_config()
        before = None
        for command in (['up'], ['cluster', 'create']):
            master, slave = pty.openpty()
            process = subprocess.Popen([str(BINARY), *command, '--file', str(self.input)],
                stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=self.env, cwd=self.home)
            os.close(slave)
            try:
                stdout, stderr = process.communicate(timeout=25)
                self.assertNotEqual(process.returncode, 0)
                text = stdout.decode()
                self.assertIn('Cluster "my-cluster"', text)
                self.assertIn('Local preparation: complete', text)
                self.assertIn('Cluster creation:  not started', text)
                self.assertIn('No cluster API was contacted', text)
                self.assertIn('No credentials were issued or renewed', text)
                self.assertNotIn('requestDigest', text)
                self.assertNotIn('sha256:', text)
                self.assertNotIn('Type ok', text + stderr.decode())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
                os.close(master)
            if before is None:
                pending = json.loads(self.automatic_prepare().stdout)
                root = Path(pending['requestPath']).parent
                before = {str(p): p.read_bytes() for p in root.rglob('*') if p.is_file()}
        self.assertEqual(before, {str(p): p.read_bytes() for p in root.rglob('*') if p.is_file()})
        repeated = self.automatic_prepare()
        self.assertNotEqual(repeated.returncode, 0)
        self.assertEqual(json.loads(repeated.stdout), pending)
        self.assertFalse((root / 'execution-started.json').exists())
        self.assertFalse((root / 'handoff-started.json').exists())
        self.assertFalse((root / 'executor-terminal').exists())
        self.assertFalse(self.marker.exists())

    def install_platform_handoff(self, request, runtime_path):
        path = Path(request['requestPath']).parent / 'platform-handoff.json'
        path.write_text(json.dumps({'format': 'ok-cli-platform-handoff/v1',
            'requestDigest': request['requestDigest'], 'runtimeInputsPath': str(runtime_path),
            'runtimeInputsDigest': 'sha256:' + hashlib.sha256(runtime_path.read_bytes()).hexdigest()}))
        path.chmod(0o600)
        return path

    def test_automatic_preparation_compiles_contract_and_exact_policy_without_credentials(self):
        self.automatic_config()
        result = self.automatic_prepare()
        self.assertNotEqual(result.returncode, 0)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt['state'], 'AWAITING_PLATFORM_AUTHORITY')
        for field in ('apiContacted', 'authorizationConsumed', 'mutationAllowed', 'runnerReady'):
            self.assertIs(receipt[field], False)
        root = Path(receipt['requestPath']).parent
        request = json.loads(Path(receipt['requestPath']).read_text())
        prepared = root / 'preparation'
        self.assertEqual(yaml.safe_load((prepared / 'contract.yaml').read_text()), self.reviewed_contract())
        self.assertTrue(json.loads((prepared / 'binding-receipt.json').read_text())['contractSourceDigests'])
        plan = json.loads((prepared / 'staged-plan.json').read_text())
        policy = json.loads((prepared / 'stage-authority-policy.json').read_text())
        self.assertEqual(policy['planDigest'], request['plan']['SemanticDigest'])
        self.assertEqual(policy['contractIdentity'], {'namespace': 'my-cluster', 'name': 'my-cluster'})
        self.assertEqual(policy['executionFixture'], plan['executionFixture'])
        self.assertNotIn('signature', policy)
        self.assertFalse((prepared / 'full-run-manifest.json').exists())
        before = {str(path): path.read_bytes() for path in root.rglob('*') if path.is_file()}
        repeated = self.automatic_prepare()
        self.assertNotEqual(repeated.returncode, 0)
        self.assertEqual(json.loads(repeated.stdout)['requestDigest'], receipt['requestDigest'])
        self.assertEqual(before, {str(path): path.read_bytes() for path in root.rglob('*') if path.is_file()})
        self.assertNotIn('Reviewed Contract file:', repeated.stderr)
        self.assertFalse(self.marker.exists())

    def test_automatic_handoff_is_exact_non_authorizing_and_does_not_rerender(self):
        self.automatic_config()
        pending = json.loads(self.automatic_prepare().stdout)
        root = Path(pending['requestPath']).parent
        before = {str(path): path.read_bytes() for path in (root / 'preparation').rglob('*') if path.is_file()}
        runtime_path, _ = self.synthetic_runtime_inputs()
        self.install_platform_handoff(pending, runtime_path)
        result = self.automatic_prepare()
        self.assert_policy_denial(result)
        self.assertFalse((root / 'managed-preparation.json').exists())
        self.assertFalse((root / 'preparation/runner-handoff-receipt.json').exists())
        for path, raw in before.items():
            self.assertEqual(Path(path).read_bytes(), raw)
        self.assertFalse((root / 'execution-started.json').exists())
        self.assertFalse((root / 'executor-terminal').exists())
        repeated = self.automatic_prepare()
        self.assertNotEqual(repeated.returncode, 0)
        self.assertIn('already attempted', repeated.stderr)
        request_path = Path(pending['requestPath'])
        request = json.loads(request_path.read_text())
        request['binaryDigest'] = 'sha256:' + '0' * 64
        request_path.write_text(json.dumps(request))
        self.assertNotEqual(self.automatic_prepare().returncode, 0)
        self.assertFalse((root / 'execution-started.json').exists())
        self.assertFalse(self.marker.exists())

    def test_automatic_handoff_rejects_wrong_binding_and_retains_failure_without_retry(self):
        self.automatic_config()
        pending = json.loads(self.automatic_prepare().stdout)
        root = Path(pending['requestPath']).parent
        runtime_path, inputs = self.synthetic_runtime_inputs()
        path = self.install_platform_handoff(pending, runtime_path)
        original = json.loads(path.read_text())
        for field in ('requestDigest', 'runtimeInputsDigest'):
            changed = dict(original)
            changed[field] = 'sha256:' + '0' * 64
            path.write_text(json.dumps(changed))
            self.assertNotEqual(self.automatic_prepare().returncode, 0)
            self.assertFalse((root / 'handoff-started.json').exists())
        for changed in ({**original, 'format': 'unknown'}, {**original, 'runtimeInputsPath': 'relative.json'},
                        {**original, 'execute': True}):
            path.write_text(json.dumps(changed))
            self.assertNotEqual(self.automatic_prepare().returncode, 0)
            self.assertFalse((root / 'handoff-started.json').exists())
        path.write_text(json.dumps(original))
        Path(inputs['management']['tokenFile']).chmod(0o644)
        self.assertNotEqual(self.automatic_prepare().returncode, 0)
        self.assertTrue((root / 'handoff-started.json').exists())
        before = {str(p): p.read_bytes() for p in root.rglob('*') if p.is_file()}
        Path(inputs['management']['tokenFile']).chmod(0o600)
        self.assertNotEqual(self.automatic_prepare().returncode, 0)
        self.assertEqual(before, {str(p): p.read_bytes() for p in root.rglob('*') if p.is_file()})
        self.assertFalse((root / 'execution-started.json').exists())
        self.assertFalse(self.marker.exists())

    def test_automatic_parallel_preparation_and_handoff_are_create_only(self):
        self.automatic_config()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.automatic_prepare(), range(2)))
        receipts = [json.loads(result.stdout) for result in results if result.stdout]
        self.assertTrue(receipts)
        self.assertTrue(all(receipt['state'] == 'AWAITING_PLATFORM_AUTHORITY' for receipt in receipts))
        self.assertEqual(len(list(self.home.rglob('platform-preparation-request.json'))), 1)
        root = Path(receipts[0]['requestPath']).parent
        runtime_path, _ = self.synthetic_runtime_inputs()
        self.install_platform_handoff(receipts[0], runtime_path)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.automatic_prepare(), range(2)))
        self.assertTrue(all(result.returncode != 0 for result in results))
        self.assertTrue(any('client-certificate execution is disabled' in result.stderr for result in results), [result.stderr for result in results])
        self.assertTrue(all(not result.stdout for result in results))
        self.assertFalse((root / 'managed-preparation.json').exists())
        self.assertFalse((root / 'preparation/runner-handoff-receipt.json').exists())
        self.assertEqual(len(list(root.rglob('full-run-manifest.json'))), 1)
        self.assertFalse((root / 'execution-started.json').exists())
        self.assertFalse(self.marker.exists())

    def test_automatic_preparation_rejects_changed_binary_identity(self):
        self.automatic_config()
        pending = json.loads(self.automatic_prepare().stdout)
        path = Path(pending['requestPath'])
        request = json.loads(path.read_text())
        request['binaryDigest'] = 'sha256:' + '0' * 64
        path.write_text(json.dumps(request))
        result = self.automatic_prepare()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('binary changed', result.stderr)
        self.assertFalse((path.parent / 'handoff-started.json').exists())
        self.assertFalse(self.marker.exists())

    def test_automatic_preparation_rejects_yaml_and_static_drift_without_repair(self):
        self.automatic_config()
        pending = json.loads(self.automatic_prepare().stdout)
        root = Path(pending['requestPath']).parent
        original = self.input.read_bytes()
        self.input.write_bytes(original.replace(b'192.0.2.10', b'192.0.2.11'))
        self.assertNotEqual(self.automatic_prepare().returncode, 0)
        self.input.write_bytes(original)
        contract = root / 'preparation/contract.yaml'
        contract.write_bytes(contract.read_bytes() + b'\n')
        changed = contract.read_bytes()
        self.assertNotEqual(self.automatic_prepare().returncode, 0)
        self.assertEqual(contract.read_bytes(), changed)
        self.assertFalse(self.marker.exists())

    def test_guided_up_rejects_piped_confirmation_before_any_state(self):
        result = subprocess.run([str(BINARY), 'up', '--file', str(self.input)], input='ok\n',
            capture_output=True, text=True, env=self.env, cwd=self.home, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('requires a terminal', result.stderr)
        self.assertEqual(list(self.home.rglob('managed-preparation.json')), [])
        self.assertFalse(self.marker.exists())

    def test_runtime_handoff_fails_without_success_receipt_on_missing_or_foreign_inputs(self):
        runtime_path, inputs = self.synthetic_runtime_inputs()
        for case in ('missing-token', 'foreign-authority', 'shared-key', 'unsafe-file-mode', 'unknown-field'):
            with self.subTest(case=case):
                data = json.loads(json.dumps(inputs))
                if case == 'missing-token':
                    data['infrastructure']['tokenFile'] = str(self.home / 'not-present')
                elif case == 'foreign-authority':
                    data['management']['authorityIdentity'] = 'foreign-management'
                elif case == 'shared-key':
                    data['independentEvidencePublicKeyPath'] = data['authorization']['publicKeyPath']
                elif case == 'unknown-field':
                    data['plan'] = {'path': '/historical/not-read'}
                runtime_path.write_text(json.dumps(data))
                runtime_path.chmod(0o644 if case == 'unsafe-file-mode' else 0o600)
                self.output = self.home / case
                result = self.bind(self.reviewed_contract(), prepare=True, runtime_inputs=runtime_path)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertIn('handoff', result.stderr)
                self.assertFalse((self.output / 'runner-handoff-receipt.json').exists())
                self.assertEqual(json.loads((self.output / 'preparation-receipt.json').read_text())['state'], 'STATIC_PLAN_BOUND_NO_GO')
                self.assertNotIn('p' * 48, result.stderr)
                self.assertFalse(self.marker.exists())

    def test_static_binding_uses_owning_contract_and_projection_verifiers(self):
        result = self.bind(self.reviewed_contract())
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt['state'], 'CONTRACT_PROJECTION_BOUND_NO_GO')
        for name in ('execution-fixture.json', 'provider-access-policy.json', 'preparation-receipt.json'):
            self.assertFalse((self.output / name).exists())
        self.assertEqual(receipt['canonicalizationProfile'], 'openkubes-contract-c14n/v1')
        self.assertEqual(receipt['contractIdentity'], {'name': 'my-cluster', 'namespace': 'my-cluster'})
        self.assertEqual(receipt['intentRevision'], 'sha256:' + hashlib.sha256((self.output / 'contract.canonical.json').read_bytes()).hexdigest())
        self.assertEqual(receipt['rawContractDigest'], 'sha256:' + hashlib.sha256(self.source_contract_raw).hexdigest())
        self.assertEqual(receipt['projection']['intentRevision'], receipt['intentRevision'])
        self.assertEqual(receipt['projection']['infrastructurePlane']['resourceCount'], 5)
        self.assertEqual(receipt['projection']['managementPlane']['resourceCount'], 8)
        self.assertEqual((self.output / 'contract.yaml').read_bytes(), self.source_contract_raw)
        self.assertEqual((self.home / 'reviewed-contract.yaml').read_bytes(), self.source_contract_raw)
        for field in ('apiContacted', 'authorizationConsumed', 'mutationAllowed', 'runnerReady'):
            self.assertIs(receipt[field], False)
        self.assertIn('seven-stage Plan', receipt['missingBindings'])
        self.assertFalse((self.output / 'full-run-manifest.json').exists())
        for path in self.output.rglob('*'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)
        manifest = json.loads((self.output / 'projection/manifest.json').read_text())
        self.assertEqual(manifest['authorizationState'], 'NO-GO')
        self.assertEqual(manifest['R'], receipt['intentRevision'])
        self.assertFalse(self.marker.exists())
        before = {str(p.relative_to(self.output)): p.read_bytes() for p in self.output.rglob('*') if p.is_file()}
        repeated = self.bind(self.reviewed_contract())
        self.assertNotEqual(repeated.returncode, 0)
        self.assertEqual(before, {str(p.relative_to(self.output)): p.read_bytes() for p in self.output.rglob('*') if p.is_file()})

    def test_static_binding_refuses_contract_identity_or_semantics_drift(self):
        for field in ('name', 'uid', 'network', 'machine', 'kubernetes', 'operatingSystem'):
            with self.subTest(field=field):
                contract = self.reviewed_contract()
                if field == 'name':
                    contract['metadata']['name'] = contract['metadata']['namespace'] = 'historical-cluster'
                elif field == 'uid':
                    contract['metadata']['uid'] = 'historical-object-uid'
                elif field == 'network':
                    contract['spec']['connectivity']['podCIDR'] = '10.43.0.0/16'
                elif field == 'machine':
                    contract['spec']['topology']['workers']['machine']['disk'] = '30Gi'
                elif field == 'kubernetes':
                    contract['spec']['kubernetesVersion'] = 'v1.36.2'
                else:
                    contract['spec']['operatingSystem']['identity'] = 'sha256:' + 'f' * 64
                result = self.bind(contract)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.output.exists())
                self.assertFalse(self.marker.exists())

    def test_prepare_internally_binds_but_returns_incomplete_not_success(self):
        for canonical in (False, True):
            with self.subTest(canonical=canonical):
                self.output = self.home / ('canonical-prepare' if canonical else 'up-prepare')
                result = self.bind(self.reviewed_contract(), prepare=True, canonical=canonical)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('preparation incomplete (NO-GO)', result.stderr)
                receipt = json.loads(result.stdout)
                self.assertEqual(receipt, json.loads((self.output / 'preparation-receipt.json').read_text()))
                self.assertEqual(receipt['state'], 'STATIC_PLAN_BOUND_NO_GO')
                self.assertEqual(receipt['format'], 'ok-cli-cluster-preparation/v2')
                static = json.loads((self.output / 'binding-receipt.json').read_text())
                self.assertEqual(receipt['bindingReceiptDigest'], 'sha256:' + hashlib.sha256((self.output / 'binding-receipt.json').read_bytes()).hexdigest())
                self.assertEqual(receipt['contractIdentity'], static['contractIdentity'])
                self.assertEqual(receipt['intentRevision'], static['intentRevision'])
                fixture = json.loads((self.output / 'execution-fixture.json').read_text())
                self.assertEqual(fixture['format'], 'ok-cli-local-execution-fixture/v2')
                self.assertEqual(fixture['authorizationState'], 'NO-GO')
                self.assertEqual(fixture['contractIdentity'], receipt['contractIdentity'])
                self.assertEqual(fixture['intentRevision'], receipt['intentRevision'])
                self.assertEqual(fixture['bindingReceiptDigest'], receipt['bindingReceiptDigest'])
                self.assertEqual(fixture['runnerRecipeDigest'], receipt['runnerRecipeDigest'])
                self.assertEqual(receipt['runnerRecipeDigest'], 'sha256:' + hashlib.sha256((ROOT / 'profiles/cli/talos-kubevirt-mvp-v1.json').read_bytes()).hexdigest())
                self.assertEqual(fixture['runner']['executionMode'], 'local-cli')
                cli_version = subprocess.run([str(BINARY), 'version'], capture_output=True, text=True,
                    check=True, env=self.env, cwd=self.home, timeout=10).stdout.split()
                self.assertEqual(fixture['runner']['version'], cli_version[0])
                self.assertEqual(fixture['runner']['sourceRevision'], cli_version[1])
                self.assertEqual(fixture['runner']['binaryDigest'], 'sha256:' + hashlib.sha256(BINARY.read_bytes()).hexdigest())
                self.assertFalse(fixture['runner']['imagePublicationPerformed'])
                self.assertEqual(receipt['executionFixtureDigest'], 'sha256:' + hashlib.sha256((self.output / 'execution-fixture.json').read_bytes()).hexdigest())
                policy = json.loads((self.output / 'provider-access-policy.json').read_text())
                self.assertEqual(policy['format'], 'ok147-provider-access-policy/v1')
                self.assertEqual(policy['contractIdentity'], receipt['contractIdentity'])
                self.assertEqual(policy['intentRevision'], receipt['intentRevision'])
                self.assertEqual(policy['executionFixture'], receipt['executionFixtureDigest'])
                self.assertEqual(policy['managementAuthority'], 'ok-mgmt')
                self.assertEqual(policy['providerAuthority'], 'ok-infra')
                self.assertEqual(policy['secret'], {'apiVersion': 'v1', 'kind': 'Secret', 'namespace': 'my-cluster',
                    'name': 'external-infra-kubeconfig-my-cluster', 'type': 'Opaque', 'dataKey': 'kubeconfig', 'immutable': True})
                self.assertEqual(receipt['providerAccessPolicyDigest'], 'sha256:' + hashlib.sha256((self.output / 'provider-access-policy.json').read_bytes()).hexdigest())
                self.assertNotIn('fresh execution fixture', receipt['missingBindings'])
                self.assertNotIn('seven-stage Plan', receipt['missingBindings'])
                plan = json.loads((self.output / 'staged-plan.json').read_text())
                verified = json.loads((self.output / 'verified-staged-plan.json').read_text())
                self.assertEqual(plan['format'], 'ok147-staged-execution-plan/v1')
                self.assertEqual(plan['authorizationState'], 'NO-GO')
                self.assertEqual(plan['completionMode'], 'bare-cluster-mvp/v1')
                self.assertEqual(plan['contractIdentity'], receipt['contractIdentity'])
                self.assertEqual(plan['executionFixture'], receipt['executionFixtureDigest'])
                network_profile = json.loads((self.output / 'network-profile.json').read_text())
                semantic_network_digest = 'sha256:' + hashlib.sha256(json.dumps(network_profile, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
                projection_inputs = {('projection.provider-prerequisites' if a['name'] == 'ok-infra-prerequisites.yaml' else 'projection.cluster-lifecycle'): a['digest']
                    for a in static['projection']['artifacts'] if a['name'] in ('ok-infra-prerequisites.yaml', 'ok-mgmt-lifecycle.yaml')}
                raw_inputs = {'stage.provider-access': 'provider-access-policy.json', 'stage.lifecycle-observation': 'lifecycle-observation.json',
                    'stage.enablement': 'enablement.yaml', 'stage.runtime-binding': 'runtime-binding-requirements.json', 'stage.target-access': 'target-access.yaml'}
                for stage in plan['stages']:
                    for item in stage['inputs']:
                        if item['name'] in raw_inputs:
                            self.assertEqual(item['digest'], 'sha256:' + hashlib.sha256((self.output / raw_inputs[item['name']]).read_bytes()).hexdigest())
                        elif item['name'] == 'stage.network-observation':
                            self.assertEqual(item['digest'], semantic_network_digest)
                        else:
                            self.assertEqual(item['digest'], projection_inputs[item['name']])
                self.assertEqual(receipt['planDigest'], verified['planDigest'])
                self.assertEqual(receipt['planRawDigest'], 'sha256:' + hashlib.sha256((self.output / 'staged-plan.json').read_bytes()).hexdigest())
                self.assertEqual([s['id'] for s in plan['stages']], ['provider-prerequisites', 'cluster-lifecycle', 'lifecycle-observation', 'enablement', 'network-observation', 'runtime-binding', 'target-access'])
                self.assertNotIn('networkObservationMode', plan)
                self.assertNotIn('executionAttemptDigest', plan)
                for name, digest in receipt['stageArtifacts'].items():
                    self.assertEqual(digest, 'sha256:' + hashlib.sha256((self.output / name).read_bytes()).hexdigest())
                enablement = yaml.safe_load((self.output / 'enablement.yaml').read_text())
                target_access = list(yaml.safe_load_all((self.output / 'target-access.yaml').read_text()))
                self.assertEqual(len(target_access), 16)
                self.assertEqual(enablement['metadata']['annotations']['openkubes.io/execution-fixture'], receipt['executionFixtureDigest'])
                self.assertFalse((self.output / 'runtime-binding.json').exists())
                for path in self.output.rglob('*'):
                    self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)
                for field in ('runnerReady', 'mutationAllowed', 'apiContacted', 'authorizationConsumed'):
                    self.assertIs(receipt[field], False)
                self.assertNotIn('manifestDigest', receipt)
                self.assertFalse((self.output / 'full-run-manifest.json').exists())
                before = {str(p.relative_to(self.output)): p.read_bytes() for p in self.output.rglob('*') if p.is_file()}
                repeated = self.bind(self.reviewed_contract(), prepare=True, canonical=canonical)
                self.assertNotEqual(repeated.returncode, 0)
                self.assertEqual(repeated.stdout, '')
                self.assertEqual(before, {str(p.relative_to(self.output)): p.read_bytes() for p in self.output.rglob('*') if p.is_file()})
                self.assertFalse(self.marker.exists())

    def test_local_inputs_change_with_new_cluster_identity(self):
        first = self.bind(self.reviewed_contract(), prepare=True)
        self.assertNotEqual(first.returncode, 0)
        a = json.loads(first.stdout)
        self.input.write_text(self.input.read_text().replace('my-cluster', 'other-cluster'))
        contract = self.reviewed_contract()
        contract['metadata'] = {'name': 'other-cluster', 'namespace': 'other-cluster'}
        access = contract['spec']['infrastructure']['providerAccess']
        access['secretRef']['name'] = 'external-infra-kubeconfig-other-cluster'
        access['secretRef']['namespace'] = access['targetNamespace'] = 'other-cluster'
        self.output = self.home / 'other-preparation'
        second = self.bind(contract, prepare=True)
        self.assertNotEqual(second.returncode, 0)
        b = json.loads(second.stdout)
        self.assertNotEqual(a['executionFixtureDigest'], b['executionFixtureDigest'])
        self.assertNotEqual(a['providerAccessPolicyDigest'], b['providerAccessPolicyDigest'])
        for path in self.output.rglob('*'):
            if path.is_file():
                self.assertNotIn(b'my-cluster', path.read_bytes())
        self.assertFalse(self.marker.exists())

    def test_unsupported_os_profiles_never_fall_back_to_talos(self):
        original = self.input.read_text()
        for profile in ('flatcar-kubevirt-mvp', 'ubuntu-kubevirt-mvp'):
            self.input.write_text(original.replace('talos-kubevirt-mvp', profile))
            for mode in ('--dry-run', '--prepare', '--live'):
                result = subprocess.run([str(BINARY), 'up', '--file', str(self.input), mode],
                    capture_output=True, text=True, env=self.env, cwd=self.home, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
            self.assertFalse(self.output.exists())
        self.assertFalse(self.marker.exists())

    def test_recipe_revision_mismatch_keeps_partial_static_output_without_replay(self):
        contract = self.reviewed_contract()
        contract['spec']['platform']['revision'] = 'sha256:' + 'e' * 64
        result = self.bind(contract, prepare=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertIn('runner recipe differs', result.stderr)
        self.assertTrue((self.output / 'binding-receipt.json').is_file())
        self.assertFalse((self.output / 'execution-fixture.json').exists())
        self.assertFalse((self.output / 'preparation-receipt.json').exists())
        before = {str(p.relative_to(self.output)): p.read_bytes() for p in self.output.rglob('*') if p.is_file()}
        retry = self.bind(self.reviewed_contract(), prepare=True)
        self.assertNotEqual(retry.returncode, 0)
        self.assertEqual(retry.stdout, '')
        self.assertEqual(before, {str(p.relative_to(self.output)): p.read_bytes() for p in self.output.rglob('*') if p.is_file()})
        self.assertFalse(self.marker.exists())

    def test_prepare_rejects_contract_drift_before_output(self):
        contract = self.reviewed_contract()
        contract['spec']['connectivity']['podCIDR'] = '10.43.0.0/16'
        result = self.bind(contract, prepare=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertFalse(self.output.exists())
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
