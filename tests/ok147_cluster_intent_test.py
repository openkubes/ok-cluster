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

    def bind(self, contract, *, prepare=False, canonical=False, saved_paths=False):
        source = self.home / 'reviewed-contract.yaml'
        source.write_text(yaml.safe_dump(contract, sort_keys=False))
        self.source_contract_raw = source.read_bytes()
        command = ['cluster', 'create'] if canonical else ['up']
        command += ['--prepare'] if prepare else ['bind']
        paths = [] if saved_paths else ['--lifecycle-root', str(ROOT), '--ok-linux-path', str(ROOT.parent / 'ok-linux')]
        return subprocess.run([str(BINARY), *command, '--file', str(self.input),
            '--contract', str(source), '--output', str(self.output), *paths], capture_output=True, text=True,
            env=self.env, cwd=self.home, timeout=20)

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
