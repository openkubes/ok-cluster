#!/usr/bin/env python3
"""CLI -> owning renderer, synthetic inventories and fake read-only APIs only."""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get('OK_CLI_TEST_BINARY', ROOT / '.tools/bin/ok'))


class NetworkProposalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.inventory = self.home / 'inventory'
        self.inventory.mkdir()
        self.input = self.home / 'cluster.yaml'
        self.input.write_bytes((ROOT / 'examples/ok-cli-cluster.yaml').read_bytes())
        self.output = self.home / 'proposed.yaml'
        self.calls = self.home / 'calls.jsonl'
        self.responses = self.home / 'responses.json'
        tools = self.home / 'bin'
        tools.mkdir()
        tool = tools / 'kubectl'
        tool.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as stream:
    stream.write(json.dumps(args) + '\\n')
assert args[0] == '--kubeconfig' and args[2] == '--context'
assert args[4] == 'get' and args[6:] == ['-A', '-o', 'json', '--request-timeout=10s']
data = json.loads(Path(os.environ['RESPONSES']).read_text())
if data.get('fail') == args[5]:
    print('SECRET_MUST_NOT_LEAK', file=sys.stderr)
    sys.exit(17)
plane = Path(args[1]).stem
print(json.dumps({'items': data.get(plane + '/' + args[5], [])}))
''')
        tool.chmod(0o700)
        self.env = {**os.environ, 'HOME': str(self.home), 'XDG_CONFIG_HOME': str(self.home / '.config'),
                    'PATH': str(tools) + os.pathsep + os.environ['PATH'],
                    'CALLS': str(self.calls), 'RESPONSES': str(self.responses),
                    'PYTHONDONTWRITEBYTECODE': '1', 'KUBECONFIG': '/must-not-use-default'}
        self.data = {}

    def config(self, name='existing', endpoint='192.168.100.200', pod='10.32.0.0/16', service='10.96.0.0/20', parent=None):
        parent = parent or self.inventory
        directory = parent / name
        directory.mkdir(parents=True)
        path = directory / 'cluster-config.yaml'
        path.write_text(yaml.safe_dump({'name': name, 'network': {'endpoint': endpoint,
                                                               'podCIDR': pod, 'serviceCIDR': service}}))
        return path

    def run_proposal(self, extra=(), online=False, output=True):
        self.responses.write_text(json.dumps(self.data))
        return subprocess.run([str(BINARY), 'up', 'network-suggest', '--file', str(self.input),
            '--lifecycle-root', str(ROOT), '--clusters-dir', str(self.inventory),
            *(['--online'] if online else ['--endpoint-pool', '192.168.100.200-192.168.100.210']),
            *(['--output', str(self.output)] if output else []), *extra],
            capture_output=True, text=True, env=self.env, cwd=self.home, timeout=30)

    def online_inputs(self):
        openssl = shutil.which('openssl')
        if not openssl:
            self.skipTest('OpenSSL required for synthetic offline CA fixture')
        cert = self.home / 'ca.crt'
        subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=synthetic-test-ca', '-keyout', str(self.home / 'ca.key'),
                        '-out', str(cert)], check=True, capture_output=True, timeout=20)
        intent = yaml.safe_load(self.input.read_text())
        for plane in ('management', 'infrastructure'):
            path = self.home / (plane + '.yaml')
            path.write_text(yaml.safe_dump({'apiVersion': 'v1', 'kind': 'Config', 'current-context': 'ignored',
                'contexts': [{'name': plane + '-selected', 'context': {'cluster': plane, 'user': 'identity'}}],
                'clusters': [{'name': plane, 'cluster': {'server': 'https://' + plane + '.invalid',
                    'certificate-authority-data': base64.b64encode(cert.read_bytes()).decode()}}],
                'users': [{'name': 'identity', 'user': {'token': 'SECRET_MUST_NOT_LEAK'}}]}))
            path.chmod(0o600)
            intent['spec'][plane] = {'kubeconfig': './' + path.name}
        self.input.write_text(yaml.safe_dump(intent))
        self.data['infrastructure/ipaddresspools.metallb.io'] = [self.pool()]

    def pool(self, name='endpoints', addresses=None, **options):
        return {'metadata': {'namespace': 'metallb-system', 'name': name},
                'spec': {'addresses': addresses or ['192.168.100.200-192.168.100.210'], **options}}

    def observed_cluster(self, name='existing', namespace=None):
        return {'metadata': {'name': name, 'namespace': namespace or name,
                             'uid': 'observed-uid', 'resourceVersion': '42'},
                'spec': {'controlPlaneEndpoint': {'host': '192.168.100.200'},
                         'clusterNetwork': {'pods': {'cidrBlocks': ['10.32.0.0/16']},
                                            'services': {'cidrBlocks': ['10.96.0.0/20']}}}}

    def assert_no_go(self, result, online=False):
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt['state'], 'PROPOSED_NOT_RESERVED')
        self.assertEqual(receipt['apiContacted'], online)
        self.assertEqual(receipt['observedCollisionCheckCompleted'], online)
        for field in ('globalAvailabilityProven', 'reservationCreated', 'authorizationConsumed', 'mutationAllowed', 'runnerReady'):
            self.assertIs(receipt[field], False)
        self.assertNotIn('SECRET_MUST_NOT_LEAK', result.stdout + result.stderr)
        return receipt

    def test_offline_proposes_without_tools_or_modifying_input_inventory(self):
        path = self.config()
        before = self.input.read_bytes(), path.read_bytes()
        receipt = self.assert_no_go(self.run_proposal())
        self.assertEqual(receipt['proposedNetwork'], {'endpoint': '192.168.100.201',
                         'podCIDR': '10.33.0.0/16', 'serviceCIDR': '10.96.16.0/20'})
        self.assertEqual(before, (self.input.read_bytes(), path.read_bytes()))
        self.assertFalse(self.calls.exists())
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        check = subprocess.run([str(BINARY), 'up', '--file', str(self.output), '--dry-run'],
                               env=self.env, capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertFalse(json.loads(check.stdout)['runnerReady'])
        retained = self.output.read_bytes()
        self.assertNotEqual(self.run_proposal().returncode, 0)
        self.assertEqual(self.output.read_bytes(), retained)

    def test_offline_does_not_read_referenced_kubeconfigs(self):
        intent = yaml.safe_load(self.input.read_text())
        for plane in ('management', 'infrastructure'):
            intent['spec'][plane] = {'kubeconfig': './missing-' + plane}
        self.input.write_text(yaml.safe_dump(intent))
        self.assert_no_go(self.run_proposal())
        proposed = yaml.safe_load(self.output.read_text())
        self.assertEqual(proposed['spec']['management']['kubeconfig'], str(self.home / 'missing-management'))
        self.assertFalse(self.calls.exists())

    def test_containing_and_cross_role_network_overlaps_are_excluded(self):
        self.config(pod='10.32.0.0/15', service='10.96.8.0/21')
        receipt = self.assert_no_go(self.run_proposal())
        self.assertEqual(receipt['proposedNetwork']['podCIDR'], '10.34.0.0/16')
        self.assertEqual(receipt['proposedNetwork']['serviceCIDR'], '10.96.16.0/20')

    def test_retained_managed_preparation_is_inventory(self):
        # os.UserConfigDir differs on macOS and Linux; cover both without using
        # any real user's managed state.
        for prefix in ('Library/Application Support', '.config'):
            parent = self.home / prefix / 'ok/runs/retained/preparation'
            self.config(name='retained', parent=parent)
        receipt = self.assert_no_go(self.run_proposal())
        self.assertEqual(receipt['proposedNetwork']['endpoint'], '192.168.100.201')

    def test_local_name_collision_stops_without_output(self):
        self.config(name='my-cluster')
        result = self.run_proposal()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.calls.exists())

    def test_exhausted_cidr_pool_stops(self):
        self.config(pod='10.32.0.0/11')
        self.assertNotEqual(self.run_proposal().returncode, 0)
        self.assertFalse(self.output.exists())

    def test_duplicate_or_unresolved_or_symlink_inventory_stops(self):
        path = self.config()
        original = path.read_bytes()
        for raw in (original + b'network: {}\n', original.replace(b'10.32.0.0/16', b'auto')):
            path.write_bytes(raw)
            self.assertNotEqual(self.run_proposal().returncode, 0)
            self.assertFalse(self.output.exists())
        other = self.home / 'elsewhere.yaml'
        other.write_bytes(original)
        path.unlink()
        path.symlink_to(other)
        self.assertNotEqual(self.run_proposal().returncode, 0)
        self.assertFalse(self.output.exists())

    def test_online_combines_local_and_both_selected_planes(self):
        self.online_inputs()
        self.config()
        self.data['infrastructure/services'] = [{'spec': {'loadBalancerIP': '192.168.100.201'},
            'status': {'loadBalancer': {'ingress': [{'ip': '192.168.100.202'}]}}}]
        self.data['management/clusters.cluster.x-k8s.io'] = [{'metadata': {'name': 'another'}, 'spec': {
            'controlPlaneEndpoint': {'host': '192.168.100.203'},
            'clusterNetwork': {'pods': {'cidrBlocks': ['10.33.0.0/16']},
                               'services': {'cidrBlocks': ['10.96.16.0/20']}}}}]
        receipt = self.assert_no_go(self.run_proposal(online=True), online=True)
        self.assertEqual(receipt['proposedNetwork'], {'endpoint': '192.168.100.204',
                         'podCIDR': '10.34.0.0/16', 'serviceCIDR': '10.96.32.0/20'})
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(len(calls), 5)
        for args in calls:
            plane = Path(args[1]).stem
            self.assertEqual(args[3], plane + '-selected')
        self.assertEqual(len([source for source in receipt['sources'] if source['kind'] == 'api-list']), 5)

    def test_online_auto_inventory_is_resolved_without_writing_source(self):
        self.online_inputs()
        path = self.config(name='ok-kagent', endpoint='auto', pod='auto', service='auto')
        before = path.read_bytes()
        self.data['management/clusters.cluster.x-k8s.io'] = [self.observed_cluster(name='ok-kagent')]
        receipt = self.assert_no_go(self.run_proposal(online=True), online=True)
        self.assertEqual(receipt['proposedNetwork'], {'endpoint': '192.168.100.201',
                         'podCIDR': '10.33.0.0/16', 'serviceCIDR': '10.96.16.0/20'})
        self.assertEqual(path.read_bytes(), before)
        source = next(item for item in receipt['sources'] if item['kind'] == 'local-cluster-config')
        resolution = source['autoResolution']
        self.assertEqual(resolution['fields'], ['endpoint', 'podCIDR', 'serviceCIDR'])
        self.assertEqual(resolution['observedValues']['podCIDR'], ['10.32.0.0/16'])
        self.assertEqual(resolution['clusters'], [{'plane': 'management', 'name': 'ok-kagent',
            'namespace': 'ok-kagent', 'uid': 'observed-uid', 'resourceVersion': '42'}])

    def test_partial_auto_preserves_concrete_local_and_observed_allocations(self):
        self.online_inputs()
        self.config(endpoint='192.168.100.201', pod='auto', service='10.96.16.0/20')
        self.data['infrastructure/clusters.cluster.x-k8s.io'] = [self.observed_cluster()]
        receipt = self.assert_no_go(self.run_proposal(online=True), online=True)
        self.assertEqual(receipt['proposedNetwork'], {'endpoint': '192.168.100.202',
                         'podCIDR': '10.33.0.0/16', 'serviceCIDR': '10.96.32.0/20'})
        source = next(item for item in receipt['sources'] if item['kind'] == 'local-cluster-config')
        self.assertEqual(source['autoResolution']['fields'], ['podCIDR'])

    def test_offline_auto_error_identifies_file_and_fields_without_api(self):
        path = self.config(endpoint='auto', pod='auto')
        result = self.run_proposal()
        self.assertNotEqual(result.returncode, 0)
        for detail in (str(path), 'endpoint', 'podCIDR', '--online'):
            self.assertIn(detail, result.stderr)
        self.assertFalse(self.calls.exists())
        self.assertFalse(self.output.exists())

    def test_online_auto_missing_wrong_namespace_or_incomplete_cluster_stops(self):
        self.online_inputs()
        path = self.config(endpoint='auto', pod='auto', service='auto')
        incomplete = self.observed_cluster()
        del incomplete['spec']['clusterNetwork']['services']
        missing_uid = self.observed_cluster()
        del missing_uid['metadata']['uid']
        missing_version = self.observed_cluster()
        del missing_version['metadata']['resourceVersion']
        for items in ([], [self.observed_cluster(namespace='unrelated')], [incomplete],
                      [missing_uid], [missing_version]):
            with self.subTest(items=items):
                self.data['management/clusters.cluster.x-k8s.io'] = items
                result = self.run_proposal(online=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(str(path), result.stderr)
                self.assertIn('serviceCIDR', result.stderr)
                self.assertFalse(self.output.exists())

    def test_online_auto_different_planes_are_not_a_unique_identity(self):
        self.online_inputs()
        path = self.config(pod='auto')
        for plane in ('management', 'infrastructure'):
            self.data[plane + '/clusters.cluster.x-k8s.io'] = [self.observed_cluster()]
        result = self.run_proposal(online=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ambiguous', result.stderr)
        self.assertIn(str(path), result.stderr)
        self.assertFalse(self.output.exists())

    def test_online_auto_same_api_uid_and_values_can_be_observed_twice(self):
        self.online_inputs()
        self.config(endpoint='auto', pod='auto', service='auto')
        # Both contexts intentionally refer to exactly the same API + CA.
        mgmt = yaml.safe_load((self.home / 'management.yaml').read_text())
        infra_path = self.home / 'infrastructure.yaml'
        infra = yaml.safe_load(infra_path.read_text())
        infra['clusters'][0]['cluster'] = mgmt['clusters'][0]['cluster']
        infra_path.write_text(yaml.safe_dump(infra))
        for plane in ('management', 'infrastructure'):
            self.data[plane + '/clusters.cluster.x-k8s.io'] = [self.observed_cluster()]
        self.assert_no_go(self.run_proposal(online=True), online=True)
        self.output.unlink()
        # A UID replacement or an allocation changing between snapshots is not
        # the same stable binding, even when both contexts select the same API.
        observed = self.data['infrastructure/clusters.cluster.x-k8s.io'][0]
        observed['metadata']['uid'] = 'replacement'
        self.assertNotEqual(self.run_proposal(online=True).returncode, 0)
        self.assertFalse(self.output.exists())
        observed['metadata']['uid'] = 'observed-uid'
        observed['spec']['clusterNetwork']['pods']['cidrBlocks'] = ['10.33.0.0/16']
        self.assertNotEqual(self.run_proposal(online=True).returncode, 0)
        self.assertFalse(self.output.exists())

    def test_online_failure_never_falls_back_or_leaks_stderr(self):
        self.online_inputs()
        self.data['fail'] = 'clusters.cluster.x-k8s.io'
        result = self.run_proposal(online=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertNotIn('SECRET_MUST_NOT_LEAK', result.stderr)
        self.assertFalse(self.output.exists())

    def test_online_ambiguous_pool_requires_explicit_selection(self):
        self.online_inputs()
        self.data['infrastructure/ipaddresspools.metallb.io'].append(self.pool(name='second'))
        self.assertNotEqual(self.run_proposal(online=True).returncode, 0)
        self.assertFalse(self.output.exists())
        self.assert_no_go(self.run_proposal(online=True, extra=['--pool', 'metallb-system/second']), online=True)

    def test_online_name_collision_stops(self):
        self.online_inputs()
        self.data['management/clusters.cluster.x-k8s.io'] = [{'metadata': {'name': 'my-cluster'}}]
        self.assertNotEqual(self.run_proposal(online=True).returncode, 0)
        self.assertFalse(self.output.exists())

    def test_online_context_ambiguity_stops_before_api(self):
        self.online_inputs()
        path = self.home / 'management.yaml'
        config = yaml.safe_load(path.read_text())
        config['contexts'].append({'name': 'other', 'context': {'cluster': 'management', 'user': 'identity'}})
        path.write_text(yaml.safe_dump(config))
        self.assertNotEqual(self.run_proposal(online=True).returncode, 0)
        self.assertFalse(self.calls.exists())

    def test_online_honors_avoid_buggy_ips_and_pool_selectors(self):
        self.online_inputs()
        self.data['infrastructure/ipaddresspools.metallb.io'] = [self.pool(
            addresses=['192.168.100.0/24'], avoidBuggyIPs=True)]
        receipt = self.assert_no_go(self.run_proposal(online=True), online=True)
        self.assertEqual(receipt['proposedNetwork']['endpoint'], '192.168.100.1')
        self.output.unlink()
        self.data['infrastructure/ipaddresspools.metallb.io'][0]['spec']['serviceAllocation'] = {'namespaces': ['other']}
        self.assertNotEqual(self.run_proposal(online=True).returncode, 0)
        self.assertFalse(self.output.exists())

    def test_existing_output_stops_before_online_queries(self):
        self.online_inputs()
        self.output.write_text('keep me')
        self.assertNotEqual(self.run_proposal(online=True).returncode, 0)
        self.assertEqual(self.output.read_text(), 'keep me')
        self.assertFalse(self.calls.exists())

    def test_online_auth_plugins_are_rejected_before_either_api(self):
        self.online_inputs()
        path = self.home / 'infrastructure.yaml'
        config = yaml.safe_load(path.read_text())
        config['users'][0]['user']['exec'] = {'command': 'must-not-run'}
        path.write_text(yaml.safe_dump(config))
        self.assertNotEqual(self.run_proposal(online=True).returncode, 0)
        self.assertFalse(self.calls.exists())
        self.assertFalse(self.output.exists())

    def test_endpoint_pool_is_excluded_from_cidr_selection(self):
        receipt = self.assert_no_go(self.run_proposal(extra=['--endpoint-pool', '10.32.0.1-10.32.0.10']))
        self.assertEqual(receipt['proposedNetwork']['endpoint'], '10.32.0.1')
        self.assertEqual(receipt['proposedNetwork']['podCIDR'], '10.33.0.0/16')

    def test_missing_online_refs_and_invalid_ranges_fail_without_output(self):
        self.assertNotEqual(self.run_proposal(online=True).returncode, 0)
        for value in ('0.0.0.0/0', '192.168.100.210-192.168.100.200', 'invalid'):
            self.assertNotEqual(self.run_proposal(extra=['--endpoint-pool', value]).returncode, 0)
            self.assertFalse(self.output.exists())
        self.assertFalse(self.calls.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
