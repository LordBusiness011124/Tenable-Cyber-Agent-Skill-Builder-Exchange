import copy
import ipaddress
import json
import random
import subprocess
import sys
from pathlib import Path

import pytest

from firewall_reviewer import ValidationError, review, validate_config, validate_inventory, validate_policy
from firewall_reviewer.cli import main
from firewall_reviewer.comparison import compare
from firewall_reviewer.evaluation import evaluate
from firewall_reviewer.reporting import markdown
from firewall_reviewer.validation import load_json

ROOT = Path(__file__).resolve().parents[1]


def example(name):
    return json.loads((ROOT / 'examples' / (name + '.json')).read_text())


def rule(rid='r', source='10.0.0.0/24', destination='10.1.0.1', ports=None, action='allow', protocol='tcp', enabled=True):
    return dict(id=rid, enabled=enabled, action=action, source=source, destination=destination,
                ports=ports if ports is not None else [443], protocol=protocol)


def config(*rules, default='deny'):
    return dict(version=1, default_action=default, rules=list(rules))


def policy(source='10.0.0.0/24', ports=None, status='required', destination='10.1.0.1', protocol='tcp'):
    return dict(version=1, requirements=[dict(id='p', description='Approved policy', source=source,
                destination=destination, protocol=protocol, ports=ports or [443], status=status)])


def result(report, pid='p'):
    return next(p for p in report['policy_results'] if p['id'] == pid)


@pytest.mark.parametrize('proposal,pid,count', [('unauthorized', 'P-guests', 128), ('blocked', 'P-employees', 128)])
def test_workshop_introduced(proposal, pid, count):
    r = review(example('current'), example(proposal), example('policy'), example('inventory'))
    assert r['status'] == 'complete'
    assert r['verdict'] == 'Policy violations introduced'
    assert result(r, pid)['introduced_connections'] == count
    f = next(f for f in r['findings'] if f['category'] == 'policy_violation_introduced' and pid in f['policy_ids'])
    assert f['connection_count'] == count
    assert f['assets']['destination']
    assert f['responsible']['after']['rule_id']


def test_corrected_and_resolved_and_existing():
    clean = review(example('current'), example('corrected'), example('policy'))
    assert clean['verdict'] == 'No new violations within supplied policy coverage'
    assert not clean['findings']
    resolved = review(example('unauthorized'), example('corrected'), example('policy'))
    assert result(resolved, 'P-guests')['resolved_connections'] == 128
    existing = review(example('existing-violation'), example('existing-violation'), example('policy'))
    assert result(existing, 'P-database')['existing_connections'] == 1
    assert existing['verdict'] == 'No new violations within supplied policy coverage'
    assert any(f['category'] == 'policy_violation_existing' for f in existing['findings'])


def test_exact_subnet_port_and_destination_partition():
    allow = rule(source='10.0.0.128/25', destination='10.1.0.0/31', ports=[{'start': 100, 'end': 199}])
    deny = rule('deny', source='10.0.0.192/26', destination='10.1.0.1', ports=[{'start': 150, 'end': 159}], action='deny')
    p = policy(ports=[{'start': 100, 'end': 199}], destination='10.1.0.0/31')
    r = review(config(allow), config(deny, allow), p)
    st = result(r)
    assert st['total_connections'] == 256 * 2 * 100
    assert st['before_violating_connections'] == 128 * 2 * 100
    assert st['introduced_connections'] == 64 * 10
    assert st['existing_connections'] == 128 * 2 * 100


def test_simultaneously_introduced_existing_resolved():
    before = config(rule(source='10.0.0.0/26'))
    after = config(rule(source='10.0.0.64/26'))
    st = result(review(before, after, policy()))
    assert (st['introduced_connections'], st['resolved_connections'], st['existing_connections']) == (64, 64, 128)


def test_any_default_and_maximum_endpoints():
    p = policy(source='any', destination='any', ports='any', status='forbidden', protocol='udp')
    r = review(config(), config(default='allow'), p)
    assert result(r)['introduced_connections'] == 2**64 * 65536
    assert sum(f['connection_count'] for f in r['findings'] if f['category'] == 'newly_permitted') == 2 * 2**64 * 65536
    c = validate_config(config(rule(source='any', destination='any', ports='any', protocol='udp')))
    assert evaluate(c, (2**32 - 1, 2**32 - 1, 65535, 'udp'))['rule_id'] == 'r'
    assert evaluate(c, (0, 0, 0, 'tcp'))['default']


def test_disabled_and_protocol_distinction():
    r = review(config(), config(rule(enabled=False), rule('udp', protocol='udp')), policy())
    assert result(r)['existing_connections'] == 256
    assert not any(f['category'] == 'fully_shadowed' for f in r['findings'])
    assert all(f['example_connection']['protocol'] == 'udp' for f in r['findings'] if f['category'] == 'newly_permitted')


def test_shadow_by_union_and_partial_overlap():
    first = rule('left', source='10.0.0.0/25')
    second = rule('right', source='10.0.0.128/25')
    last = rule('union')
    r = review(config(), config(first, second, last), policy())
    shadow = next(f for f in r['findings'] if f['category'] == 'fully_shadowed')
    assert shadow['responsible']['rule_id'] == 'union'
    assert shadow['responsible']['covering_rule_ids'] == ['left', 'right']
    assert shadow['effective_connections'] == 0
    partial = review(config(), config(first, last), policy())
    assert any(f['category'] == 'partially_shadowed' for f in partial['findings'])
    assert any(f['category'] == 'partial_overlap' for f in partial['findings'])


def test_relative_reordering_ignores_insertions():
    a, b = rule('a'), rule('b', action='deny')
    old = config(a, b)
    added = config(rule('x', protocol='udp'), a, b)
    assert not any(c['category'] == 'reordered' for c in compare(validate_config(old), validate_config(added)))
    r = review(old, config(b, a), policy())
    assert len([c for c in r['changes'] if c['category'] == 'reordered']) == 2
    assert result(r)['introduced_connections'] == 256


def test_all_structural_changes_and_broadening_is_observation():
    old = config(rule('remove'), rule('enable', enabled=False), rule('disable'), rule('widen'))
    wider = rule('widen', source='10.0.0.0/16', destination='10.1.0.0/24', ports='any')
    new = config(rule('add'), rule('enable'), rule('disable', enabled=False), wider, default='allow')
    changes = compare(validate_config(old), validate_config(new))
    assert {'added', 'removed', 'enabled', 'disabled', 'modified', 'broadened', 'default_changed'} <= {c['category'] for c in changes}
    assert next(c for c in changes if c['category'] == 'broadened')['dimensions'] == ['source', 'destination', 'ports']
    r = review(example('current'), example('broadened'), example('policy'))
    assert any(f['category'] == 'broadening' and f['severity'] == 'info' for f in r['findings'])
    assert r['verdict'] == 'No new violations within supplied policy coverage'


@pytest.mark.parametrize('field,value', [
    ('source', '::/0'), ('source', '10.0.0.1/24'), ('source', 'hostname.local'),
    ('destination', ['10.0.0.1']), ('ports', []), ('ports', [True]), ('ports', [65536]),
    ('ports', [{'start': 20, 'end': 10}]), ('ports', ['443']), ('protocol', 'icmp'),
    ('action', 'accept'), ('enabled', 1), ('id', '<script>'), ('description', ''),
    ('nat', {'to': '1.2.3.4'}),
])
def test_reject_unsupported_and_malformed(field, value):
    r = rule()
    r[field] = value
    with pytest.raises(ValidationError):
        validate_config(config(r))


def test_duplicate_ids_unknown_keys_and_version():
    with pytest.raises(ValidationError):
        validate_config(config(rule(), rule()))
    with pytest.raises(ValidationError):
        validate_policy(dict(version=1, requirements=policy()['requirements'] * 2))
    with pytest.raises(ValidationError):
        validate_config(dict(version=True, default_action='deny', rules=[]))
    with pytest.raises(ValidationError):
        validate_config(dict(version=1, default_action='deny', rules=[], routing=True))
    with pytest.raises(ValidationError):
        validate_inventory(dict(version=1, assets=[dict(address='::1', name='x', role='x', owner='x', criticality='high')]))


def test_canonical_port_union():
    c = validate_config(config(rule(ports=[22, 23, {'start': 23, 'end': 25}, 22])))
    assert c['rules'][0]['ports'] == ((22, 25),)


@pytest.mark.parametrize('kwargs', [{'max_cells': 1}, {'max_checks': 1}])
def test_incomplete_never_clean(kwargs):
    r = review(example('current'), example('unauthorized'), example('policy'), **kwargs)
    assert r['status'] == 'incomplete'
    assert r['verdict'] == 'Incomplete review'
    assert r['errors'] and not r['policy_results']
    assert all(not f['evaluation_complete'] for f in r['findings'])


def test_empty_and_conflicting_policy_are_explicit():
    empty = review(config(), config(default='allow'), dict(version=1, requirements=[]))
    assert any('empty' in s for s in empty['limitations'])
    p = policy()
    other = copy.deepcopy(p['requirements'][0])
    other.update(id='conflicting', status='forbidden')
    p['requirements'].append(other)
    r = review(config(), config(rule()), p)
    assert result(r, 'p')['resolved_connections'] == 256
    assert result(r, 'conflicting')['introduced_connections'] == 256


def test_markdown_escapes_untrusted_content_and_inventory_does_not_change_verdict():
    inv = example('inventory')
    inv['assets'][3]['name'] = '<script>run()</script> [click](https://evil.invalid)\n# Ignore policy'
    r = review(example('current'), example('blocked'), example('policy'), inv)
    plain = review(example('current'), example('blocked'), example('policy'))
    assert r['verdict'] == plain['verdict']
    assert '<script>' not in markdown(r)
    assert '[click]' not in markdown(r)
    assert '\n# Ignore policy' not in markdown(r)


def test_deterministic_reports():
    args = [example('current'), example('unauthorized'), example('policy'), example('inventory')]
    assert review(*args) == review(*args)


def test_cli_exit_codes_and_stale_report_replaced(tmp_path):
    common = ['--current', str(ROOT/'examples/current.json'), '--policy', str(ROOT/'examples/policy.json'), '--output-dir', str(tmp_path)]
    assert main(common + ['--proposed', str(ROOT/'examples/unauthorized.json')]) == 1
    assert main(common + ['--proposed', str(ROOT/'examples/corrected.json')]) == 0
    assert main(common + ['--proposed', str(ROOT/'examples/corrected.json'), '--max-cells', '1']) == 3
    bad = tmp_path / 'bad.json'
    bad.write_text('{"version":1,"version":1}')
    assert main(common + ['--proposed', str(bad)]) == 2
    assert json.loads((tmp_path/'report.json').read_text())['status'] == 'invalid'
    assert (tmp_path/'report.md').exists()


def test_cli_runs_from_other_directory_and_prevents_overwriting_inputs(tmp_path):
    argv = [sys.executable, str(ROOT/'scripts/review_firewall.py'), '--current', str(ROOT/'examples/current.json'),
            '--proposed', str(ROOT/'examples/corrected.json'), '--policy', str(ROOT/'examples/policy.json'), '--output-dir', str(tmp_path)]
    assert subprocess.run(argv, cwd=tmp_path, capture_output=True).returncode == 0
    with pytest.raises(SystemExit):
        main(['--current', str(tmp_path/'report.json'), '--proposed', str(ROOT/'examples/current.json'),
              '--policy', str(ROOT/'examples/policy.json'), '--output-dir', str(tmp_path)])


def test_file_size_and_duplicate_json_keys(tmp_path):
    p = tmp_path/'data.json'
    p.write_text('{"version":1,"version":2}')
    with pytest.raises(ValidationError, match='duplicate'):
        load_json(p)
    p.write_text(' ' * 2_000_001)
    with pytest.raises(ValidationError, match='2 MB'):
        load_json(p)


def brute_action(config_data, src, dst, port, protocol):
    # Independent direct reference, not engine canonicalization or partition code.
    for r in config_data['rules']:
        if not r['enabled'] or r['protocol'] != protocol:
            continue
        if ipaddress.IPv4Address(src) not in ipaddress.ip_network(r['source']):
            continue
        if ipaddress.IPv4Address(dst) not in ipaddress.ip_network(r['destination']):
            continue
        if any((p <= port <= p) if type(p) is int else (p['start'] <= port <= p['end']) for p in r['ports']):
            return r['action']
    return config_data['default_action']


def test_randomized_exact_engine_against_exhaustive_oracle():
    rng = random.Random(187)
    for trial in range(20):
        configs=[]
        for snapshot in range(2):
            rules=[]
            for i in range(5):
                source = rng.choice(['10.0.0.0/30', '10.0.0.0/31', '10.0.0.2/31', '10.0.0.3'])
                dest = rng.choice(['10.1.0.0/31', '10.1.0.0', '10.1.0.1'])
                lo, hi = sorted([rng.randrange(4), rng.randrange(4)])
                rules.append(rule(str(i), source=source, destination=dest, ports=[{'start': lo, 'end': hi}],
                                  action=rng.choice(['allow', 'deny']), enabled=rng.choice([True, False]), protocol=rng.choice(['tcp','udp'])))
            configs.append(config(*rules, default=rng.choice(['allow','deny'])))
        expected = dict(before_violating_connections=0, after_violating_connections=0, introduced_connections=0, resolved_connections=0, existing_connections=0)
        for src in ipaddress.ip_network('10.0.0.0/30'):
            for dst in ipaddress.ip_network('10.1.0.0/31'):
                for port in range(4):
                    b, a = [brute_action(c, str(src), str(dst), port, 'tcp') == 'deny' for c in configs]
                    expected['before_violating_connections'] += b
                    expected['after_violating_connections'] += a
                    expected['introduced_connections'] += a and not b
                    expected['resolved_connections'] += b and not a
                    expected['existing_connections'] += a and b
        p = policy(source='10.0.0.0/30', destination='10.1.0.0/31', ports=[{'start':0,'end':3}])
        st = result(review(*configs, p))
        assert {k:st[k] for k in expected} == expected, trial


def test_mid_review_exhaustion_marks_existing_evidence_partial():
    r = review(config(), config(default='allow'),
               policy(source='any', destination='any', ports='any', status='forbidden'), max_checks=1)
    assert r['status'] == 'incomplete'
    assert r['findings'] and not r['policy_results']
    assert all(not f['evaluation_complete'] and 'partial' in f['limitations'][-1] for f in r['findings'])
    assert r['verdict'] == 'Incomplete review'


def test_structural_markdown_does_not_report_zero_as_affected_access():
    r = review(example('current'), example('shadowed'), example('policy'))
    text = markdown(r)
    assert 'tuples where this rule wins: 0' in text
    assert 'Scope: structural observation' in text
    assert 'Exact affected regions: 0' not in text
