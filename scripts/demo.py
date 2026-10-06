#!/usr/bin/env python3
"""Run fictional examples and assert workshop acceptance criteria."""
import argparse
from pathlib import Path

from firewall_reviewer import review
from firewall_reviewer.reporting import write_reports
from firewall_reviewer.validation import load_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=Path('reports/demo'))
    args = parser.parse_args()
    examples = Path(__file__).resolve().parents[1] / 'examples'
    def data(name):
        return load_json(examples / (name + '.json'))
    cases = [
        ('unauthorized', 'current', 'unauthorized', 'introduced_connections', 'P-guests', 128),
        ('blocked', 'current', 'blocked', 'introduced_connections', 'P-employees', 128),
        ('broadened', 'current', 'broadened', None, None, None),
        ('shadowed', 'current', 'shadowed', None, None, None),
        ('existing', 'existing-violation', 'existing-violation', 'existing_connections', 'P-database', 1),
        ('resolved', 'unauthorized', 'corrected', 'resolved_connections', 'P-guests', 128),
        ('corrected', 'current', 'corrected', None, None, None),
        ('incomplete', 'current', 'unauthorized', None, None, None),
    ]
    for name, old, new, field, pid, count in cases:
        report = review(data(old), data(new), data('policy'), data('inventory'),
                        **({'max_cells': 1} if name == 'incomplete' else {}))
        expected = ('Incomplete review' if name == 'incomplete' else 'Policy violations introduced'
                    if name in ('unauthorized', 'blocked') else 'No new violations within supplied policy coverage')
        if report['verdict'] != expected:
            raise RuntimeError(f'{name}: unexpected verdict {report["verdict"]}')
        if field:
            actual = next(p[field] for p in report['policy_results'] if p['id'] == pid)
            if actual != count:
                raise RuntimeError(f'{name}: expected {count}, got {actual}')
        if name in ('broadened', 'shadowed'):
            category = 'broadening' if name == 'broadened' else 'fully_shadowed'
            if not any(f['category'] == category for f in report['findings']):
                raise RuntimeError(f'{name}: missing {category}')
        write_reports(report, args.output_dir / name)
        print(f'{name}: {report["verdict"]} (verified)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
