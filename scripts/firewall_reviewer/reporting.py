"""Escape imported content in Markdown; JSON remains the exact evidence artifact."""
import html
import json
from pathlib import Path


def safe(value):
    text = str(value)
    for char in ('\\', '`', '*', '_', '[', ']', '|', '#', '>'):
        text = text.replace(char, '\\' + char)
    return html.escape(text, quote=False).replace('\n', ' ').replace('\r', ' ')


def details(value):
    if isinstance(value, dict):
        if 'action' in value and 'default' in value:
            return value['action'] + ' via ' + ('default action' if value['default'] else 'rule ' + value['rule_id'])
        return '; '.join(f'{k}: {details(v)}' for k, v in value.items())
    if isinstance(value, list):
        return ', '.join(map(str, value))
    return str(value)


def behavior(value):
    if value is None:
        return 'Not an access-transition field for this structural observation.'
    origin = 'default action' if value['default'] else 'rule ' + value['rule_id']
    return safe(value['action'] + ' via ' + origin)


def markdown(report):
    lines = ['# Firewall Change Review', '', report['verdict'], '',
             f"Status: {report['status']}. Evaluation covers supplied configuration semantics only.", '',
             '## Limitations', '']
    lines.extend('- ' + safe(x) for x in report['limitations'])
    if report['errors']:
        lines += ['', '## Errors', ''] + ['- ' + safe(x) for x in report['errors']]
    lines += ['', '## Configuration changes', '']
    for change in report['changes']:
        detail = details({k: v for k, v in change.items() if k != 'category'})
        lines.append('- ' + safe(change['category'] + ': ' + detail))
    if not report['changes']:
        lines.append('None.')
    lines += ['', '## Policy results', '', '| ID | Before violations | After violations | Introduced | Resolved | Existing |', '|---|---:|---:|---:|---:|---:|']
    for p in report['policy_results']:
        lines.append(f"| {safe(p['id'])} | {p['before_violating_connections']} | {p['after_violating_connections']} | {p['introduced_connections']} | {p['resolved_connections']} | {p['existing_connections']} |")
    lines += ['', 'Counts are exact connection tuples, not hosts or live sessions. Partial reviews withhold policy totals.', '', '## Findings', '']
    if not report['findings']:
        lines += ['No findings produced. Read the verdict, coverage, and completeness status above.']
    for f in report['findings']:
        ex = f['example_connection']
        lines += [f"### {f['id']}: {f['category']} ({f['severity']})", '', safe(f['explanation']), '',
                  '- Policy: ' + safe(', '.join(f['policy_ids']) or 'none'),
                  '- Before: ' + behavior(f['before']), '- After: ' + behavior(f['after']),
                  '- Responsible: ' + safe(details(f['responsible'])),
                  '- Example: ' + safe(f"{ex['source']} → {ex['destination']}, {ex['protocol'].upper()}/{ex['port']}"),
                  '- Severity rationale: ' + safe(f['severity_rationale']), '- Correction: ' + safe(f['suggested_correction'])]
        for side, assets in f['assets'].items():
            if assets:
                lines.append('- ' + side.capitalize() + ' assets at example: ' + safe('; '.join(
                    f"{a['name']} (role {a['role']}, owner {a['owner']}, criticality {a['criticality']})" for a in assets)))
        if f['affected_regions']:
            lines.append(f"- Exact affected regions: {len(f['affected_regions'])}; connection tuples: {f['connection_count']}. All regions are in report.json.")
            for r in f['affected_regions'][:5]:
                lines.append('- Region: ' + safe(f"source {r['source'][0]}–{r['source'][1]}; destination {r['destination'][0]}–{r['destination'][1]}; {r['protocol'].upper()} ports {r['ports'][0]}–{r['ports'][1]}"))
            if len(f['affected_regions']) > 5:
                lines.append('- Additional regions are listed in report.json.')
        else:
            lines.append('- Scope: structural observation; the example demonstrates selector/order behavior, not an enumerated access change.')
        if 'matched_connections' in f:
            lines.append(f"- Matched connection tuples: {f['matched_connections']}; tuples where this rule wins: {f['effective_connections']}.")
        lines += ['- Verification: ' + safe(' '.join(f['verification_steps'])),
                  '- Limitations: ' + safe(' '.join(f['limitations'])), '']
    return '\n'.join(lines) + '\n'


def write_reports(report, output_dir):
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    (output / 'report.md').write_text(markdown(report), encoding='utf-8')
