"""CLI exit codes: 0 complete/no introduced violation, 1 introduced, 2 invalid, 3 incomplete."""
import argparse
import sys
from pathlib import Path

from .review import LIMITATIONS, review
from .reporting import write_reports
from .validation import ValidationError, load_json


def main(argv=None):
    parser = argparse.ArgumentParser(description="Review offline vendor-neutral IPv4 firewall JSON changes.")
    for name in ("current", "proposed", "policy"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--max-cells", type=int, default=200_000)
    parser.add_argument("--max-checks", type=int, default=5_000_000)
    args = parser.parse_args(argv)
    # Prevent a report path from overwriting an input; no imported commands are executed.
    targets = {(args.output_dir / n).resolve() for n in ("report.json", "report.md")}
    if any(p and p.resolve() in targets for p in (args.current, args.proposed, args.policy, args.inventory)):
        parser.error("output report paths must not overwrite input files")
    try:
        report = review(load_json(args.current), load_json(args.proposed), load_json(args.policy),
                        load_json(args.inventory) if args.inventory else None,
                        max_cells=args.max_cells, max_checks=args.max_checks)
    except (ValidationError, OSError, ValueError, RecursionError) as exc:
        report = {"report_version": 1, "status": "invalid", "verdict": "Incomplete review", "errors": [str(exc)],
                  "limitations": LIMITATIONS + ["Input validation failed; no evaluation was performed."],
                  "findings": [], "policy_results": [], "changes": []}
    try:
        write_reports(report, args.output_dir)
    except OSError as exc:
        print(f"Cannot write reports: {exc}", file=sys.stderr)
        return 2
    print(report["verdict"])
    print(f"Reports: {args.output_dir / 'report.json'} and {args.output_dir / 'report.md'}")
    for error in report["errors"]:
        print(error, file=sys.stderr)
    return (2 if report["status"] == "invalid" else 3 if report["status"] == "incomplete" else
            1 if report["verdict"] == "Policy violations introduced" else 0)


if __name__ == "__main__":
    raise SystemExit(main())
