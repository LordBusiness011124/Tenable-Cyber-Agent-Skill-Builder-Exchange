"""Review validated inputs with exact cells, stable evidence, and explicit limits."""
import ipaddress
from itertools import combinations

from .comparison import compare
from .evaluation import Budget, IncompleteReview, behavior_and_matches, matches, partition
from .validation import validate_config, validate_policy, validate_inventory

LIMITATIONS = [
    "Permitted access in supplied configurations does not prove live network reachability.",
    "Policy coverage is limited to supplied requirements; unspecified access is not authorized or forbidden by inference.",
    "Single ordered IPv4 firewall only: no NAT, routing, IPv6, state, application identity, or multiple hops.",
    "Asset context describes the example connection only; inventory labels are untrusted and do not determine policy or severity.",
]


def connection(cell):
    source, destination, port, protocol = cell
    return {"source": str(ipaddress.IPv4Address(source[0])),
            "destination": str(ipaddress.IPv4Address(destination[0])),
            "protocol": protocol, "port": port[0]}


def region(cell):
    source, destination, port, protocol = cell
    return {"source": [str(ipaddress.IPv4Address(v)) for v in source],
            "destination": [str(ipaddress.IPv4Address(v)) for v in destination],
            "ports": list(port), "protocol": protocol}


def asset_context(example, inventory):
    result = {}
    for side in ("source", "destination"):
        value = int(ipaddress.IPv4Address(example[side]))
        result[side] = [{k: v for k, v in a.items() if k != "address"}
                        for a in inventory if a["address"][0] <= value <= a["address"][1]]
    return result


def review(current, proposed, policy, inventory=None, *, max_cells=200_000, max_checks=5_000_000):
    """Accept raw JSON objects. Invalid input raises ValidationError; exhaustion returns incomplete."""
    if type(max_cells) is not int or type(max_checks) is not int or max_cells < 1 or max_checks < 1:
        raise ValueError("resource limits must be positive integers")
    current, proposed = validate_config(current), validate_config(proposed)
    policy = validate_policy(policy)
    inventory = validate_inventory(inventory) if inventory is not None else []
    budget = Budget(max_cells, max_checks)
    report = {"report_version": 1, "status": "complete", "verdict": "No new violations within supplied policy coverage",
              "limitations": LIMITATIONS.copy(), "changes": compare(current, proposed),
              "policy_results": [], "findings": [], "errors": [],
              "limits": {"max_cells": max_cells, "max_selector_checks": max_checks}}
    grouped = {}
    evidence_records = 0
    stats = {p["id"]: {"id": p["id"], "description": p["description"], "status": p["status"],
                         "before_violating_connections": 0, "after_violating_connections": 0,
                         "introduced_connections": 0, "resolved_connections": 0, "existing_connections": 0,
                         "total_connections": 0} for p in policy}
    rule_stats = [{r["id"]: {"matches": 0, "wins": 0, "covering": set(), "cell": None}
                   for r in c["rules"] if r["enabled"]} for c in (current, proposed)]
    overlaps = [dict(), dict()]

    def add(category, explanation, policies, before, after, cell, severity, rationale, correction,
            key_extra="", responsible=None, include_region=True):
        nonlocal evidence_records
        ids = tuple(sorted(policies))
        key = (category, ids, str(before), str(after), key_extra)
        if key not in grouped:
            if len(grouped) >= 20_000:
                raise IncompleteReview("grouped finding limit exceeded (20000)")
            example = connection(cell)
            grouped[key] = {"category": category, "explanation": explanation, "policy_ids": list(ids),
                            "before": before, "after": after,
                            "responsible": responsible or {"before": before, "after": after},
                            "example_connection": example, "assets": asset_context(example, inventory),
                            "severity": severity, "severity_rationale": rationale,
                            "suggested_correction": correction,
                            "verification_steps": ["Rerun the reviewer against a corrected proposal and the same confirmed policy.",
                                                   "Check this example and every affected region in report.json; require a complete result."],
                            "limitations": LIMITATIONS.copy(), "affected_regions": [], "connection_count": 0}
        finding = grouped[key]
        if include_region:
            evidence_records += 1
            if evidence_records > 100_000:
                raise IncompleteReview("stored evidence region limit exceeded (100000)")
            finding["affected_regions"].append(region(cell))
            finding["connection_count"] += (cell[0][1] - cell[0][0] + 1) * (cell[1][1] - cell[1][0] + 1) * (cell[2][1] - cell[2][0] + 1)
        return finding

    try:
        for cell in partition((current, proposed), policy, budget):
            budget.cells += 1
            src, dst, port, protocol = cell
            point = (src[0], dst[0], port[0], protocol)
            before, old_matches = behavior_and_matches(current, point, budget)
            after, new_matches = behavior_and_matches(proposed, point, budget)
            volume = (src[1] - src[0] + 1) * (dst[1] - dst[0] + 1) * (port[1] - port[0] + 1)
            for snapshot, matched in enumerate((old_matches, new_matches)):
                for index, rule in enumerate(matched):
                    st = rule_stats[snapshot][rule["id"]]
                    st["matches"] += volume
                    st["cell"] = st["cell"] or cell
                    if index == 0:
                        st["wins"] += volume
                    else:
                        st["covering"].add(matched[0]["id"])
                for first, second in combinations(matched, 2):
                    budget.check()
                    overlaps[snapshot].setdefault((first["id"], second["id"]), cell)
            related = []
            for requirement in policy:
                if not matches(requirement, point, budget):
                    continue
                pid = requirement["id"]
                related.append(pid)
                expected = "allow" if requirement["status"] == "required" else "deny"
                bad_before, bad_after = before["action"] != expected, after["action"] != expected
                st = stats[pid]
                st["total_connections"] += volume
                st["before_violating_connections"] += volume * bad_before
                st["after_violating_connections"] += volume * bad_after
                category = ("introduced" if bad_after and not bad_before else
                            "resolved" if bad_before and not bad_after else
                            "existing" if bad_before and bad_after else None)
                if category:
                    st[category + "_connections"] += volume
                    forbidden = requirement["status"] == "forbidden"
                    if category == "resolved":
                        correction = f"Preserve the corrected {expected} behavior for {pid}; rerun all requirements before accepting the proposal."
                    elif forbidden:
                        correction = (f"Narrow or remove allow rule {after['rule_id']} for the affected regions of {pid}; "
                                      if not after["default"] else f"Add an explicit deny for the affected regions of {pid} before the allow default; ")
                        correction += "alternatively restore an earlier applicable deny. Rerun all requirements to check the correction."
                    else:
                        correction = f"Add an allow limited to the affected required regions of {pid} "
                        correction += (f"before deny rule {after['rule_id']}, or narrow that deny; "
                                       if not after["default"] else "before the deny default; ")
                        correction += "rerun all requirements and inspect other changed access."
                    add("policy_violation_" + category,
                        f"{requirement['status'].capitalize()} access {pid}: violation {category} for the listed regions.",
                        [pid], before, after, cell,
                        "info" if category == "resolved" else "high" if forbidden else "medium",
                        "Resolved violations are informational." if category == "resolved" else
                        "Explicit forbidden access is permitted by configuration." if forbidden else
                        "Explicit required connectivity is denied by configuration; business impact is not established.",
                        correction)
            if before["action"] != after["action"]:
                permitted = after["action"] == "allow"
                add("newly_permitted" if permitted else "newly_blocked",
                    "The change permits previously denied access." if permitted else "The change denies previously permitted access.",
                    related, before, after, cell, "info",
                    "Behavior change alone does not establish a policy violation.",
                    "Confirm the changed regions against explicit policy; narrow or restore access if unintended.")

        report["policy_results"] = [stats[p["id"]] for p in policy]
        for snapshot, config in enumerate((current, proposed)):
            label = "current" if snapshot == 0 else "proposed"
            lookup = {r["id"]: r for r in config["rules"]}
            for rid, st in rule_stats[snapshot].items():
                if st["wins"] < st["matches"]:
                    full = st["wins"] == 0
                    winner, _ = behavior_and_matches(config, (st["cell"][0][0], st["cell"][1][0], st["cell"][2][0], st["cell"][3]), budget)
                    # Pick an actually covered point; the first structural cell may be reachable.
                    if not full:
                        covered_cell = next(c for pair, c in overlaps[snapshot].items() if pair[1] == rid)
                        winner, _ = behavior_and_matches(config, (covered_cell[0][0], covered_cell[1][0], covered_cell[2][0], covered_cell[3]), budget)
                    else:
                        covered_cell = st["cell"]
                    f = add("fully_shadowed" if full else "partially_shadowed",
                        f"In {label}, rule {rid} never wins." if full else f"In {label}, earlier rules cover part of rule {rid}.",
                        [], winner if snapshot == 0 else None, winner if snapshot == 1 else None,
                        covered_cell, "info", "Rule reachability observation; it is not itself a policy violation.",
                        "Inspect earlier rules and intended order. Remove redundant rules or reorder only after reviewing the corrected proposal.",
                        key_extra=label + rid, responsible={"snapshot": label, "rule_id": rid, "covering_rule_ids": sorted(st["covering"])}, include_region=False)
                    f["matched_connections"] = st["matches"]
                    f["effective_connections"] = st["wins"]
            for (first, second), overlap_cell in overlaps[snapshot].items():
                a, b = lookup[first], lookup[second]
                # Same-action overlaps also matter to ordering and rule maintenance.
                if rule_stats[snapshot][second]["wins"] == 0:
                    continue  # Already explained as full shadowing.
                add("partial_overlap", f"In {label}, rules {first} and {second} intersect; {first} precedes {second}.",
                    [], None, None, overlap_cell, "info", "Selector overlap is an ordering observation, not proof of a violation.",
                    "Confirm overlap and intended precedence; review a narrowed or reordered proposal before use.",
                    key_extra=label + first + ":" + second,
                    responsible={"snapshot": label, "rule_ids": [first, second], "actions": [a["action"], b["action"]]}, include_region=False)
        for change in report["changes"]:
            if change["category"] != "broadened":
                continue
            r = next(r for r in proposed["rules"] if r["id"] == change["rule_id"])
            cell = (r["source"], r["destination"], r["ports"][0], r["protocol"])
            point = (cell[0][0], cell[1][0], cell[2][0], cell[3])
            b, _ = behavior_and_matches(current, point, budget)
            a, _ = behavior_and_matches(proposed, point, budget)
            add("broadening", f"Rule {r['id']} includes values previously outside its {', '.join(change['dimensions'])} selectors. The example is within its proposed scope; effective changes have separate evidence.",
                [], b, a, cell, "info", "Broadening alone is not evidence of unauthorized access; disabled and shadowed rules may have no effect.",
                "Confirm the wider selectors against approved intent and narrow them if unnecessary.", key_extra=r["id"],
                responsible={"rule_id": r["id"], "dimensions": change["dimensions"]}, include_region=False)
        if any(st["introduced_connections"] for st in stats.values()):
            report["verdict"] = "Policy violations introduced"
        if not policy:
            report["limitations"].append("No requirements supplied: policy coverage is empty; only configuration behavior was reviewed.")
    except IncompleteReview as exc:
        report["status"] = "incomplete"
        report["verdict"] = "Incomplete review"
        report["errors"].append(str(exc))
        report["limitations"].append("All findings and counts are partial; policy results are withheld because evaluation did not finish.")
        report["policy_results"] = []
    for i, finding in enumerate(grouped.values(), 1):
        finding["id"] = f"F-{i:04d}"
        finding["evaluation_complete"] = report["status"] == "complete"
        if report["status"] != "complete":
            finding["limitations"].append("Evaluation stopped early; affected regions and counts are partial.")
        report["findings"].append(finding)
    report["evaluation"] = {"cells_evaluated": budget.cells, "selector_checks": budget.checks,
                            "policy_requirement_count": len(policy), "scope": "entire IPv4 / TCP+UDP / ports 0..65535"}
    return report
