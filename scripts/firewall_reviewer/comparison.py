"""Structural comparison is separate from effective-access evaluation."""


def includes(intervals, value):
    return any(lo <= value[0] and hi >= value[1] for lo, hi in intervals)


def compare(current, proposed):
    old = {r["id"]: r for r in current["rules"]}
    new = {r["id"]: r for r in proposed["rules"]}
    changes = []
    for rid in old.keys() - new.keys():
        changes.append({"category": "removed", "rule_id": rid})
    for rid in new.keys() - old.keys():
        changes.append({"category": "added", "rule_id": rid})
    shared = old.keys() & new.keys()
    old_order = [r["id"] for r in current["rules"] if r["id"] in shared]
    new_order = [r["id"] for r in proposed["rules"] if r["id"] in shared]
    for rid in sorted(shared):
        fields = [k for k in old[rid] if k not in ("id", "enabled") and old[rid][k] != new[rid][k]]
        if fields:
            changes.append({"category": "modified", "rule_id": rid, "fields": fields})
        if old[rid]["enabled"] != new[rid]["enabled"]:
            changes.append({"category": "enabled" if new[rid]["enabled"] else "disabled", "rule_id": rid})
        if old_order.index(rid) != new_order.index(rid):
            changes.append({"category": "reordered", "rule_id": rid,
                            "before_shared_index": old_order.index(rid), "after_shared_index": new_order.index(rid)})
        broadened = []
        for axis in ("source", "destination"):
            if not includes([old[rid][axis]], new[rid][axis]):
                broadened.append(axis)
        if any(not includes(old[rid]["ports"], p) for p in new[rid]["ports"]):
            broadened.append("ports")
        if broadened:
            changes.append({"category": "broadened", "rule_id": rid, "dimensions": broadened})
    if current["default_action"] != proposed["default_action"]:
        changes.append({"category": "default_changed", "before": current["default_action"], "after": proposed["default_action"]})
    return sorted(changes, key=lambda x: (x["category"], x.get("rule_id", "")))
