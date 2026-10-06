"""Exact atomic cells: behavior is constant throughout each Cartesian cell."""
from itertools import product
from math import prod


class IncompleteReview(RuntimeError):
    pass


class Budget:
    def __init__(self, max_cells=200_000, max_checks=5_000_000):
        self.max_cells, self.max_checks = max_cells, max_checks
        self.cells = self.checks = 0

    def check(self):
        self.checks += 1
        if self.checks > self.max_checks:
            raise IncompleteReview(f"selector check limit exceeded ({self.max_checks})")


def segments(intervals, end):
    boundaries = {0, end + 1}
    for lo, hi in intervals:
        boundaries.update((lo, hi + 1))
    points = sorted(boundaries)
    return [(a, b - 1) for a, b in zip(points, points[1:])]


def partition(configs, policy, budget):
    selectors = [r for c in configs for r in c["rules"] if r["enabled"]] + policy
    source = segments([r["source"] for r in selectors], 2**32 - 1)
    dest = segments([r["destination"] for r in selectors], 2**32 - 1)
    port = segments([p for r in selectors for p in r["ports"]], 65535)
    count = 2 * prod(map(len, (source, dest, port)))
    if count > budget.max_cells:
        raise IncompleteReview(f"exact partition requires {count} cells; limit is {budget.max_cells}")
    return product(source, dest, port, ("tcp", "udp"))


def matches(rule, connection, budget=None):
    if budget:
        budget.check()
    src, dst, port, protocol = connection
    return (rule["protocol"] == protocol
            and rule["source"][0] <= src <= rule["source"][1]
            and rule["destination"][0] <= dst <= rule["destination"][1]
            and any(lo <= port <= hi for lo, hi in rule["ports"]))


def evaluate(config, connection, budget=None):
    for rule in config["rules"]:
        if rule["enabled"] and matches(rule, connection, budget):
            return {"action": rule["action"], "rule_id": rule["id"], "default": False}
    return {"action": config["default_action"], "rule_id": None, "default": True}


def behavior_and_matches(config, connection, budget):
    matched = [r for r in config["rules"] if r["enabled"] and matches(r, connection, budget)]
    behavior = ({"action": matched[0]["action"], "rule_id": matched[0]["id"], "default": False}
                if matched else {"action": config["default_action"], "rule_id": None, "default": True})
    return behavior, matched
