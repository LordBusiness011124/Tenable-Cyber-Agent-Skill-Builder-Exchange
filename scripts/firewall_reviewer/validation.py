"""Strict JSON validation and canonical inclusive intervals."""
import ipaddress
import json
import re
from pathlib import Path


class ValidationError(ValueError):
    pass


def fail(where, message):
    raise ValidationError(f"{where}: {message}")


def obj(value, required, optional, where):
    if not isinstance(value, dict):
        fail(where, "expected an object")
    missing = set(required) - value.keys()
    extra = value.keys() - set(required) - set(optional)
    if missing or extra:
        fail(where, f"missing fields {sorted(missing)}; unsupported fields {sorted(extra)}")


def text(value, where):
    if not isinstance(value, str) or not value.strip() or len(value) > 2000:
        fail(where, "expected nonempty text, at most 2000 characters")
    return value


def identifier(value, where):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", value):
        fail(where, "ID must contain 1–80 ASCII letters, digits, underscores, dots or hyphens")
    return value


def choice(value, options, where):
    if not isinstance(value, str) or value not in options:
        fail(where, f"expected one of {sorted(options)}")
    return value


def address(value, where):
    if value == "any":
        return (0, 2**32 - 1)
    if not isinstance(value, str):
        fail(where, "expected IPv4 address, canonical CIDR, or 'any'")
    try:
        net = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        fail(where, f"invalid IPv4 address/CIDR: {exc}")
    if net.version != 4:
        fail(where, "IPv6 is unsupported")
    return (int(net.network_address), int(net.broadcast_address))


def merge(intervals):
    result = []
    for lo, hi in sorted(intervals):
        if result and lo <= result[-1][1] + 1:
            result[-1] = (result[-1][0], max(result[-1][1], hi))
        else:
            result.append((lo, hi))
    return tuple(result)


def ports(value, where):
    if value == "any":
        return ((0, 65535),)
    if not isinstance(value, list) or not value or len(value) > 256:
        fail(where, "expected 'any' or a nonempty list of at most 256 ports/ranges")
    result = []
    for item in value:
        if type(item) is int:
            lo = hi = item
        elif isinstance(item, dict):
            obj(item, ["start", "end"], [], where)
            lo, hi = item["start"], item["end"]
        else:
            fail(where, "ports must be integers or {start, end} objects")
        if type(lo) is not int or type(hi) is not int or not 0 <= lo <= hi <= 65535:
            fail(where, "ports must be ordered integers within 0..65535 (booleans forbidden)")
        result.append((lo, hi))
    return merge(result)


def version(value, where):
    if type(value) is not int or value != 1:
        fail(where, "version must be integer 1")


def selectors(item, where):
    return {"source": address(item["source"], where + ".source"),
            "destination": address(item["destination"], where + ".destination"),
            "protocol": choice(item["protocol"], {"tcp", "udp"}, where + ".protocol"),
            "ports": ports(item["ports"], where + ".ports")}


def records(value, limit, where):
    if not isinstance(value, list) or len(value) > limit:
        fail(where, f"expected list of at most {limit} entries")
    return value


def validate_config(value):
    obj(value, ["version", "default_action", "rules"], [], "configuration")
    version(value["version"], "configuration.version")
    default = choice(value["default_action"], {"allow", "deny"}, "default_action")
    rules, seen = [], set()
    for i, item in enumerate(records(value["rules"], 200, "rules")):
        where = f"rules[{i}]"
        obj(item, ["id", "enabled", "action", "source", "destination", "protocol", "ports"], ["description"], where)
        rid = identifier(item["id"], where + ".id")
        if rid in seen:
            fail(where, "duplicate rule ID")
        seen.add(rid)
        if type(item["enabled"]) is not bool:
            fail(where, "enabled must be a boolean")
        if "description" in item:
            text(item["description"], where + ".description")
        rules.append({"id": rid, "enabled": item["enabled"],
                      "action": choice(item["action"], {"allow", "deny"}, where + ".action"),
                      "description": item.get("description", ""), **selectors(item, where)})
    return {"default_action": default, "rules": rules}


def validate_policy(value):
    obj(value, ["version", "requirements"], [], "policy")
    version(value["version"], "policy.version")
    requirements, seen = [], set()
    for i, item in enumerate(records(value["requirements"], 200, "requirements")):
        where = f"requirements[{i}]"
        obj(item, ["id", "description", "source", "destination", "protocol", "ports", "status"], [], where)
        pid = identifier(item["id"], where + ".id")
        if pid in seen:
            fail(where, "duplicate policy ID")
        seen.add(pid)
        requirements.append({"id": pid, "description": text(item["description"], where + ".description"),
                             "status": choice(item["status"], {"required", "forbidden"}, where + ".status"),
                             **selectors(item, where)})
    return requirements


def validate_inventory(value):
    obj(value, ["version", "assets"], [], "inventory")
    version(value["version"], "inventory.version")
    result = []
    for i, item in enumerate(records(value["assets"], 1000, "assets")):
        where = f"assets[{i}]"
        obj(item, ["address", "name", "role", "owner", "criticality"], [], where)
        result.append({"address": address(item["address"], where + ".address"),
                       **{k: text(item[k], where + "." + k) for k in ("name", "role", "owner")},
                       "criticality": choice(item["criticality"], {"low", "medium", "high", "critical"}, where + ".criticality")})
    return result


def load_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                fail(str(path), f"duplicate JSON key: {key}")
            result[key] = value
        return result
    path = Path(path)
    if path.stat().st_size > 2_000_000:
        fail(str(path), "input exceeds 2 MB limit")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs,
                          parse_constant=lambda s: fail(str(path), f"invalid JSON constant {s}"))
    except (json.JSONDecodeError, UnicodeError) as exc:
        fail(str(path), f"invalid UTF-8 JSON: {exc}")
