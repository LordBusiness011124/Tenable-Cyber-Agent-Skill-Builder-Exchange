# Vendor-neutral input format, version 1

All inputs are UTF-8 JSON objects. Unknown fields are rejected, including vendor extensions, NAT, routing, state, application identity, and IPv6. Duplicate JSON keys and duplicate rule/policy IDs are rejected. IDs use 1–80 ASCII letters, digits, dots, underscores, or hyphens. Descriptions and inventory labels are nonempty strings of at most 2000 characters. Each file is limited to 2 MB. Canonical IPv4 CIDRs must have zero host bits; a bare IPv4 address represents one host. CIDRs include all addresses, including network and broadcast addresses. No DNS resolution occurs.

## Configuration

Required keys: `version` (integer 1), `default_action` (`allow` or `deny`), `rules` (ordered array, up to 200 rules).

Each rule requires `id`, `enabled` (JSON boolean), `action` (`allow` or `deny`), `source`, `destination`, `protocol`, and `ports`. Optional `description` is metadata only. First enabled matching rule wins, otherwise the explicit default applies. IDs are unique within each configuration and establish identity across configurations.

```json
{
  "version": 1,
  "default_action": "deny",
  "rules": [{
    "id": "admin-ssh",
    "enabled": true,
    "action": "allow",
    "source": "10.10.10.0/24",
    "destination": "10.10.40.10",
    "protocol": "tcp",
    "ports": [22, {"start": 8000, "end": 8080}]
  }]
}
```

`source` and `destination` each accept a single IPv4 address, canonical CIDR, or literal `"any"` (all IPv4). `protocol` accepts only `"tcp"` or `"udp"`. `ports` accepts literal `"any"` (0 through 65535) or a nonempty array of at most 256 individual integers or objects containing exactly `start` and `end`, inclusive. Port 0 is a valid configuration selector; no live transport behavior is inferred. Booleans, strings, reversed ranges, and out-of-range ports are rejected. Duplicate, adjacent, and overlapping port intervals are canonicalized into their exact union.

## Policy

Required keys: `version` (integer 1), `requirements` (array, up to 200 entries). Each entry requires `id`, `description`, `source`, `destination`, `protocol`, `ports`, and `status` (`required` or `forbidden`). Selectors use the same format as configuration rules. IDs are unique. Empty policy is allowed with an explicit empty-coverage limitation.

```json
{
  "version": 1,
  "requirements": [{
    "id": "P-guests",
    "description": "Guests must not access the database",
    "source": "10.10.30.0/24",
    "destination": "10.10.50.10",
    "protocol": "tcp",
    "ports": [5432],
    "status": "forbidden"
  }]
}
```

A required entry means **every** matching connection tuple must be allowed; forbidden means **every** tuple must be denied. Overlapping entries are evaluated independently. Conflicting required and forbidden entries cannot both pass: the report exposes their respective violations; resolve policy with its owner. No implicit relationship exists between entries. Requirements do not constitute a universal allowlist: uncovered connections remain outside policy coverage.

## Optional inventory

Required keys: `version` (integer 1), `assets` (array, up to 1000 entries). Each asset requires `address` (IPv4/CIDR/`any`), `name`, `role`, `owner`, `criticality` (`low`, `medium`, `high`, `critical`). Overlapping inventory entries are allowed; every matching entry is attached to the example connection. Inventory does not change evaluation, authorization, or severity.

```json
{
  "version": 1,
  "assets": [{
    "address": "10.10.50.10",
    "name": "Database server",
    "role": "database",
    "owner": "Data team",
    "criticality": "critical"
  }]
}
```

## Output contract

`report.json` contains `report_version`, `status` (`complete`, `incomplete`, `invalid`), `verdict`, `errors`, `limitations`, structural `changes`, `policy_results`, and `findings`. Complete/limited reviews also include `limits` and `evaluation` counters.

Each policy result counts total and violating connection tuples before and after, plus introduced, resolved, and existing violating tuples. Counts are exact Python integers; JavaScript consumers must preserve integers larger than 2^53 without floating-point conversion.

Findings have stable traversal IDs, category, explanation, policy IDs, before/after behavior, responsible rule IDs/default evidence, a concrete example, asset context, severity and rationale, correction, verification steps, limitations, and `evaluation_complete`. Access/violation findings contain disjoint exact inclusive `affected_regions` and `connection_count`. Structural observations instead contain examples and rule details; their empty region list and zero count do not imply no matched access. Shadow findings expose `matched_connections` and `effective_connections`. `null` before/after in structural findings means not an access transition. JSON is the complete region artifact; Markdown provides readable summaries.
