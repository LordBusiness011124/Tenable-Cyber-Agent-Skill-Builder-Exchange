# Firewall Change Reviewer

An offline cybersecurity agent skill for a Tenable CyberAgents Exchange workshop. It answers: **Does this proposed firewall change introduce unauthorized access or block required connectivity?**

The local Python engine compares two ordered firewall configurations against explicit required and forbidden access policy. It produces exact affected ranges, example connections, responsible rules/default actions, and suggested corrections. The agent collects inputs and explains evidence. No LLM API, credentials, target-host connections, or runtime dependencies are needed.

## Setup

Python 3.11 or newer. The CLI runs directly without installation:

```bash
python3 scripts/review_firewall.py --help
```

For tests and an optional installed command:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m pytest
```

Then `.venv/bin/firewall-review` accepts the same flags as the script. Tests use pytest 8.4.2; the runtime uses only the standard library.

## Codex skill installation

Installation guidance was checked on October 6, 2026 against [OpenAI's official Build skills documentation](https://developers.openai.com/codex/skills). Codex discovers repository skills under `.agents/skills` and user skills under `~/.agents/skills`. Skill folders contain `SKILL.md` and supporting resources; changes are detected automatically, with a restart if discovery does not refresh.

This workspace keeps the requested `SKILL.md` at its root. To install a self-contained copy for a repository, run these commands **from this project root**, choosing an empty destination:

```bash
mkdir -p .agents/skills/firewall-change-reviewer
cp SKILL.md README.md LICENSE .agents/skills/firewall-change-reviewer/
cp -R agents scripts references examples .agents/skills/firewall-change-reviewer/
```

For user-wide installation, replace `.agents/skills` in those commands with `~/.agents/skills`. Copy the package under `scripts` as well as the entry point. Keep the installed folder named `firewall-change-reviewer`. Invoke `$firewall-change-reviewer` in Codex, or use `/skills` to select it. This project does not install into your personal skill directory automatically. No connector or plugin installation is necessary for local use.

## Run a review

```bash
python3 scripts/review_firewall.py \
  --current examples/current.json \
  --proposed examples/unauthorized.json \
  --policy examples/policy.json \
  --inventory examples/inventory.json \
  --output-dir reports/unauthorized
```

The CLI writes `report.json` and `report.md`, replacing those names in the chosen directory. Use a distinct directory per review to preserve evidence. When running outside the skill directory, use an absolute path to `scripts/review_firewall.py` and to inputs. The optional inventory enriches examples without changing policy evaluation.

| Exit | Meaning |
|---:|---|
| 0 | Complete, no introduced policy violations; existing violations can remain |
| 1 | Complete, policy violations introduced |
| 2 | Invalid input or output write failure |
| 3 | Resource-limited incomplete review |

Always read `status`, `verdict`, coverage, and errors. Invalid inputs replace reports with an invalid/incomplete result when output is writable. A missing report or failed process never supports approval. Empty or narrow policy passing does not establish universal safety.

## Fictional network and demo

| Asset | Address | Required access |
|---|---|---|
| Admin subnet | 10.10.10.0/24 | Application TCP/22 |
| Employee subnet | 10.10.20.0/24 | Application TCP/443 |
| Guest subnet | 10.10.30.0/24 | Database TCP/5432 forbidden |
| Application server | 10.10.40.10 | Database TCP/5432 |
| Database server | 10.10.50.10 | Only the supplied policy constrains access |

Run all demonstration cases and verify their expected output:

```bash
python3 scripts/demo.py --output-dir reports/demo
```

| Case | Expected evidence |
|---|---|
| unauthorized | Allow rule before guest deny introduces 128 forbidden guest/database tuples |
| blocked | Deny for employee /25 introduces 128 denied required HTTPS tuples |
| broadened | Wider admin SSH source produces broadening and access observations; no supplied policy violation |
| shadowed | Redundant admin /25 rule is fully shadowed |
| existing | Missing application/database allow remains an existing violation |
| resolved | Corrected proposal resolves the 128 unauthorized guest tuples |
| corrected | Complete, no introduced violations |
| incomplete | Cell limit deliberately exceeded; incomplete verdict |

For example, the unauthorized report identifies `P-guests`, source `10.10.30.0` through `10.10.30.127`, destination `10.10.50.10`, TCP/5432: before `guest-db-deny` denies, after `guest-db-open` allows. Severity is high because an explicit forbidden requirement is violated. The correction is to remove/narrow the unauthorized allow or restore required precedence, then rerun against every requirement.

The policy intentionally leaves some access unspecified. For example, the broadened SSH rule permits more sources outside policy coverage; passing policy does not approve those extra sources. A plain-language change request must be translated and confirmed before it becomes authoritative policy.

## Format, architecture, and tests

[Input format and output contract](references/input-format.md) documents the complete strict JSON schemas, accepted types, and unsupported inputs. [Engine reference](references/engine.md) explains partitioning, limits, rule comparison, and severity.

The package under `scripts/firewall_reviewer/` separates validation, exact rule evaluation, structural comparison, review aggregation, Markdown/JSON generation, and CLI handling. `scripts/review_firewall.py` is a portable entry point that finds its colocated package regardless of current directory. `scripts/demo.py` exercises the workshop examples and checks expected counts/verdicts.

Tests cover partial subnet/destination/port violations, first-match order, default/any semantics, IPv4 maximum endpoints, TCP/UDP separation, disabled rules, shadowing by a union of earlier rules, structural changes, introduced/existing/resolved violations, validation, hostile metadata, limits, CLI exit behavior, and deterministic reports. A seeded exhaustive reference over small networks checks randomized configurations independently of the partition engine.

## Scope and limits

Version 1 handles a single ordered IPv4 rule list, TCP/UDP, destination ports and inclusive ranges, enabled rules, and explicit default action. It rejects unsupported schema fields and malformed selectors. It has **no native vendor compatibility**. NAT, routing, IPv6, connection state, application identity, and multiple hops are excluded. Results describe access permitted by the input configuration and do not prove live network reachability.

The default budget is 200,000 cells and 5,000,000 selector/overlap checks. Stored evidence is capped at 100,000 regions and 20,000 findings. Complete evaluation is exact; exhaustion produces an incomplete verdict and withholds policy totals. Reviewers may raise `--max-cells` / `--max-checks` after assessing local resources. File/rule limits and severity rationale are documented in the engine reference.

MIT licensed. This is a workshop implementation, not an assertion of Tenable product integration or certification.
