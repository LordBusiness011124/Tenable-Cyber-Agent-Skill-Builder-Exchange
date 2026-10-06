# Verification record

Verified October 6, 2026 on Python 3.14.7.

- `python -m pytest -q` in the project virtual environment: **38 passed**.
- `python3 scripts/demo.py --output-dir reports/demo`: **8 verified cases**, including partial-subnet unauthorized access and blocked required connectivity, broadening, union/order observations, existing and resolved violations, correction, and resource exhaustion.
- Editable package installation and the installed `firewall-review` command: passed.
- Manual skill checks: valid frontmatter fields, 422-character description, 37-line body, metadata prompt, and resolved local resource links. No local `skillcheck` was available; manual checks were used. No third-party linter was downloaded.
- Independent fresh-context skill critic: no remaining findings or blockers. Its separate-model held-out outcome probe passed **3/3** against independent evaluation/validation oracles; skill routing passed **20/20** in-scope and adjacent prompts. Probe details were withheld from the author. These checks support the implemented scope; they are not an exhaustive proof for every configuration.

The root skill file is intentional: the user required `SKILL.md` at the workspace root. README installation commands copy it and its resources into a folder named `firewall-change-reviewer` for Codex discovery.

Runtime evaluation does not contact hosts. Passing supplied policy does not prove live network reachability or authorize uncovered access. Incomplete or invalid reviews never support a clean verdict.
