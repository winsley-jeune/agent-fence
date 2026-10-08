# Contributing to agent-fence

Thanks for considering it. This project is intentionally small and literal — every rule is a readable regex or basename check with a test case, not a model call — and contributions should keep that property.

## Setup

No dependencies beyond a Python 3 interpreter on your PATH (the hooks are invoked as `python -I <script>.py` — only the standard library is used, by design, since these run as subprocesses on every matching tool call).

```bash
git clone https://github.com/winsley-jeune/agent-fence.git
cd agent-fence
python agent-fence/tests/run_all.py
```

All 68 cases should pass before you change anything. If they don't, something about your environment differs from what's assumed (e.g. Python version) — open an issue.

## Making a change

**Before opening a PR:**
- `python agent-fence/tests/run_all.py` passes, including any cases you added.
- If you touched a hook script, also sanity-check it by hand once — pipe a real `PreToolUse`-shaped JSON payload into it and read the output. The test harness only checks `allow` vs `deny`; it won't catch a malformed `ask` response, for instance:
  ```bash
  echo '{"tool_input": {"command": "rm -rf /"}}' | python -I agent-fence/scripts/block_destructive.py
  ```

### Adding a rule to an existing hook

Each rule has a stable id used by the config system (`scripts/_config.py`) to let users toggle it independently. To add one:

1. Add the pattern/check to the relevant script (`scripts/block_scan.py`, `block_sensitive_files.py`, `block_destructive.py`, or `block_ai_coauthor.py`), gated behind `_config.rule_enabled(cfg, "your_rule_id")`.
2. Add `"your_rule_id": True` to that category's `rules` dict in `scripts/_config.py`'s `DEFAULTS`, and to `agent-fence.config.example.json`.
3. Add at least one `deny` case and one nearby `allow` case (a near-miss that should *not* trigger it — false-positive regressions are exactly what the test suite is for) to the matching `tests/cases_*.jsonl` file.
4. Mention the new behavior in `agent-fence/README.md`'s numbered list.

### Adding a whole new hook/category

1. Write `scripts/block_<thing>.py`, mirroring the structure of an existing script: load config via `_config.load("block_<thing>")`, a `respond(cfg, reason)` function handling both `deny` and `ask` actions, an `allow()` function, and a `main()` that reads the `PreToolUse` JSON payload from stdin. Remember the isolated-mode gotcha below.
2. Register it in `hooks/hooks.json` with the right `matcher` (which tool names it should see) and `"${CLAUDE_PLUGIN_ROOT}"`-relative path — never a hardcoded absolute path.
3. Add its `DEFAULTS` section to `scripts/_config.py` and to `agent-fence.config.example.json`.
4. Add `("block_<thing>.py", "cases_<thing>.jsonl")` to `tests/run_all.py`'s `SUITES` and write a `tests/cases_<thing>.jsonl` fixture file (see an existing one for the format: one JSON object per line, `name`/`expect`/`payload`).
5. Document it in both `README.md` (root) and `agent-fence/README.md`.

### The `python -I` gotcha

Hooks run as `python -I <script>.py` (isolated mode) — on Python 3.11+, `-I` implies `-P`, which excludes the script's own directory from `sys.path`. A plain `import _config` from a sibling script will silently fail with `ModuleNotFoundError` unless you first do:

```python
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _config
```

This is already in every script that imports `_config` — if you copy one as a starting point, don't drop this line.

### Design principles to keep

- **Fail safe, not fail open.** A missing or malformed config file (or any unexpected input) should fall back to the strictest default behavior, never silently disable protection. `_config.load()` already does this — don't bypass it.
- **No sandbox claims.** This is text-pattern matching enforced before a tool call. If a change only works by assuming the agent can't obfuscate a command (e.g. `'.e'+'nv'`), that's a known, accepted gap — document it rather than chasing it with more regex (see `agent-fence/README.md`'s "What this is, and isn't").
- **Gate new generic substring checks.** If you add a check like "filename contains X", gate it behind something path-shaped (see `looks_like_file()` in `block_sensitive_files.py`) — a bare substring check over every shell token produces false positives on ordinary variable names and echoed strings. This has bitten this project before; see the README's "Known false-positive fix" section.
- **Minimal, boring code.** No new third-party dependencies, no abstractions for a single use site, no comments explaining *what* the code does — only ones explaining a non-obvious *why* (a workaround, an invariant, a prior bug).

## Pull requests

Keep PRs focused — one rule, one hook, or one doc fix per PR is easier to review than a bundle. Describe *why* the change is needed (what behavior it catches, or what false positive it fixes), not just what changed. Tests are expected to pass; if you're proposing a rule you're unsure about (too strict? too loose?), say so in the PR description and it can be discussed before merge.

## Reporting a problem without a PR

Open an issue. A false positive (something legitimate got blocked) and a false negative (something risky got through) are both useful reports — include the exact command or file path that triggered it.
