---
description: Interactively configure which agent-fence rules are enabled, how strict they are, and any exceptions
---

You are walking the user through configuring the `agent-fence` plugin. This plugin enforces three `PreToolUse` hooks (`block_scan.py`, `block_sensitive_files.py`, `block_destructive.py`), each driven by a shared JSON config file at `~/.claude/agent-fence.config.json` (read by `scripts/_config.py`, which every hook script imports). There is no config file by default — every rule is enabled with `action: "deny"` until the user customizes it here.

## What to do

1. **Load current state.** Try to read `~/.claude/agent-fence.config.json` (use the `Read` tool; if it doesn't exist, that's fine — treat every category as all-defaults: enabled, action `"deny"`, no allowlist). Also read `scripts/_config.py` in this plugin to get the authoritative `DEFAULTS` dict and the full list of rule ids per category — don't hardcode a stale copy of that list in your own memory; the source of truth is that file, since it may have grown new rule ids since this command was written.

2. **Show the user where things stand.** Summarize, per category (`block_scan`, `block_sensitive_files`, `block_destructive`): whether it's enabled, its action (`deny` vs `ask`), which individual rules are off (if any), and how many allow-exceptions exist.

3. **Ask what they want to change**, using the `AskUserQuestion` tool (this is a guided menu, not free-form chat parsing). Useful shapes for the questions:
   - Which category do they want to edit first (multiSelect, or one at a time)?
   - For that category: keep all rules on, turn off specific ones (list the rule ids with a one-line plain-English description each, multiSelect), or disable the whole category?
   - What action on violation: hard block (`deny`) or prompt for approval (`ask`)?
   - Any allow-exceptions to add? For `block_scan`/`block_destructive` these are regexes matched against the full shell command; for `block_sensitive_files` these are `fnmatch`-style path globs (e.g. `*/fixtures/*.env.test`) checked against the resolved file path. Ask for these as plain text — a specific command or path pattern they want to exempt, not a raw regex quiz — and translate it into a regex/glob yourself, erring toward a tight pattern (anchored to what they described) rather than a broad one that would quietly re-open an unrelated hole.
   - Offer "reset this category to defaults" as an option too.

4. **Merge and write.** Build the full config object (only include keys the user actually changed — use `_config.py`'s own defaults as the base, don't invent new keys) and write it to `~/.claude/agent-fence.config.json` with the `Write` tool. Preserve any customization for categories the user didn't touch this run (read-modify-write, never blindly overwrite the whole file from scratch if it already existed).

5. **Confirm and verify.** Show the user the final config for the categories they touched. Then actually test it: construct a small JSON payload matching what a real `PreToolUse` hook call would look like (e.g. `{"tool_input": {"command": "<something that would hit the rule they just changed>"}}` for Bash-matcher scripts, or `{"tool_name": "Read", "tool_input": {"file_path": "..."}}` for `block_sensitive_files.py`) and run `python -I scripts/<script>.py` with that payload piped to stdin via the `Bash` tool, from the plugin's root directory. Confirm the output now matches what they asked for (e.g. a rule they disabled now returns `{"continue": true}`). This catches typos in hand-built regex/globs before the user discovers them the hard way mid-session.

6. Remind them: changes apply to new tool calls immediately (the hook script reads the config file fresh on every invocation — no reload/restart needed), and the full regression suite (`python tests/run_all.py` from the plugin root) still exercises only the *default* config, so it won't catch a mistake in their custom rules — step 5's verification is what covers that.

Keep the conversation efficient: don't re-ask about categories the user says they don't want to touch, and don't dump the entire schema on them unprompted — summarize, then let `AskUserQuestion` drive the specifics.
