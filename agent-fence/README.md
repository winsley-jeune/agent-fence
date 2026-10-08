# agent-fence

A Claude Code plugin that blocks four categories of risky or unwanted agent behavior with deterministic `PreToolUse` hooks (code that runs *before* the tool call, not model judgment):

1. **Network/filesystem scanning** (`scripts/block_scan.py`) — known port/network scanner tool names (nmap, masscan, zmap, ...), recursive traversal of a bare drive root or system directory, and access to another user's profile.
2. **Sensitive-file access** (`scripts/block_sensitive_files.py`) — `.env` and variants, SSH/TLS private keys, `.ssh`/`.aws` directories, npm/pip/netrc token files, crypto wallet files, and generically-named credentials/secrets files. Applies to `Read`, `Grep`, `Bash`, and `PowerShell` tool calls.
3. **Destructive commands** (`scripts/block_destructive.py`) — `git reset --hard`, `git push --force`, `git clean -f`, `rm -rf` on a drive root/home dir, `chmod 777`, `curl | sh`-style remote code execution, fork bombs, `mkfs`, `crontab -r`, and destructive `docker volume`/`system prune` commands.
4. **AI co-author attribution** (`scripts/block_ai_coauthor.py`) — blocks any `git commit`/`git commit --amend` whose message embeds a `Co-Authored-By:` trailer naming Claude or Anthropic, so the assistant can't attribute a commit to itself even if a future session's default instructions tell it to.

## Install (local directory marketplace)

```jsonc
// in settings.json
{
  "extraKnownMarketplaces": {
    "local-plugins": {
      "source": { "source": "directory", "path": "C:/Users/<you>/Desktop/agent-fence" }
    }
  },
  "enabledPlugins": {
    "agent-fence@local-plugins": true
  }
}
```

## Configuring rules

Every rule is enabled (`action: "deny"`) by default — no config file is required. To customize, either:

- Run `/agent-fence:configure` in Claude Code — a guided menu that reads your current settings, asks what to change, writes the file for you, and verifies the result by actually invoking the affected hook script.
- Or hand-edit `~/.claude/agent-fence.config.json` yourself (see `agent-fence.config.example.json` for the full schema). Each hook script re-reads this file on every invocation — no reload needed, and a missing or malformed file just falls back to defaults (fail-safe: all rules on), never fails open.

Per category (`block_scan`, `block_sensitive_files`, `block_destructive`, `block_ai_coauthor`) you can set:
- `"enabled"` — turn the whole category off.
- `"action"` — `"deny"` (hard block) or `"ask"` (prompt for approval instead of blocking outright).
- `"rules"` — turn off individual checks by id (e.g. `"mkfs": false`). See `scripts/_config.py`'s `DEFAULTS` for the current list of ids per category.
- `"allow"` (`block_scan`/`block_destructive`) — a list of regexes; a match against the full shell command bypasses that script entirely for this call.
- `"allow_paths"` (`block_sensitive_files`) — a list of `fnmatch` glob patterns checked against the (symlink-resolved) target path.

## What this is, and isn't

This is **text-pattern matching enforced by code that runs before the tool call** — not the model's own judgment, and not an OS-level sandbox. It will not catch:

- **Base64-encoded or programmatically-concatenated commands** (`python -c "f='.e'+'nv'; open(f)"`, `echo <base64> | base64 -d | bash`). The revealing content doesn't exist as plain text until an interpreter runs it, so no amount of regex closes this. The real fix for this class is Claude Code's `sandbox.credentials.files` (mask mode) or `sandbox.filesystem.denyRead`, which intercepts the actual file open at the OS/sandbox-runtime level — but on Windows that requires a pre-provisioned restricted user account (not set up by this plugin), and credential *masking* specifically is Linux/WSL2/macOS only as of this writing.
- **Symlinks pointing at a sensitive file from Bash/PowerShell command text** — `block_sensitive_files.py` resolves symlinks via `os.path.realpath()` for direct `Read`/`Grep` tool calls (where the path is unambiguous), but does not attempt to resolve a relative path extracted from free-form shell text, since the hook doesn't reliably know the shell's actual working directory.
- Anything not covered by the specific patterns above. This is a maintained blocklist, not a formally verified boundary.

## Known false-positive fix (worth knowing if you extend this)

An early version split command tokens on `=`/`:` to catch `dd if=.env`-style args, then ran a bare substring check for "credential"/"secret" against every resulting token. That meant `echo API_SECRET=value` tripped the hook — the token "API_SECRET" contains "secret" but isn't a file path at all. Fixed by gating that substring check behind `looks_like_file()` (requires a path separator or file extension). If you add new generic-substring checks, gate them the same way.

Separately: Python's `shlex` in POSIX mode treats backslash as an *escape character*, silently consuming every backslash in a Windows path (`C:\Users\...` → `C:Users...`). This broke all backslash-path detection until `lexer.escape = ""` was set. If you ever swap the tokenizer, re-verify this specifically — it's easy to regress silently, since a mangled path can still coincidentally match a substring check and *look* like it's working.

## Tests

```
python tests/run_all.py
```

Runs all four hook scripts against their fixture files in `tests/cases_*.jsonl` via subprocess (never executes the actual risky command). 68 cases as of this writing, all passing.
