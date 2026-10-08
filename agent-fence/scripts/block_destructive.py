#!/usr/bin/env python
"""PreToolUse guard for Bash/PowerShell tool calls.

New capability (not in the original hand-rolled hooks) inspired by
third-party agent-guardrail tools found during research (notably Leash):
blocks commands with no reasonable accidental/legitimate-agent use, that
cause irreversible data loss or remote code execution, regardless of which
directory they target:

  - git reset --hard / git clean -f(d) / git push --force (no --force-with-lease)
  - rm -rf on a drive root, home directory, or with no path restriction
  - chmod 777 (world-writable, a standing security hole, not just risky once)
  - curl/wget piped straight into a shell (fetch-and-execute)
  - fork bombs
  - mkfs (filesystem format)
  - crontab -r (silently wipes all cron jobs)
  - docker volume rm/prune, docker system prune -a (destroys data/images)

Deliberately NOT covered: ordinary `rm -rf <project-subdir>`, ordinary
`git reset --hard <ref>` inside a repo the agent is actively working in --
those have legitimate everyday use and are better handled by Claude's own
judgment/confirmation flow than a blanket hook deny.
"""
import json
import os
import re
import shlex
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _config

PATTERNS = [
    ("git_reset_hard", re.compile(r"git\s+reset\s+--hard\b"), "git reset --hard discards uncommitted work irreversibly"),
    ("git_clean_force", re.compile(r"git\s+clean\s+-[a-z]*f[a-z]*\b", re.IGNORECASE), "git clean -f permanently deletes untracked files"),
    ("git_push_force", re.compile(r"git\s+push\s+.*--force(?!-with-lease)\b"), "git push --force can overwrite remote history/other people's work"),
    ("git_push_force", re.compile(r"git\s+push\s+.*-f\b(?!orce-with-lease)"), "git push -f can overwrite remote history/other people's work"),
    ("rm_rf_root", re.compile(r"\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+(/|~|\$HOME|[a-zA-Z]:[\\\\/]\s*$)", re.IGNORECASE),
     "rm -rf targeting a drive root or home directory"),
    ("chmod_777", re.compile(r"\bchmod\s+777\b"), "chmod 777 makes a path world-writable"),
    ("curl_pipe_shell", re.compile(r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|powershell|pwsh)\b", re.IGNORECASE),
     "piping a remote download straight into a shell is a remote-code-execution pattern"),
    ("fork_bomb", re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&?\s*\}\s*;\s*:"), "fork bomb pattern"),
    ("mkfs", re.compile(r"\bmkfs(\.[a-z0-9]+)?\b", re.IGNORECASE), "mkfs formats a filesystem, destroying its data"),
    ("crontab_r", re.compile(r"\bcrontab\s+-r\b"), "crontab -r silently wipes all scheduled jobs"),
    ("docker_volume_prune", re.compile(r"\bdocker\s+volume\s+(rm|prune)\b"), "docker volume rm/prune destroys persistent container data"),
    ("docker_system_prune", re.compile(r"\bdocker\s+system\s+prune\s+.*-a[fl]?\b", re.IGNORECASE), "docker system prune -a removes all unused images/data"),
    ("remove_item_recurse_force_root", re.compile(r"Remove-Item\s+.*-Recurse\s+.*-Force\s+.*[a-zA-Z]:[\\/]\s*$", re.IGNORECASE),
     "Remove-Item -Recurse -Force targeting a drive root"),
    ("format_volume", re.compile(r"Format-Volume\b", re.IGNORECASE), "Format-Volume destroys all data on the target volume"),
]


def respond(cfg: dict, reason: str) -> None:
    if cfg.get("action") == "ask":
        print(json.dumps({
            "continue": True,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": f"agent-fence (block-destructive): {reason}",
            },
        }))
    else:
        print(json.dumps({
            "continue": False,
            "stopReason": f"Blocked by agent-fence (block-destructive): {reason}",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            },
        }))
    sys.exit(0)


def allow() -> None:
    print(json.dumps({"continue": True}))
    sys.exit(0)


def main() -> None:
    cfg = _config.load("block_destructive")

    try:
        data = json.load(sys.stdin)
    except Exception:
        allow()
        return

    cmd = (data.get("tool_input") or {}).get("command") or ""
    if not cmd:
        allow()
        return

    if not cfg.get("enabled", True):
        allow()
        return

    if _config.matches_any(cfg.get("allow"), cmd):
        allow()
        return

    for rule_id, pattern, reason in PATTERNS:
        if _config.rule_enabled(cfg, rule_id) and pattern.search(cmd):
            respond(cfg, reason)

    allow()


if __name__ == "__main__":
    main()
