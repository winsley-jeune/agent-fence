#!/usr/bin/env python
"""PreToolUse guard for Bash/PowerShell tool calls.

Blocks a `git commit` (or `git commit --amend`) whose message embeds a
`Co-Authored-By:` trailer naming Claude or Anthropic -- the attribution
line Claude Code adds by default unless told otherwise. Some users want
that disclosure; this user explicitly doesn't, and would rather enforce
it deterministically than repeat the instruction every session.

Denying (rather than silently stripping) is deliberate and consistent
with the rest of this plugin: a PreToolUse hook can say yes/no/ask, but
can't rewrite the pending command. A deny surfaces the reason to Claude,
which can then redo the commit without the trailer.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _config

GIT_COMMIT_RE = re.compile(r"\bgit\s+commit\b", re.IGNORECASE)
AI_COAUTHOR_RE = re.compile(r"co-authored-by:\s*(claude|anthropic)", re.IGNORECASE)


def respond(cfg: dict, reason: str) -> None:
    if cfg.get("action") == "ask":
        print(json.dumps({
            "continue": True,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": f"agent-fence (block-ai-coauthor): {reason}",
            },
        }))
    else:
        print(json.dumps({
            "continue": False,
            "stopReason": f"Blocked by agent-fence (block-ai-coauthor): {reason}",
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
    cfg = _config.load("block_ai_coauthor")

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

    if (
        _config.rule_enabled(cfg, "ai_coauthor_trailer")
        and GIT_COMMIT_RE.search(cmd)
        and AI_COAUTHOR_RE.search(cmd)
    ):
        respond(cfg, "commit message includes a Claude/Anthropic Co-Authored-By trailer")

    allow()


if __name__ == "__main__":
    main()
