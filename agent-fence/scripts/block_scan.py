#!/usr/bin/env python
"""PreToolUse guard for Bash/PowerShell tool calls.

Blocks:
  1. Known network scanning / enumeration tools (nmap, masscan, etc.)
  2. Recursive traversal of a bare drive root (C:\\, C:/) or a system
     directory (Windows, Program Files, ProgramData)
  3. Any access to another user's profile under C:\\Users\\<name>

This is a text-pattern heuristic enforced by code that runs before the
tool call -- it is not a sandbox and can be evaded by a sufficiently
obfuscated command. Claude Code's built-in `sandbox` settings block
(OS-level network/filesystem containment) is a stronger, complementary
control if real enforcement is required, but needs a provisioned
restricted account and Linux/macOS/WSL2 for full effect.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _config

ME = os.environ.get("USERNAME") or os.environ.get("USER") or ""

SCAN_TOOLS = re.compile(
    r"(?<![a-z0-9_])"
    r"(nmap|masscan|zmap|netdiscover|arp-scan|unicornscan|hping3?|"
    r"angryip|ike-scan|fping|nbtscan|rustscan|zenmap)"
    r"(?![a-z0-9_])",
    re.IGNORECASE,
)

RECURSE_FLAG = re.compile(r"(-recurse\b|/s\b|-r\b|--recursive\b)", re.IGNORECASE)

# A filesystem path token: DRIVE:\... or DRIVE:/... with no spaces/quotes inside
PATH_TOKEN = re.compile(r"[a-zA-Z]:[\\/][^\s\"']*")

SYSTEM_DIR = re.compile(
    r"^[a-zA-Z]:[\\/](windows|program ?files(?: ?\(x86\))?|programdata)(?:[\\/]|$)",
    re.IGNORECASE,
)

USERS_DIR = re.compile(r"^[a-zA-Z]:[\\/]users[\\/]([^\\/]+)", re.IGNORECASE)


def is_bare_drive_root(token: str) -> bool:
    t = token.rstrip("\\/")
    return bool(re.fullmatch(r"[a-zA-Z]:", t))


def respond(cfg: dict, reason: str) -> None:
    if cfg.get("action") == "ask":
        print(json.dumps({
            "continue": True,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": f"agent-fence (block-scan): {reason}",
            },
        }))
    else:
        print(json.dumps({
            "continue": False,
            "stopReason": f"Blocked by agent-fence (block-scan): {reason}",
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
    cfg = _config.load("block_scan")

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

    if _config.rule_enabled(cfg, "scan_tools") and SCAN_TOOLS.search(cmd):
        respond(cfg, "network scanning tool detected in command")

    tokens = PATH_TOKEN.findall(cmd)
    has_recurse = bool(RECURSE_FLAG.search(cmd))

    for tok in tokens:
        m = USERS_DIR.match(tok)
        if _config.rule_enabled(cfg, "foreign_user_profile") and m and ME and m.group(1).lower() != ME.lower():
            respond(cfg, "access to another user's profile directory is not permitted")

        if _config.rule_enabled(cfg, "recurse_drive_root") and has_recurse and is_bare_drive_root(tok):
            respond(cfg, "recursive scan of a whole drive root is not permitted")

        if _config.rule_enabled(cfg, "recurse_system_dir") and has_recurse and SYSTEM_DIR.match(tok):
            respond(cfg, "recursive scan of a system directory is not permitted")

    # bash-style root scans: find / ..., ls -R /, du -sh /
    if _config.rule_enabled(cfg, "root_scan_posix") and (
        re.search(r"(^|[;&|]\s*)find\s+/\s", cmd) or
        re.search(r"(^|[;&|]\s*)(ls|du)\s+[^\n;&|]*-[a-zA-Z]*r[a-zA-Z]*\s+/(\s|$)", cmd, re.IGNORECASE)
    ):
        respond(cfg, "recursive scan of the filesystem root is not permitted")

    allow()


if __name__ == "__main__":
    main()
