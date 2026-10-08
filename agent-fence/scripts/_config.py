"""Shared config loader for agent-fence hook scripts.

Each hook script runs as a standalone `python -I` subprocess (see hooks.json),
so this module is imported via an explicit sys.path.insert in each script --
`-I` (isolated mode) deliberately excludes the script's own directory from
sys.path, so a plain `import _config` fails with ModuleNotFoundError unless
the caller does that first.

Reads ~/.claude/agent-fence.config.json (created/edited by the
/agent-fence:configure command, or by hand) and merges it over the built-in
defaults below. A missing file, missing section, or malformed JSON all fall
back to defaults -- this must fail SAFE (rules enabled, action=deny), never
fail open, since a broken config file is exactly the kind of thing that
otherwise silently disables every protection at once.
"""
import json
import re
from pathlib import Path

CONFIG_PATH = Path.home() / ".claude" / "agent-fence.config.json"

DEFAULTS = {
    "block_scan": {
        "enabled": True,
        "action": "deny",  # "deny" (hard block) or "ask" (prompt for approval)
        "rules": {
            "scan_tools": True,
            "foreign_user_profile": True,
            "recurse_drive_root": True,
            "recurse_system_dir": True,
            "root_scan_posix": True,
        },
        "allow": [],  # list of regexes; a match on the full command allows it unconditionally
    },
    "block_sensitive_files": {
        "enabled": True,
        "action": "deny",
        "rules": {
            "env_files": True,
            "ssh_keys": True,
            "key_files": True,
            "token_dotfiles": True,
            "wallet_files": True,
            "credentials_dir": True,
            "generic_credentials_name": True,
        },
        "allow_paths": [],  # list of fnmatch glob patterns matched against the (resolved) path
    },
    "block_destructive": {
        "enabled": True,
        "action": "deny",
        "rules": {
            "git_reset_hard": True,
            "git_clean_force": True,
            "git_push_force": True,
            "rm_rf_root": True,
            "chmod_777": True,
            "curl_pipe_shell": True,
            "fork_bomb": True,
            "mkfs": True,
            "crontab_r": True,
            "docker_volume_prune": True,
            "docker_system_prune": True,
            "remove_item_recurse_force_root": True,
            "format_volume": True,
        },
        "allow": [],  # list of regexes; a match on the full command allows it unconditionally
    },
    "block_ai_coauthor": {
        "enabled": True,
        "action": "deny",
        "rules": {
            "ai_coauthor_trailer": True,
        },
        "allow": [],  # list of regexes; a match on the full command allows it unconditionally
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in override.items():
        if key in out and isinstance(out[key], dict) and isinstance(value, dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load(section: str) -> dict:
    defaults = DEFAULTS[section]
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            user_config = json.load(f)
    except Exception:
        return defaults
    override = user_config.get(section)
    if not isinstance(override, dict):
        return defaults
    return _deep_merge(defaults, override)


def rule_enabled(cfg: dict, rule_id: str) -> bool:
    return bool(cfg.get("rules", {}).get(rule_id, True))


def matches_any(patterns, text: str) -> bool:
    for pattern in patterns or []:
        try:
            if re.search(pattern, text):
                return True
        except re.error:
            continue
    return False
