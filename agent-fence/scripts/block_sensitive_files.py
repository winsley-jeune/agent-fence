#!/usr/bin/env python
"""PreToolUse guard for Read/Grep/Bash/PowerShell tool calls.

Blocks access to common secret-bearing files regardless of whether the
path is inside the working directory. Covers:
  - .env and variants (but not .env.example/.sample/.template)
  - SSH private keys, and anything under a .ssh/ directory
  - private key / keystore files (.pem, .key, .pfx, .p12, .jks, ...)
  - .npmrc, .netrc, .pypirc (token-bearing dotfiles)
  - anything under an .aws/ or .docker/ directory
  - crypto wallet/keystore files
  - files with "credential(s)" or "secret(s)" in the name (not placeholders)

Hardening in this version (over the first hand-rolled hook):
  - Read/Grep file_path is resolved through os.path.realpath() first, so a
    symlink with an innocuous name pointing at a sensitive file is still
    caught (and a symlink pointing AWAY from one isn't falsely flagged).
  - Bash/PowerShell commands are tokenized with shlex using punctuation_chars,
    which correctly splits on &&, ||, ;, | (even with no surrounding
    whitespace) while still respecting quoting and adjacent-quote
    concatenation ("a""b" -> "ab"), instead of a hand-rolled regex split.
  - Tokens are stripped of wrapping shell punctuation ($, `, (, )) so
    "$(cat .env)" and ".env)" still resolve to ".env".
  - "=" and ":" split assignment-style args (dd if=.env, --file=.env).
  - Wildcard globs (.e*, .??v) are checked against known sensitive names
    with fnmatch.
  - Windows NTFS alternate-data-stream suffixes and trailing dots/spaces
    are normalized away before matching.

This is still a filename heuristic, not content inspection or a sandbox --
base64-encoded or programmatically-concatenated paths ('.e'+'nv') cannot be
caught by text matching, because the revealing content doesn't exist until
an interpreter runs it. See README.md for why that gap is left open rather
than "fixed" with more regex.
"""
import fnmatch
import json
import os
import re
import shlex
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _config

PLACEHOLDER_TAGS = ("example", "sample", "template", ".dist")
SENSITIVE_DIR_NAMES = {".ssh", ".aws", ".docker"}
PRIVATE_KEY_BASENAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
TOKEN_DOTFILES = {".npmrc", ".netrc", ".pypirc"}
WALLET_BASENAMES = {"wallet.json", "keystore.json"}
KEY_EXTENSION_RE = re.compile(r"\.(pem|key|ppk|pfx|p12|jks|keystore|asc|gpg|pgp|kdbx)$")
KNOWN_SENSITIVE_NAMES = (
    {".env"} | PRIVATE_KEY_BASENAMES | TOKEN_DOTFILES | WALLET_BASENAMES
)
ADS_SUFFIX_RE = re.compile(r"::\$[A-Za-z0-9_]+$")


def is_placeholder(name_lower: str) -> bool:
    return any(tag in name_lower for tag in PLACEHOLDER_TAGS)


FILE_EXTENSION_RE = re.compile(r"\.[A-Za-z0-9]{1,6}$")


def looks_like_file(name_lower: str) -> bool:
    # Guards the generic "credential"/"secret" substring check below so it
    # only fires on something path/filename-shaped, not on any shell word
    # that happens to contain those letters (e.g. an echoed "API_SECRET=x"
    # value, or a variable name) -- that was a real false positive found
    # while testing this exact hook.
    return bool(re.search(r"[\\/]", name_lower)) or bool(FILE_EXTENSION_RE.search(name_lower))


def is_sensitive_basename(name: str, cfg: dict):
    lname = name.lower()
    if not lname:
        return None
    if _config.rule_enabled(cfg, "env_files") and (
        lname == ".env" or (lname.startswith(".env.") and not is_placeholder(lname))
    ):
        return "environment/secrets file"
    if _config.rule_enabled(cfg, "ssh_keys") and lname in PRIVATE_KEY_BASENAMES:
        return "SSH private key"
    if _config.rule_enabled(cfg, "key_files") and KEY_EXTENSION_RE.search(lname):
        return "private key / keystore file"
    if _config.rule_enabled(cfg, "token_dotfiles") and lname in TOKEN_DOTFILES:
        return "credential-bearing dotfile"
    if _config.rule_enabled(cfg, "wallet_files") and lname in WALLET_BASENAMES:
        return "crypto wallet/keystore file"
    if (
        _config.rule_enabled(cfg, "generic_credentials_name")
        and looks_like_file(lname)
        and ("credential" in lname or "secret" in lname)
        and not is_placeholder(lname)
    ):
        return "credentials/secrets-named file"
    return None


def normalize_path(path_str: str) -> str:
    # Windows ignores trailing dots/spaces on path components, and an NTFS
    # alternate-data-stream suffix ("file::$DATA") still opens the base file.
    p = ADS_SUFFIX_RE.sub("", path_str)
    return p.rstrip(" .")


def is_sensitive_glob(token: str):
    if not any(ch in token for ch in "*?["):
        return None
    base = token.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if base.startswith(".") and len(base) <= 12:
        for name in KNOWN_SENSITIVE_NAMES:
            if fnmatch.fnmatch(name, base):
                return "a wildcard pattern matching a known sensitive filename"
        return "a wildcard pattern targeting a hidden/dotfile path"
    return None


def path_is_sensitive(path_str: str, cfg: dict, resolve: bool = False):
    if not path_str:
        return None
    path_str = normalize_path(path_str)
    if resolve:
        try:
            resolved = os.path.realpath(path_str)
            if resolved and resolved != path_str:
                path_str = resolved
        except OSError:
            pass
    if any(fnmatch.fnmatch(path_str.lower(), pat.lower()) for pat in cfg.get("allow_paths") or []):
        return None
    glob_hit = is_sensitive_glob(path_str)
    if glob_hit:
        return glob_hit
    parts = [p for p in re.split(r"[\\/]+", path_str) if p]
    if not parts:
        return None
    if parts[-1].lower().endswith(".pub"):
        return None
    if _config.rule_enabled(cfg, "credentials_dir"):
        if any(p.lower() in SENSITIVE_DIR_NAMES for p in parts[:-1]):
            return "inside a credentials directory (.ssh/.aws/.docker)"
        if parts[-1].lower() in SENSITIVE_DIR_NAMES:
            return "a credentials directory (.ssh/.aws/.docker)"
    return is_sensitive_basename(parts[-1], cfg)


ASSIGNMENT_SPLIT_RE = re.compile(r"[=:]")
STRIP_CHARS = "$`(){}"


def tokenize_command(cmd: str):
    # shlex with punctuation_chars splits on &&, ||, ;, | (even glued to the
    # next word with no space) while still honoring quotes and adjacent-quote
    # concatenation ("a""b" -> "ab"), which a hand-rolled regex split cannot.
    try:
        lexer = shlex.shlex(cmd, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        # Disable backslash-as-escape: POSIX shlex otherwise eats every
        # backslash in a Windows path (C:\Users\... -> C:Users...),
        # destroying the path separators entirely. Confirmed by direct
        # testing -- an earlier version of this hook silently relied on
        # this bug (a mangled path happened to still contain a sensitive
        # substring) rather than actually detecting the path structure.
        lexer.escape = ""
        tokens = list(lexer)
    except ValueError:
        tokens = cmd.split()

    out = []
    for tok in tokens:
        stripped = tok.strip(STRIP_CHARS)
        candidate = stripped or tok
        out.append(candidate)
        out.extend(p for p in ASSIGNMENT_SPLIT_RE.split(candidate) if p)
    return out


def respond(cfg: dict, reason: str) -> None:
    if cfg.get("action") == "ask":
        print(json.dumps({
            "continue": True,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": f"agent-fence (block-sensitive-files): {reason}",
            },
        }))
    else:
        print(json.dumps({
            "continue": False,
            "stopReason": f"Blocked by agent-fence (block-sensitive-files): {reason}",
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
    cfg = _config.load("block_sensitive_files")

    try:
        data = json.load(sys.stdin)
    except Exception:
        allow()
        return

    if not cfg.get("enabled", True):
        allow()
        return

    tool = data.get("tool_name") or ""
    tool_input = data.get("tool_input") or {}

    if tool in ("Read", "Grep"):
        path = tool_input.get("file_path") or tool_input.get("path") or ""
        reason = path_is_sensitive(path, cfg, resolve=True)
        if reason:
            respond(cfg, f"target is {reason}")
        allow()
        return

    if tool in ("Bash", "PowerShell"):
        cmd = tool_input.get("command") or ""
        for token in tokenize_command(cmd):
            if not token or token.startswith("-"):
                continue
            reason = path_is_sensitive(token, cfg)
            if reason:
                respond(cfg, f"command references {reason}")
        allow()
        return

    allow()


if __name__ == "__main__":
    main()
