# agent-fence

A [Claude Code](https://claude.com/claude-code) plugin that blocks risky or unwanted agent behavior with deterministic `PreToolUse` hooks — code that runs *before* a tool call executes, not model judgment. It currently covers four categories:

1. **Network/filesystem scanning** — scanner tool names (nmap, masscan, zmap, ...), recursive scans of a bare drive root or system directory, access to another user's profile.
2. **Sensitive-file access** — `.env` files, SSH/TLS private keys, `.ssh`/`.aws`/`.docker` dirs, npm/pip/netrc tokens, crypto wallets, generically-named credentials/secrets files.
3. **Destructive commands** — `git reset --hard`, `git push --force`, `git clean -f`, `rm -rf` on a root/home dir, `chmod 777`, `curl | sh`, fork bombs, `mkfs`, `crontab -r`, destructive `docker volume`/`system prune`.
4. **AI co-author attribution** — blocks a `git commit` whose message tries to credit Claude/Anthropic as a co-author.

Every category is configurable — enable/disable it, toggle individual rules, choose a hard `deny` vs. an `ask`-for-approval prompt, or add allowlist exceptions — either by hand-editing a JSON file or through a guided `/agent-fence:configure` command. See **[agent-fence/README.md](agent-fence/README.md)** for the full write-up: how each hook works, the configuration schema, and this plugin's own documented limits (it's a text-pattern heuristic, not a sandbox — see "What this is, and isn't").

## Repo layout

This repo is itself a local-directory [plugin marketplace](https://docs.claude.com/en/docs/claude-code/plugin-marketplaces) (`.claude-plugin/marketplace.json`) containing one plugin, `agent-fence/`.

```
.
├── .claude-plugin/marketplace.json   # marketplace manifest
└── agent-fence/                      # the plugin itself
    ├── .claude-plugin/plugin.json
    ├── hooks/hooks.json               # registers the four PreToolUse hooks
    ├── scripts/                       # the hook implementations + shared config loader
    ├── commands/configure.md          # the /agent-fence:configure guided command
    ├── tests/                         # 68 fixture-driven regression cases
    └── README.md                      # full documentation
```

## Install

```bash
git clone https://github.com/winsley-jeune/agent-fence.git
```

Then point Claude Code at your clone and enable the plugin — add this to `~/.claude/settings.json` (or your project's `.claude/settings.json`):

```jsonc
{
  "extraKnownMarketplaces": {
    "agent-fence": {
      "source": { "source": "directory", "path": "/absolute/path/to/your/agent-fence/clone" }
    }
  },
  "enabledPlugins": {
    "agent-fence@agent-fence": true
  }
}
```

Restart Claude Code (or start a new session) and the hooks are active. Run `/agent-fence:configure` to customize, or hand-edit `~/.claude/agent-fence.config.json` per the schema in `agent-fence/agent-fence.config.example.json`.

## Contributing

Contributions are welcome — new detection rules, bug fixes, documentation, anything. See **[CONTRIBUTING.md](CONTRIBUTING.md)** for how to set up, test, and submit changes.

## License

[MIT](LICENSE) — use it, fork it, build on it.
