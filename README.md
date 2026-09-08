# ctf-brain-user — participant client (MCP)

A stdio **MCP server** you connect to your CLI agent (Claude Code, Codex, or any MCP-capable agent) to work in your team's shared workspace.

## Requirements

- **Node.js 22+**
- `git`
- Your team's **server URL** and a personal **API key** (generate it on the Settings page).

## Install

```bash
git clone https://github.com/sanjarbiy/ctf-brain-user
cd ctf-brain-user
npm install
```

## 1. Add your keys (one-time)

On the **Settings** page, add at least **3 OpenRouter keys + 1 Jina key** — or from the CLI:

```bash
node --import tsx client/src/cli.ts keys
```

## 2. Generate your API key

On **Settings → Connect API keys**, generate a key (shown once — copy it). It carries your workspace, so `BRAIN_CTF` is not needed.

## 3. Connect the MCP to your CLI agent

**Claude Code:**

```bash
claude mcp add mcp-console \
  --env BRAIN_SERVER=https://your-team-server.example \
  --env BRAIN_TOKEN=mcp_your_generated_key \
  --env BRAIN_STATE_DIR=$HOME/.mcp-console \
  --env BRAIN_VAULT_KEY=$(openssl rand -hex 32) \
  -- node --import tsx /absolute/path/ctf-brain-user/client/src/cli.ts mcp
```

Restart your agent. Other agents (Codex, ...) use their own MCP config with the same command.

`BRAIN_VAULT_KEY` is a 64-char hex you choose; it only encrypts this client's local session storage. `BRAIN_CTF` is optional — your API key already carries its workspace.

## Safety

`ctf_agent` runs commands as **local shell on your machine** (guarded only against host-destructive commands like `rm -rf /`). Enable it only on a host where you accept local command execution.

## CLI

```bash
node --import tsx client/src/cli.ts help
```

`login` / `redeem` (join with an invite code), `keys` (submit your OpenRouter/Jina keys), `mcp` (serve the MCP), `status`, `doctor`.
