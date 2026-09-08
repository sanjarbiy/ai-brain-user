# CTF Brain — Participant Client (MCP)

The participant side of **CTF Brain / MCP Console** — a shared, real-time offensive-intelligence system for authorized CTF teams. This repository is the **client**: a stdio **MCP server** you plug into your CLI agent (Claude Code, Codex, or any MCP-capable agent).

Your CLI agent is the **orchestrator**. This MCP talks to your team's backend ("the brain"), which does the thinking, web research, and next-command decisions on **your own** API keys. **Shell runs locally on your machine, never on the server** — because that is where your CTF targets are reachable.

> This client is useless on its own. You need your team's backend server + a personal API key that your admin/system provides.

## Requirements

- **Node.js 22+** (the client uses the built-in `node:sqlite` for encrypted local state).
- `git`.
- Your team's **server URL** and a personal **API key** (generate it on the dashboard **Settings** page).

## Install

```bash
git clone https://github.com/<your-org>/ctf-brain-user
cd ctf-brain-user
npm install
```

## 1. Add your model keys (one-time)

The brain runs research + solving on **your** quota. On the dashboard **Settings** page, add **at least 3 OpenRouter keys + 1 Jina key** — or from the CLI:

```bash
node --import tsx client/src/cli.ts keys
```

## 2. Generate your API key

On the dashboard **Settings → Connect API keys**, click generate. The key is shown **once** — copy it. It carries your workspace, so `BRAIN_CTF` is not needed.

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

Then restart your agent. You now have the `ctf_*` tools plus `consult_brain` and `ctf_agent`.

**Other agents (Codex, etc.):** use their own MCP config format with the same command — `node --import tsx <abs-path>/client/src/cli.ts mcp` — and the same env.

`BRAIN_VAULT_KEY` is a 64-char hex **you** choose; it only encrypts this client's local session storage (it is not the server key). `BRAIN_CTF` is optional — your API key already carries its workspace.

## Safety

`ctf_agent` executes brain-chosen commands as **local shell on your machine** (guarded only against host-destructive commands like `rm -rf /`, not against offensive or outbound commands). Enable it only on a host where you accept local command execution — e.g. your Kali box. The server only decides the next command and does web research on your keys; it never runs your shell and cannot reach your local network.

## CLI reference

```bash
node --import tsx client/src/cli.ts help
```

Common commands: `login` / `redeem --code … --email … --name …` (join a team with an invite code), `keys` (submit your OpenRouter/Jina keys), `mcp` (serve the MCP stdio protocol), `status`, `doctor` (check runtime + API + session + workspace).

## What this repo is not

The backend (server, dashboard, brain prompts, database) is **not** here — it is your team's private deployment. This repo contains only the participant client + the shared protocol types it needs.
