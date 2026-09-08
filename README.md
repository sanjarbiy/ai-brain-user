# ai-brain-user — participant client (MCP)

A stdio **MCP server** you connect to your CLI agent (Claude Code, Codex, Google Antigravity, or any MCP-capable agent) to work in your team's shared workspace.

## Requirements

- **Node.js 20 or newer.** Node **22.5+** additionally enables the offline note queue + presence heartbeat (they use Node's built-in `node:sqlite`); on Node 20 the MCP works fully online, those two extras are just disabled. Check with `node -v`.
- `git`
- Your team's **server URL** and a personal **API key** (generate it on the Settings page).

> Using `nvm`? Agents launch the MCP with the `PATH` they were started with, which may be the **system** Node (often v20), not your nvm shell's. Run `nvm alias default 22` (or point the MCP command at an absolute node path) so the agent uses the Node you expect.

## Install

```bash
git clone https://github.com/sanjarbiy/ai-brain-user
cd ai-brain-user
npm install       # runtime deps; dist/cli.js is prebuilt and committed
```

The MCP runs from the prebuilt bundle **`dist/cli.js`** — plain `node`, no `tsx`, fast cold start. (To rebuild from source after editing: `npm run build`.)

## 1. Add your keys (one-time)

On the **Settings** page, add one OpenRouter key for **each task tier** — high priority (deep reasoning), medium/low (chat + memory), and images (vision) — plus **one Jina key** (web research). You can add more keys to any tier for extra rate-limit failover. From the CLI:

```bash
node dist/cli.js keys
```

## 2. Generate your API key

On **Settings → Connect API keys**, generate a key (shown once — copy it). It carries your workspace, so `BRAIN_CTF` is not needed.

Your API key **locks to the first computer that uses it** (it binds to a device id stored in `BRAIN_STATE_DIR`). The same token will not work from another machine — to move it, revoke the key and generate a new one on the new computer. This makes a leaked token useless elsewhere, and lets the backend tie every request to one user on one device.

## 3. Connect the MCP to your agent

Run the connect command **from inside the cloned `ai-brain-user` folder** so `$(pwd)` expands to the absolute path on its own (no hand-editing), and `$(openssl rand -hex 32)` fills in `BRAIN_VAULT_KEY`. Replace only the server URL and `mcp_your_generated_key`.

Environment:

```
BRAIN_SERVER=https://your-team-server.example
BRAIN_TOKEN=mcp_your_generated_key
BRAIN_STATE_DIR=$HOME/.mcp-console            # any writable path; ~ and $HOME are accepted
BRAIN_VAULT_KEY=<64-hex>                       # openssl rand -hex 32 — optional (offline persistence only)
```

### Claude Code

```bash
cd ai-brain-user
claude mcp add mcp-console -s user \
  --env BRAIN_SERVER=https://your-team-server.example \
  --env BRAIN_TOKEN=mcp_your_generated_key \
  --env BRAIN_STATE_DIR=$HOME/.mcp-console \
  --env BRAIN_VAULT_KEY=$(openssl rand -hex 32) \
  -- node "$(pwd)/dist/cli.js" mcp
```

`-s user` registers it for your whole user account. Without it, `claude mcp add` defaults to **local** (project) scope — the server is bound to the current directory and vanishes when you open Claude Code somewhere else. Restart Claude Code, then verify with `claude mcp list` (look for `mcp-console … ✔ Connected`).

### Codex CLI

```bash
cd ai-brain-user
codex mcp add mcp-console \
  --env BRAIN_SERVER=https://your-team-server.example \
  --env BRAIN_TOKEN=mcp_your_generated_key \
  --env BRAIN_STATE_DIR=$HOME/.mcp-console \
  --env BRAIN_VAULT_KEY=$(openssl rand -hex 32) \
  -- node "$(pwd)/dist/cli.js" mcp
```

Or edit `~/.codex/config.toml` (Windows: `C:\Users\you\.codex\config.toml`) — use a real absolute path to `dist/cli.js`:

```toml
[mcp_servers.mcp-console]
command = "node"
args = ["/absolute/path/ai-brain-user/dist/cli.js", "mcp"]

[mcp_servers.mcp-console.env]
BRAIN_SERVER = "https://your-team-server.example"
BRAIN_TOKEN = "mcp_your_generated_key"
BRAIN_STATE_DIR = "/home/you/.mcp-console"
BRAIN_VAULT_KEY = "<64-hex>"
```

Restart Codex; verify with `codex mcp list`. (The prebuilt bundle starts instantly, so the old `startup_timeout_sec = 60` workaround is no longer needed.)

### Google Antigravity ("agy")

Edit `~/.gemini/config/mcp_config.json` (Windows: `C:\Users\you\.gemini\config\mcp_config.json`) — or in the IDE open **… → MCP Servers → Manage MCP Servers → View raw config**, or in the CLI type **`/mcp`**. This is static JSON (no shell expansion), so put a **real** absolute path (run `pwd` in the repo) and a real 64-hex `BRAIN_VAULT_KEY`:

```json
{
  "mcpServers": {
    "mcp-console": {
      "command": "node",
      "args": ["/absolute/path/ai-brain-user/dist/cli.js", "mcp"],
      "env": {
        "BRAIN_SERVER": "https://your-team-server.example",
        "BRAIN_TOKEN": "mcp_your_generated_key",
        "BRAIN_STATE_DIR": "/home/you/.mcp-console",
        "BRAIN_VAULT_KEY": "<64-hex>"
      }
    }
  }
}
```

On Windows use forward slashes in the path (or escape backslashes). Save, then reload from the **Manage MCP Servers** panel (IDE) or `/mcp` (CLI).

### hackerai

hackerai does **not** connect external MCP servers — it runs its own built-in tools in a sandbox. Two options to use this client from there:

1. **Run it as a shell command** in hackerai's terminal — install this repo on the sandbox host and call a CLI subcommand directly (see `node dist/cli.js help`), instead of the persistent `mcp` server.
2. **Add it as a native tool** by patching the hackerai source (advanced).

## Verify / troubleshoot

```bash
node dist/cli.js doctor      # runtime + API + session + workspace checks
```

- **Agent shows "failed to connect" but `doctor` works in your terminal** → the agent launched the MCP under a different Node than your shell. Set `nvm alias default 22`, or use an absolute node path in the MCP command.
- `localStateSupported: false` in `doctor` → you're on Node < 22.5; the MCP still works, only the offline queue/presence are off.

## Safety

`ctf_agent` runs commands as **local shell on your machine** (guarded only against host-destructive commands like `rm -rf /`). Enable it only on a host where you accept local command execution. The client logs to stderr, not stdout — stdio MCP multiplexes JSON-RPC over stdout.

## From source (development)

```bash
node --import tsx client/src/cli.ts help    # run TS directly with tsx (no build step)
npm run build                               # regenerate dist/cli.js after editing client/src
```
