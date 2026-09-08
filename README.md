# ctf-brain-user — participant client (MCP)

A stdio **MCP server** you connect to your CLI agent (Claude Code, Codex, Google Antigravity, or any MCP-capable agent) to work in your team's shared workspace.

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

On the **Settings** page, add one OpenRouter key for **each task tier** — high priority (deep reasoning), medium/low (chat + memory), and images (vision) — plus **one Jina key** (web research). You can add more keys to any tier for extra rate-limit failover. From the CLI:

```bash
node --import tsx client/src/cli.ts keys
```

## 2. Generate your API key

On **Settings → Connect API keys**, generate a key (shown once — copy it). It carries your workspace, so `BRAIN_CTF` is not needed.

## 3. Connect the MCP to your agent

The MCP server is always the same command:

```
node --import tsx <ABSOLUTE-PATH>/ctf-brain-user/client/src/cli.ts mcp
```

with these env vars (use an **absolute** `BRAIN_STATE_DIR` — `~` is not expanded by every agent):

```
BRAIN_SERVER=https://your-team-server.example
BRAIN_TOKEN=mcp_your_generated_key
BRAIN_STATE_DIR=/home/you/.mcp-console        # Windows: C:\Users\you\.mcp-console
BRAIN_VAULT_KEY=<64-hex>                       # openssl rand -hex 32
```

### Claude Code

```bash
claude mcp add mcp-console \
  --env BRAIN_SERVER=https://your-team-server.example \
  --env BRAIN_TOKEN=mcp_your_generated_key \
  --env BRAIN_STATE_DIR=$HOME/.mcp-console \
  --env BRAIN_VAULT_KEY=$(openssl rand -hex 32) \
  -- node --import tsx /absolute/path/ctf-brain-user/client/src/cli.ts mcp
```

Restart Claude Code.

### Codex CLI

**Option A — `codex mcp add`** (everything after `--` is the server command):

```bash
codex mcp add mcp-console \
  --env BRAIN_SERVER=https://your-team-server.example \
  --env BRAIN_TOKEN=mcp_your_generated_key \
  --env BRAIN_STATE_DIR=/home/you/.mcp-console \
  --env BRAIN_VAULT_KEY=<64-hex> \
  -- node --import tsx /absolute/path/ctf-brain-user/client/src/cli.ts mcp
```

**Option B — edit `~/.codex/config.toml`** (Windows: `C:\Users\you\.codex\config.toml`):

```toml
[mcp_servers.mcp-console]
command = "node"
args = ["--import", "tsx", "/absolute/path/ctf-brain-user/client/src/cli.ts", "mcp"]
startup_timeout_sec = 60   # tsx compiles TS on first launch; raise from the default 10s

[mcp_servers.mcp-console.env]
BRAIN_SERVER = "https://your-team-server.example"
BRAIN_TOKEN = "mcp_your_generated_key"
BRAIN_STATE_DIR = "/home/you/.mcp-console"
BRAIN_VAULT_KEY = "<64-hex>"
```

**Set `startup_timeout_sec = 60`** even if you used Option A (edit the entry `add` created) — otherwise the first launch times out while tsx compiles. Restart Codex; verify with `codex mcp list`.

### Google Antigravity ("agy")

Edit `~/.gemini/config/mcp_config.json` (Windows: `C:\Users\you\.gemini\config\mcp_config.json`) — or in the IDE open **… → MCP Servers → Manage MCP Servers → View raw config**, or in the CLI type **`/mcp`**:

```json
{
  "mcpServers": {
    "mcp-console": {
      "command": "node",
      "args": ["--import", "tsx", "/absolute/path/ctf-brain-user/client/src/cli.ts", "mcp"],
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

1. **Run it as a shell command** in hackerai's terminal — install this repo on the sandbox host and call a CLI subcommand directly (see `cli.ts help`), instead of the persistent `mcp` server.
2. **Add it as a native tool** by patching the hackerai source (advanced).

## Safety

`ctf_agent` runs commands as **local shell on your machine** (guarded only against host-destructive commands like `rm -rf /`). Enable it only on a host where you accept local command execution. Make sure the client logs to stderr, not stdout — stdio MCP multiplexes JSON-RPC over stdout.

## CLI

```bash
node --import tsx client/src/cli.ts help
```

`login` / `redeem` (join with an invite code), `keys` (submit your OpenRouter/Jina keys), `mcp` (serve the MCP), `status`, `doctor`.
