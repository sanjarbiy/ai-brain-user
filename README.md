# ai-brain-user — participant client (MCP)

A stdio **MCP server** you connect to your CLI agent (Claude Code, Codex, Google Antigravity, or any MCP-capable agent) so it can work inside your team's shared offensive-intelligence workspace — recon notes, findings, and an autonomous solver, all coordinated on the server and executed on your machine.

Follow the steps in order. By the end your agent has the `ctf_*` workspace tools plus `consult_brain` and `ctf_agent`.

---

## 1. What you need

Three things, on the machine you'll run tools from (for example, your Kali box):

- **Node.js 20 or newer, and `git`.** Check with `node -v`. Node **22.5+** additionally turns on the offline note queue + presence heartbeat (they use Node's built-in `node:sqlite`); on Node 20 everything else works.
  - Using **nvm**? Agents launch the MCP with the `PATH` they were started with — often the *system* Node (v20), not your nvm shell's. Run `nvm alias default 22` (or point the MCP command at an absolute node path) so the agent uses the Node you expect.
- **An account on this workspace.** Ask your team admin to add you (they open **Team → Add member**); they'll give you your email and a one-time **temporary password**.
- **OpenRouter + Jina API keys** (free tiers are fine): three OpenRouter keys from [openrouter.ai](https://openrouter.ai) and one Jina key from [jina.ai](https://jina.ai). Research and reasoning run on *your* quota, so you provide your own.

## 2. Sign in

Open your team's dashboard (e.g. `https://mcp.sansec.uz`) and sign in with your email and the temporary password from your admin. The dashboard is where you do steps 3 and 4.

## 3. Add your provider keys

On **Settings → Connect keys**, add one OpenRouter key for **each task tier** — high priority (deep reasoning), medium / low (chat + memory), and images (vision) — plus one **Jina** key (web research).

This is **required**: until all four keys are in, your API key won't issue and the AI tools stay locked. Add more keys to a tier for extra rate-limit failover. (You can also do this from the terminal after step 5: `node dist/cli.js keys`.)

## 4. Generate your API key

On **Settings → Connect API keys**, click **Generate** and copy the key — it's shown once. It already carries your workspace, so you never set `BRAIN_CTF`.

Your key **locks to the first computer that uses it** (it binds to a device id stored in `BRAIN_STATE_DIR`). A copied token won't work from another machine — to move it, revoke the key and generate a new one there. This makes a leaked token useless elsewhere and lets the backend tie every request to one user on one device.

## 5. Get the client

On your machine, clone the repo and install dependencies. The MCP runs from the prebuilt **`dist/cli.js`** bundle — plain `node`, no `tsx`, fast cold start.

```bash
git clone https://github.com/sanjarbiy/ai-brain-user
cd ai-brain-user
npm install
```

(To rebuild the bundle after editing the source: `npm run build`.)

## 6. Connect the MCP to your agent

Run the command for your agent **from inside the cloned `ai-brain-user` folder**, so `$(pwd)` becomes the absolute path on its own (no hand-editing) and `$(openssl rand -hex 32)` generates a local encryption key. Replace only the server URL and `mcp_your_generated_key` (from step 4).

> `BRAIN_STATE_DIR` is any writable path (`~` and `$HOME` are both accepted). `BRAIN_VAULT_KEY` is optional — it encrypts local session/offline storage only.

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

`-s user` registers it for your whole account. Without it, `claude mcp add` defaults to **local** (project) scope — the server binds to the current directory and vanishes when you open Claude Code elsewhere. Restart Claude Code.

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

The prebuilt bundle starts instantly, so the old `startup_timeout_sec = 60` workaround is no longer needed. Restart Codex.

### Google Antigravity ("agy")

Edit `~/.gemini/config/mcp_config.json` (Windows: `C:\Users\you\.gemini\config\mcp_config.json`) — or in the IDE open **… → MCP Servers → View raw config**, or in the CLI type **`/mcp`**. This is static JSON (no shell expansion), so use a **real** absolute path (run `pwd` in the repo) and a real 64-hex `BRAIN_VAULT_KEY`:

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

On Windows use forward slashes in the path. Save, then reload from the **Manage MCP Servers** panel (IDE) or `/mcp` (CLI).

### hackerai

hackerai does **not** connect external MCP servers — it runs its own built-in tools in a sandbox. Use this client as a shell command in its terminal instead (see `node dist/cli.js help`), or add it as a native tool by patching the hackerai source (advanced).

## 7. Verify & troubleshoot

Restart your agent so it loads the server, then:

```bash
claude mcp list           # look for: mcp-console … ✔ Connected
node dist/cli.js doctor   # api, identity, workspace — all green
```

- A tool returns **424 "add your key"** → finish step 3 (you're missing a tier or the Jina key).
- Your agent says **"failed to connect"** but `node dist/cli.js doctor` works in your terminal → the agent launched a different Node. Set `nvm alias default 22`, or use an absolute node path in the MCP command.
- `localStateSupported: false` in `doctor` → you're on Node < 22.5; the MCP still works, only the offline queue/presence are off.

## Safety

`ctf_agent` runs commands as **local shell on your machine** (guarded only against host-destructive commands like `rm -rf /`). Enable it only on a host where you accept local command execution. The client logs to stderr, not stdout — stdio MCP multiplexes JSON-RPC over stdout.

## From source (development)

```bash
node --import tsx client/src/cli.ts help    # run the TypeScript directly with tsx (no build)
npm run build                               # regenerate dist/cli.js after editing client/src
```
