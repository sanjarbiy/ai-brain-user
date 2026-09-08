import { spawn } from 'node:child_process';

// The agent's LOCAL shell. Commands the backend brain decides are executed here, on the operator's
// own machine — that is where the CTF target is reachable (the server cannot reach the operator's
// local network). Output is capped and the command's whole process group is killed on timeout, so a
// runaway, huge-output, or backgrounded command cannot hang the loop or leak processes. Everything
// offensive is allowed; only commands that would destroy the operator's HOST (not attack the target)
// are refused.

export type ExecOutcome = { output: string; code: number; timedOut: boolean; blocked?: boolean };

// Programs that are never a legitimate attack on a target and would wreck the operator's host.
const DESTRUCTIVE = /^(?:shutdown|reboot|halt|poweroff|mkfs(?:\.[a-z0-9]+)?|wipefs|fdisk|sfdisk)$/i;

// The programs actually invoked by a command line — at its start, or after a separator (; & |) or
// sudo/xargs. This means a hostname, URL path, or grep/wordlist argument that merely CONTAINS a word
// like "reboot" or "mkfs" is not mistaken for invoking it.
function invokedPrograms(command: string): string[] {
  return command
    .split(/[;\n]|&&|\|\||[|&]|`|\$\(/) // command boundaries (;, newline, &&, ||, |, &, backtick, $( )
    .map((seg) =>
      seg
        .trim()
        .replace(/^(?:sudo|xargs|env|nohup|time|nice)\s+/i, '') // drop common wrapper prefixes
        .replace(/^\w+=\S*\s+/, ''), // drop a leading VAR=value assignment
    )
    .map((seg) => ((seg.match(/[A-Za-z0-9_./-]+/) || [''])[0] || '').replace(/^.*\//, '')) // basename of the program
    .filter(Boolean);
}

export function isDangerous(command: string): boolean {
  const progs = invokedPrograms(command);
  if (progs.some((p) => DESTRUCTIVE.test(p))) return true;
  if (progs.includes('init') && /\binit\s+[06]\b/.test(command)) return true;
  // rm invoked with recursive AND force AND a root-ish target ("/", "'/'", "/*") — order-independent,
  // so `rm -fr /`, `rm -rf "/"`, and `rm --recursive --force /` are all caught, while `rm -rf ./loot`
  // is not.
  if (progs.includes('rm')) {
    const recursive = /(?:^|\s)-[A-Za-z]*r|--recursive/.test(command);
    const force = /(?:^|\s)-[A-Za-z]*f|--force/.test(command);
    const rootTarget = /\s(['"]?)\/\1(?:\s|$|\*)/.test(command);
    if (recursive && force && rootTarget) return true;
  }
  if (/\bdd\b[^\n]*\bof=\/dev\/(?:sd|nvme|vd|hd)/i.test(command)) return true; // overwrite a raw disk
  if (/>\s*\/dev\/(?:sd|nvme|vd|hd)[a-z]/i.test(command)) return true; // redirect over a raw disk
  if (/:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/.test(command)) return true; // fork bomb
  return false;
}

export function localExec(opts: { timeoutMs?: number; shell?: string; cap?: number } = {}) {
  const timeoutMs = Math.min(Math.max(opts.timeoutMs ?? 120000, 1000), 600000);
  const cap = opts.cap ?? 100000;
  const shell = opts.shell ?? 'bash';
  return (command: string): Promise<ExecOutcome> => {
    if (isDangerous(command))
      return Promise.resolve({
        output: 'Refused: this command looks host-destructive, not an attack on the target.',
        code: 126,
        timedOut: false,
        blocked: true,
      });
    return new Promise<ExecOutcome>((resolve) => {
      // detached:true puts the shell in its own process group so a timeout can kill the WHOLE tree
      // (a pipeline like `nmap ... | tee` or a backgrounded worker), not just the bash wrapper —
      // which would otherwise orphan the real tool to PID 1 and keep hammering the target.
      const child = spawn(shell, ['-lc', command], { detached: true });
      let out = '';
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        try {
          if (child.pid) process.kill(-child.pid, 'SIGKILL');
          else child.kill('SIGKILL');
        } catch {
          try {
            child.kill('SIGKILL');
          } catch {
            /* already gone */
          }
        }
      }, timeoutMs);
      const add = (d: Buffer) => {
        if (out.length < cap) out += d.toString();
      };
      child.stdout.on('data', add);
      child.stderr.on('data', add);
      child.on('close', (code) => {
        clearTimeout(timer);
        resolve({
          output: out.slice(0, cap) + (timedOut ? '\n[killed: timeout]' : ''),
          code: code ?? -1,
          timedOut,
        });
      });
      child.on('error', (e) => {
        clearTimeout(timer);
        resolve({ output: `${out}${String(e)}`, code: -1, timedOut });
      });
    });
  };
}
