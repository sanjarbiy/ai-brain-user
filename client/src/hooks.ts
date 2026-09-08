// Optional shell hooks for CTF mode (specification section 15, Method B). These are printed for the
// participant to install deliberately. When CTF mode is on, the hook only prints a reminder to
// register a configured security tool with `ctf run`. It never runs, logs, or transmits any command;
// it is not a general-purpose command surveillance system, and it ignores unrelated activity.

export const SECURITY_TOOLS = [
  'nmap',
  'rustscan',
  'masscan',
  'ffuf',
  'feroxbuster',
  'gobuster',
  'dirb',
  'wfuzz',
  'nuclei',
  'nikto',
  'httpx',
  'sqlmap',
];

export type ShellName = 'bash' | 'zsh' | 'fish' | 'powershell';

export function generateHook(shell: ShellName, tools: string[] = SECURITY_TOOLS): string {
  const list = tools.join(' ');
  if (shell === 'bash' || shell === 'zsh') {
    const register =
      shell === 'zsh'
        ? 'autoload -Uz add-zsh-hook; add-zsh-hook preexec ctf_brain_preexec'
        : 'trap \'ctf_brain_preexec "$BASH_COMMAND"\' DEBUG';
    return `# CTF Brain optional shell hook (${shell}). Active only while CTF mode is on (CTF_MODE set).
# It only prints a reminder to register configured tools with 'ctf run'. It runs, logs, transmits nothing.
export CTF_BRAIN_TOOLS="${list}"
ctf_brain_preexec() {
  [ -n "$CTF_MODE" ] || return 0
  local first="\${1%% *}"
  case " $CTF_BRAIN_TOOLS " in
    *" $first "*) echo "ctf-brain: register this with 'ctf run --target LABEL -- $1'" ;;
  esac
}
${register}
`;
  }
  if (shell === 'fish') {
    return `# CTF Brain optional shell hook (fish). Active only while CTF mode is on (CTF_MODE set).
set -gx CTF_BRAIN_TOOLS ${list}
function ctf_brain_preexec --on-event fish_preexec
  test -n "$CTF_MODE"; or return 0
  set -l first (string split ' ' -- $argv[1])[1]
  if contains -- $first (string split ' ' -- $CTF_BRAIN_TOOLS)
    echo "ctf-brain: register this with 'ctf run --target LABEL -- $argv[1]'"
  end
end
`;
  }
  return `# CTF Brain optional shell hook (PowerShell). Active only while CTF mode is on ($env:CTF_MODE set).
$env:CTF_BRAIN_TOOLS = "${list}"
function global:Invoke-CtfBrainPreexec([string]$Line) {
  if (-not $env:CTF_MODE) { return }
  $first = ($Line -split ' ')[0]
  if (($env:CTF_BRAIN_TOOLS -split ' ') -contains $first) {
    Write-Host "ctf-brain: register this with 'ctf run --target LABEL -- $Line'"
  }
}
`;
}
