// Category-aware readiness / preflight (specification sections 34-37). Returns a capability
// inventory, not a flat PASS/FAIL, and evaluates readiness relative to the challenge category: a web
// participant is not blocked by missing Android tools. Tool detection is injected so the logic is
// testable without a real machine. Secrets are never handled here.

export type ToolCategory = 'base' | 'web' | 'mobile' | 'reverse' | 'pwn' | 'forensics';

export const TOOL_CATEGORIES: Record<ToolCategory, string[]> = {
  base: ['curl', 'wget', 'git', 'python', 'node', 'openssl'],
  web: ['nmap', 'ffuf', 'feroxbuster', 'gobuster', 'httpx', 'nuclei', 'sqlmap'],
  mobile: ['adb', 'jadx', 'apktool', 'frida'],
  reverse: ['gdb', 'radare2', 'objdump', 'ghidra'],
  pwn: ['gdb', 'checksec', 'ROPgadget', 'pwntools'],
  forensics: ['binwalk', 'exiftool', 'foremost', 'volatility'],
};

export type Detector = (tool: string) => boolean;
export type AgentReadiness = Record<string, 'READY' | 'NOT_CONFIGURED'>;
export type ReadinessInput = { category?: ToolCategory; agents?: AgentReadiness };

export type ReadinessReport = {
  health: 'GREEN' | 'YELLOW' | 'RED';
  score: number;
  ready: boolean;
  categories: Record<string, { present: string[]; missing: string[] }>;
  missingRequired: string[];
  missingOptional: string[];
  agents: AgentReadiness;
};

export function capabilityInventory(detect: Detector, input: ReadinessInput = {}): ReadinessReport {
  // `detect` is an expensive probe (a `which`/`where` process spawn in the real CLI) and a
  // deterministic predicate for a given tool within one call, so memoize it: each distinct tool is
  // probed exactly once instead of up to 4x (present + missing + missingRequired + score count). The
  // returned report is identical; only the number of probes drops.
  const probed = new Map<string, boolean>();
  const detectOnce = (tool: string): boolean => {
    let hit = probed.get(tool);
    if (hit === undefined) probed.set(tool, (hit = detect(tool)));
    return hit;
  };
  const categories: Record<string, { present: string[]; missing: string[] }> = {};
  for (const [category, tools] of Object.entries(TOOL_CATEGORIES)) {
    const present: string[] = [];
    const missing: string[] = [];
    for (const t of tools) (detectOnce(t) ? present : missing).push(t);
    categories[category] = { present, missing };
  }

  // Relevant to the assigned role: base always, plus the challenge category when known.
  const relevant: ToolCategory[] = input.category ? ['base', input.category] : ['base'];
  const relevantTools = [...new Set(relevant.flatMap((c) => TOOL_CATEGORIES[c]))];
  const missingRequired = [...new Set(relevantTools.filter((t) => !detectOnce(t)))];
  const missingOptional = [
    ...new Set(
      (Object.keys(TOOL_CATEGORIES) as ToolCategory[])
        .filter((c) => !relevant.includes(c))
        .flatMap((c) => categories[c].missing),
    ),
  ];
  const present = relevantTools.filter(detectOnce).length;
  const score = relevantTools.length ? Math.round((present / relevantTools.length) * 100) : 100;
  const ready = missingRequired.length === 0;
  const health: 'GREEN' | 'YELLOW' | 'RED' = !ready
    ? 'RED'
    : missingOptional.length
      ? 'YELLOW'
      : 'GREEN';
  return {
    health,
    score,
    ready,
    categories,
    missingRequired,
    missingOptional,
    agents: input.agents ?? {},
  };
}
