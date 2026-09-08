// Scan activity normalization and duplicate detection (specification sections 13 and 14).
// Pure, dependency-free logic shared by the server duplicate detector and the local
// `ctf run` telemetry wrapper. It describes the SHAPE of an activity so equivalent work by
// different tools is recognized as overlapping. It never executes anything.

export type ActivityFamily =
  | 'PORT_DISCOVERY'
  | 'SERVICE_DETECTION'
  | 'CONTENT_DISCOVERY'
  | 'VULN_SCAN'
  | 'HTTP_PROBE'
  | 'SUBDOMAIN_ENUM'
  | 'SQL_INJECTION_TEST'
  | 'UNKNOWN';

export type Protocol = 'TCP' | 'UDP' | 'HTTP' | 'NONE';

export type ScanFingerprint = {
  target: string;
  activityFamily: ActivityFamily;
  protocol: Protocol;
  ports: string;
  pathScope: string;
  wordlistFamily: string;
  toolFamily: string;
};

export type ScanInput = {
  target: string;
  tool?: string;
  command?: string;
  activityFamily?: ActivityFamily;
  ports?: string;
  pathScope?: string;
  wordlist?: string;
};

const TOOL_FAMILY: Record<string, string> = {
  nmap: 'portscanner',
  masscan: 'portscanner',
  rustscan: 'portscanner',
  unicornscan: 'portscanner',
  zmap: 'portscanner',
  ffuf: 'content-fuzzer',
  feroxbuster: 'content-fuzzer',
  gobuster: 'content-fuzzer',
  dirb: 'content-fuzzer',
  dirbuster: 'content-fuzzer',
  dirsearch: 'content-fuzzer',
  wfuzz: 'content-fuzzer',
  nuclei: 'vuln-scanner',
  nikto: 'vuln-scanner',
  httpx: 'http-prober',
  httprobe: 'http-prober',
  subfinder: 'subdomain-enum',
  amass: 'subdomain-enum',
  assetfinder: 'subdomain-enum',
  findomain: 'subdomain-enum',
  sqlmap: 'sqli-tester',
};

const FAMILY_ACTIVITY: Record<string, ActivityFamily> = {
  portscanner: 'PORT_DISCOVERY',
  'content-fuzzer': 'CONTENT_DISCOVERY',
  'vuln-scanner': 'VULN_SCAN',
  'http-prober': 'HTTP_PROBE',
  'subdomain-enum': 'SUBDOMAIN_ENUM',
  'sqli-tester': 'SQL_INJECTION_TEST',
};

const round = (n: number) => Math.round(n * 1000) / 1000;
const clamp = (n: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, n));

function normalizePorts(command: string, tool: string, explicit?: string): string {
  if (explicit) return explicit.trim();
  const c = command.toLowerCase();
  if (/-p-(\s|$)/.test(c) || /-p\s*1-65535/.test(c) || /-p\s*0-65535/.test(c))
    return 'full(1-65535)';
  const top = c.match(/--top-ports\s+(\d+)/);
  if (top) return `top-${top[1]}`;
  const range = c.match(/-p\s*([0-9,\-]+)/);
  if (range) return range[1].replace(/\s+/g, '');
  // rustscan scans the full range by default when no port flag is given.
  if (tool === 'rustscan') return 'full(1-65535)';
  return 'default';
}

function normalizePath(command: string, explicit?: string): string {
  if (explicit) return explicit;
  const url = command.match(/https?:\/\/[^\s'"]+/i);
  if (!url) return '/';
  try {
    const pathname = new URL(url[0].replace(/FUZZ/g, '')).pathname || '/';
    return pathname.replace(/\/+$/, '') || '/';
  } catch {
    return '/';
  }
}

function wordlistFamilyOf(command: string, explicit?: string): string {
  const w =
    explicit || command.match(/-w\s+(\S+)/i)?.[1] || command.match(/--wordlist[=\s]+(\S+)/i)?.[1];
  if (!w) return 'none';
  const base = w.split(/[\\/]/).pop()!.toLowerCase();
  if (base.includes('common')) return 'common';
  if (base.includes('raft')) return 'raft';
  if (base.includes('directory-list') || base.includes('dirbuster')) return 'directory-list';
  if (base.includes('big')) return 'big';
  return base.replace(/\.(txt|lst)$/, '');
}

export function normalizeScan(input: ScanInput): ScanFingerprint {
  const command = (input.command || '').trim();
  const tool = (input.tool || command.split(/\s+/)[0] || '').toLowerCase();
  const toolFamily = TOOL_FAMILY[tool] || 'unknown';
  let activityFamily: ActivityFamily =
    input.activityFamily || FAMILY_ACTIVITY[toolFamily] || 'UNKNOWN';
  // nmap service/aggressive flags are case-sensitive (-sV/-sC/-A); match the original command so
  // rustscan's lowercase -a (address) is not mistaken for nmap's -A (aggressive).
  if (activityFamily === 'PORT_DISCOVERY' && /(-sV|-sC|-A)(\s|$)/.test(command))
    activityFamily = 'SERVICE_DETECTION';

  let protocol: Protocol = 'NONE';
  if (activityFamily === 'PORT_DISCOVERY' || activityFamily === 'SERVICE_DETECTION')
    protocol = /-sU(\s|$)/.test(command) ? 'UDP' : 'TCP';
  else if (
    activityFamily === 'CONTENT_DISCOVERY' ||
    activityFamily === 'HTTP_PROBE' ||
    activityFamily === 'VULN_SCAN' ||
    activityFamily === 'SQL_INJECTION_TEST'
  )
    protocol = 'HTTP';

  const portRelevant = protocol === 'TCP' || protocol === 'UDP';
  const contentRelevant = activityFamily === 'CONTENT_DISCOVERY';
  return {
    target: input.target,
    activityFamily,
    protocol,
    ports: portRelevant ? normalizePorts(command, tool, input.ports) : 'n/a',
    pathScope: contentRelevant ? normalizePath(command, input.pathScope) : 'n/a',
    wordlistFamily: contentRelevant ? wordlistFamilyOf(command, input.wordlist) : 'n/a',
    toolFamily,
  };
}

export function exactDuplicateScore(a: ScanFingerprint, b: ScanFingerprint): number {
  return a.target === b.target &&
    a.activityFamily === b.activityFamily &&
    a.protocol === b.protocol &&
    a.ports === b.ports &&
    a.pathScope === b.pathScope
    ? 1
    : 0;
}

export function semanticOverlapScore(a: ScanFingerprint, b: ScanFingerprint): number {
  if (a.target !== b.target) return 0;
  if (a.activityFamily === 'UNKNOWN' || b.activityFamily === 'UNKNOWN') return 0;
  if (a.activityFamily !== b.activityFamily) return 0;
  let score = 0.6;
  if (a.protocol === b.protocol) score += 0.15;
  if (a.ports === b.ports) score += 0.15;
  if (a.pathScope === b.pathScope) score += 0.1;
  return round(score);
}

export function freshnessScore(startedSecondsAgo: number, ttlSeconds = 3600): number {
  return round(clamp(1 - startedSecondsAgo / ttlSeconds, 0, 1));
}

export function leaseExpired(lastHeartbeatSecondsAgo: number, ttlSeconds = 120): boolean {
  return lastHeartbeatSecondsAgo > ttlSeconds;
}

export type ScanStatus = 'STARTED' | 'ACTIVE' | 'FINISHED' | 'EXPIRED' | 'FAILED';
export type ScanDecisionKind = 'ALLOW' | 'ALLOW_WITH_WARNING' | 'WARN' | 'BLOCK_DUPLICATE';

export type ExistingRun = {
  fingerprint: ScanFingerprint;
  participant: string;
  activity: string;
  startedSecondsAgo: number;
  status: ScanStatus;
};

export type ScanDecision = {
  decision: ScanDecisionKind;
  overlap: number;
  activeRun?: {
    participant: string;
    activity: string;
    startedSecondsAgo: number;
    status: ScanStatus;
  };
  recommendation: string;
};

function ref(run: ExistingRun) {
  return {
    participant: run.participant,
    activity: run.activity,
    startedSecondsAgo: run.startedSecondsAgo,
    status: run.status,
  };
}

export function decideScan(
  candidate: ScanFingerprint,
  existing: ExistingRun[],
  opts: { force?: boolean } = {},
): ScanDecision {
  let best: ExistingRun | undefined;
  let bestOverlap = 0;
  let bestExact = 0;
  for (const run of existing) {
    if (run.status === 'EXPIRED' || run.status === 'FAILED') continue;
    const overlap = semanticOverlapScore(candidate, run.fingerprint);
    if (overlap === 0) continue;
    const active = run.status === 'STARTED' || run.status === 'ACTIVE';
    const bestActive = best ? best.status === 'STARTED' || best.status === 'ACTIVE' : false;
    // Prefer higher overlap; break ties in favor of an active run so a live duplicate wins.
    if (overlap > bestOverlap || (overlap === bestOverlap && active && !bestActive)) {
      bestOverlap = overlap;
      best = run;
      bestExact = exactDuplicateScore(candidate, run.fingerprint);
    }
  }
  if (opts.force)
    return {
      decision: 'ALLOW',
      overlap: bestOverlap,
      activeRun: best && ref(best),
      recommendation: 'Override accepted. The duplication reason is recorded with this run.',
    };
  if (!best || bestOverlap < 0.6)
    return {
      decision: 'ALLOW',
      overlap: bestOverlap,
      recommendation: 'No overlapping team activity found. Proceed.',
    };
  const active = best.status === 'STARTED' || best.status === 'ACTIVE';
  if (bestExact === 1 && active)
    return {
      decision: 'BLOCK_DUPLICATE',
      overlap: bestOverlap,
      activeRun: ref(best),
      recommendation: `${best.participant} is already running ${best.activity}. Reuse that result or pick a different subtask; override with a reason only if independent validation is required.`,
    };
  if (bestOverlap >= 0.9 && active)
    return {
      decision: 'WARN',
      overlap: bestOverlap,
      activeRun: ref(best),
      recommendation: `${best.participant} is running very similar work (${best.activity}). Prefer reusing it.`,
    };
  return {
    decision: 'ALLOW_WITH_WARNING',
    overlap: bestOverlap,
    activeRun: ref(best),
    recommendation: active
      ? `Overlaps ${best.participant}'s active ${best.activity}. Coordinate before proceeding.`
      : `${best.participant} recently completed ${best.activity}. Consider reusing that result.`,
  };
}
