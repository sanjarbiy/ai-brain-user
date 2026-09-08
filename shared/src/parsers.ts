// Pluggable tool-output parsers (specification section 16). Pure functions that turn a
// security tool's textual output into compact structured observations. Raw output is kept as an
// artifact; only the small structured observations flow into shared context. Adding a new tool
// means adding one ToolParser to the registry, not touching the pipeline.

export type ParsedObservation = {
  kind: 'observation' | 'finding';
  title: string;
  body: string;
  data?: Record<string, unknown>;
};

export type ParsedToolResult = {
  tool: string;
  observations: ParsedObservation[];
  summary: string;
};

export type ToolContext = { tool?: string; command?: string };

export interface ToolParser {
  name: string;
  canParse(ctx: ToolContext, output: string): boolean;
  parse(output: string, ctx: ToolContext): ParsedObservation[];
}

const lines = (output: string) =>
  output
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
const named = (ctx: ToolContext, name: string) =>
  (ctx.tool || ctx.command || '').toLowerCase().includes(name);

export const nmapParser: ToolParser = {
  name: 'nmap',
  canParse: (ctx, output) => named(ctx, 'nmap') || /^\d+\/(tcp|udp)\s+open/im.test(output),
  parse(output) {
    const obs: ParsedObservation[] = [];
    for (const line of lines(output)) {
      const m = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$/i);
      if (!m) continue;
      const [, port, proto, service, version] = m;
      obs.push({
        kind: 'observation',
        title: `${port}/${proto} ${service}${version ? ` (${version.trim()})` : ''}`,
        body: `Open ${proto.toUpperCase()} port ${port} running ${service}${version ? `: ${version.trim()}` : ''}.`,
        data: { port: Number(port), protocol: proto, service, version: version?.trim() },
      });
    }
    return obs;
  },
};

export const rustscanParser: ToolParser = {
  name: 'rustscan',
  canParse: (ctx, output) => named(ctx, 'rustscan') || /^Open\s+\S+:\d+/im.test(output),
  parse(output) {
    const obs: ParsedObservation[] = [];
    for (const line of lines(output)) {
      const m = line.match(/^Open\s+(\S+):(\d+)/i);
      if (m)
        obs.push({
          kind: 'observation',
          title: `${m[2]}/tcp open`,
          body: `Open TCP port ${m[2]} on ${m[1]}.`,
          data: { host: m[1], port: Number(m[2]), protocol: 'tcp' },
        });
    }
    return obs;
  },
};

export const ffufParser: ToolParser = {
  name: 'ffuf',
  canParse: (ctx, output) => named(ctx, 'ffuf') || /\[Status:\s*\d+,\s*Size:/i.test(output),
  parse(output) {
    const obs: ParsedObservation[] = [];
    for (const line of lines(output)) {
      const m = line.match(/^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)/i);
      if (m)
        obs.push({
          kind: 'observation',
          title: `/${m[1]} -> ${m[2]}`,
          body: `ffuf hit: /${m[1]} returned HTTP ${m[2]} (size ${m[3]}).`,
          data: { path: m[1], status: Number(m[2]), size: Number(m[3]) },
        });
    }
    return obs;
  },
};

export const gobusterParser: ToolParser = {
  name: 'gobuster',
  canParse: (ctx, output) => named(ctx, 'gobuster') || /^\/\S*\s+\(Status:\s*\d+\)/im.test(output),
  parse(output) {
    const obs: ParsedObservation[] = [];
    for (const line of lines(output)) {
      const m = line.match(/^(\/\S*)\s+\(Status:\s*(\d+)\)/i);
      if (m)
        obs.push({
          kind: 'observation',
          title: `${m[1]} -> ${m[2]}`,
          body: `gobuster hit: ${m[1]} returned HTTP ${m[2]}.`,
          data: { path: m[1], status: Number(m[2]) },
        });
    }
    return obs;
  },
};

export const feroxbusterParser: ToolParser = {
  name: 'feroxbuster',
  canParse: (ctx, output) =>
    named(ctx, 'feroxbuster') || /^\d{3}\s+\w+\s+\d+l\s+\d+w\s+\d+c\s+\S+/im.test(output),
  parse(output) {
    const obs: ParsedObservation[] = [];
    for (const line of lines(output)) {
      const m = line.match(/^(\d{3})\s+\w+\s+\d+l\s+\d+w\s+\d+c\s+(\S+)/i);
      if (m)
        obs.push({
          kind: 'observation',
          title: `${m[2]} -> ${m[1]}`,
          body: `feroxbuster hit: ${m[2]} returned HTTP ${m[1]}.`,
          data: { url: m[2], status: Number(m[1]) },
        });
    }
    return obs;
  },
};

export const httpxParser: ToolParser = {
  name: 'httpx',
  canParse: (ctx, output) => named(ctx, 'httpx') || /^https?:\/\/\S+\s+\[\d{3}\]/im.test(output),
  parse(output) {
    const obs: ParsedObservation[] = [];
    for (const line of lines(output)) {
      const m = line.match(
        /^(https?:\/\/\S+)\s+\[(\d{3})\]\s*(?:\[([^\]]*)\])?\s*(?:\[([^\]]*)\])?/i,
      );
      if (m)
        obs.push({
          kind: 'observation',
          title: `${m[1]} [${m[2]}]`,
          body: `httpx: ${m[1]} responded ${m[2]}${m[3] ? `, title "${m[3]}"` : ''}${m[4] ? `, tech ${m[4]}` : ''}.`,
          data: { url: m[1], status: Number(m[2]), title: m[3], tech: m[4] },
        });
    }
    return obs;
  },
};

export const nucleiParser: ToolParser = {
  name: 'nuclei',
  canParse: (ctx, output) =>
    named(ctx, 'nuclei') ||
    /^\[[^\]]+\]\s+\[[^\]]+\]\s+\[(info|low|medium|high|critical)\]/im.test(output),
  parse(output) {
    const obs: ParsedObservation[] = [];
    for (const line of lines(output)) {
      const m = line.match(
        /^\[([^\]]+)\]\s+\[[^\]]+\]\s+\[(info|low|medium|high|critical)\]\s+(\S+)/i,
      );
      if (!m) continue;
      const severity = m[2].toLowerCase();
      obs.push({
        kind: severity === 'info' ? 'observation' : 'finding',
        title: `${m[1]} [${severity}] on ${m[3]}`,
        body: `nuclei template ${m[1]} (${severity}) matched ${m[3]}. This is a scanner signal, not a confirmed finding.`,
        data: { template: m[1], severity, url: m[3] },
      });
    }
    return obs;
  },
};

export const curlParser: ToolParser = {
  name: 'curl',
  canParse: (ctx, output) => named(ctx, 'curl') || /^HTTP\/[\d.]+\s+\d{3}/im.test(output),
  parse(output) {
    const obs: ParsedObservation[] = [];
    const status = output.match(/^HTTP\/[\d.]+\s+(\d{3})([^\r\n]*)/im);
    if (status)
      obs.push({
        kind: 'observation',
        title: `HTTP ${status[1]}`,
        body: `Response status ${status[1]}${status[2] ? ` (${status[2].trim()})` : ''}.`,
        data: { status: Number(status[1]) },
      });
    for (const header of ['Server', 'X-Powered-By', 'Location', 'WWW-Authenticate']) {
      const h = output.match(new RegExp(`^${header}:\\s*(.+)$`, 'im'));
      if (h)
        obs.push({
          kind: 'observation',
          title: `${header}: ${h[1].trim()}`,
          body: `Response header ${header} is ${h[1].trim()}.`,
          data: { header, value: h[1].trim() },
        });
    }
    return obs;
  },
};

export const sqlmapParser: ToolParser = {
  name: 'sqlmap',
  canParse: (ctx, output) =>
    named(ctx, 'sqlmap') || /injection point|is vulnerable|sqlmap identified/i.test(output),
  parse(output) {
    const obs: ParsedObservation[] = [];
    const params = [...output.matchAll(/^Parameter:\s*(\S+)/gim)].map((m) => m[1]);
    for (const p of params)
      obs.push({
        kind: 'finding',
        title: `Possible SQL injection in parameter ${p}`,
        body: `sqlmap reported injection potential in parameter ${p}. Confirm against the target before treating it as a finding.`,
        data: { parameter: p },
      });
    if (!params.length && /injection point|is vulnerable|sqlmap identified/i.test(output))
      obs.push({
        kind: 'finding',
        title: 'sqlmap reported a possible injection point',
        body: 'sqlmap reported a potential injection point. Confirm against the target.',
        data: {},
      });
    return obs;
  },
};

export const parsers: ToolParser[] = [
  nmapParser,
  rustscanParser,
  ffufParser,
  gobusterParser,
  feroxbusterParser,
  httpxParser,
  nucleiParser,
  curlParser,
  sqlmapParser,
];

export function parseToolOutput(output: string, ctx: ToolContext = {}): ParsedToolResult | null {
  const byName = ctx.tool
    ? parsers.find((p) => (ctx.tool || '').toLowerCase().includes(p.name))
    : undefined;
  const chosen =
    byName && byName.canParse(ctx, output) ? byName : parsers.find((p) => p.canParse(ctx, output));
  if (!chosen) return null;
  const observations = chosen.parse(output, ctx).slice(0, 100);
  if (!observations.length) return null;
  return {
    tool: chosen.name,
    observations,
    summary: `${chosen.name}: ${observations.length} observation(s) extracted.`,
  };
}
