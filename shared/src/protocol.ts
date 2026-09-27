import { z } from 'zod';

export const Id = z.string().uuid();
export const Label = z.string().trim().min(1).max(120);
export const Body = z.string().trim().min(1).max(16000);
export const Provenance = z.enum([
  'USER_REPORTED',
  'OBSERVED',
  'AI_INFERRED',
  // Reserved for human-recorded external research with an explicit cited source.
  // Autonomous web research is out of scope for this edition by contract.
  'RESEARCHED',
  'CONFIRMED',
  'DISPUTED',
]);
export const EntryKind = z.enum(['observation', 'finding', 'attempt', 'note', 'stuck', 'summary']);
export const ActivityFamilyEnum = z.enum([
  'PORT_DISCOVERY',
  'SERVICE_DETECTION',
  'CONTENT_DISCOVERY',
  'VULN_SCAN',
  'HTTP_PROBE',
  'SUBDOMAIN_ENUM',
  'SQL_INJECTION_TEST',
  'UNKNOWN',
]);
const target = { targetId: Id };
const task = { taskId: Id };
export const Command = z.discriminatedUnion('type', [
  z
    .object({
      type: z.literal('target.create'),
      label: Label,
      description: Body,
      category: z.enum(['web', 'reverse', 'crypto', 'forensics', 'misc']).default('misc'),
    })
    .strict(),
  z
    .object({
      type: z.literal('task.create'),
      ...target,
      title: Label,
      description: Body.optional(),
    })
    .strict(),
  z.object({ type: z.literal('task.claim'), ...task }).strict(),
  z.object({ type: z.literal('task.release'), ...task }).strict(),
  z.object({ type: z.literal('task.complete'), ...task }).strict(),
  z.object({ type: z.literal('task.block'), ...task, reason: Body }).strict(),
  z
    .object({
      type: z.literal('entry.add'),
      targetId: Id.optional(),
      taskId: Id.optional(),
      kind: EntryKind.exclude(['summary']),
      title: Label,
      body: Body,
      artifactId: Id.optional(),
    })
    .strict(),
  z
    .object({
      type: z.literal('entry.verify'),
      entryId: Id,
      state: z.enum(['CONFIRMED', 'DISPUTED']),
      reason: Body,
    })
    .strict(),
  z
    .object({
      type: z.literal('proposal.create'),
      ...task,
      recipientId: Id,
      reason: Body,
      durationMinutes: z.number().int().min(5).max(240).default(45),
    })
    .strict(),
  z
    .object({
      type: z.literal('proposal.respond'),
      proposalId: Id,
      decision: z.enum(['ACCEPTED', 'REJECTED', 'BUSY']),
      reason: z.string().max(2000).optional(),
    })
    .strict(),
  z.object({ type: z.literal('acceptance.revoke'), acceptanceId: Id }).strict(),
  z.object({ type: z.literal('summary.request'), ...target }).strict(),
  z
    .object({
      type: z.literal('scan.start'),
      targetId: Id,
      tool: Label.optional(),
      command: z.string().trim().min(1).max(2000).optional(),
      activityFamily: ActivityFamilyEnum.optional(),
      ports: z.string().trim().max(64).optional(),
      pathScope: z.string().trim().max(256).optional(),
      wordlist: z.string().trim().max(256).optional(),
      force: z.boolean().optional(),
      reason: z.string().max(2000).optional(),
    })
    .strict(),
  z.object({ type: z.literal('scan.heartbeat'), scanId: Id }).strict(),
  z
    .object({
      type: z.literal('scan.finish'),
      scanId: Id,
      status: z.enum(['FINISHED', 'FAILED']).optional(),
      summary: z.string().trim().max(2000).optional(),
      artifactId: Id.optional(),
      observations: z
        .array(
          z.object({ kind: z.enum(['observation', 'finding']), title: Label, body: Body }).strict(),
        )
        .max(50)
        .optional(),
    })
    .strict(),
  z
    .object({
      type: z.literal('command.ack'),
      commandId: Id,
      status: z.enum([
        'ACCEPTED',
        'REJECTED',
        'BUSY',
        'OUT_OF_SCOPE',
        'USER_APPROVAL_REQUIRED',
        'AGENT_UNAVAILABLE',
        'COMPLETED',
      ]),
      reason: z.string().max(2000).optional(),
    })
    .strict(),
  z
    .object({
      type: z.literal('target.setState'),
      targetId: Id,
      status: z.enum([
        'UNTOUCHED',
        'CLAIMED',
        'ACTIVE',
        'STUCK',
        'PARTIALLY_SOLVED',
        'PWNED',
        'DONE',
        'ABANDONED',
      ]),
    })
    .strict(),
  z
    .object({
      type: z.literal('stuck.raise'),
      targetId: Id.optional(),
      taskId: Id.optional(),
      description: Body,
      attemptedMethods: z.string().trim().max(4000).optional(),
      priority: z.enum(['CRITICAL', 'HIGH', 'NORMAL', 'LOW']).optional(),
    })
    .strict(),
  z.object({ type: z.literal('stuck.resolve'), stuckId: Id, resolution: Body }).strict(),
  z.object({ type: z.literal('notification.read'), notificationId: Id }).strict(),
  z.object({ type: z.literal('target.addAlias'), targetId: Id, alias: Label }).strict(),
  z
    .object({ type: z.literal('workspace.setScope'), scope: z.array(Label).min(1).max(200) })
    .strict(),
]);
export type Command = z.infer<typeof Command>;
export const Envelope = z.object({ idempotencyKey: Id, command: Command }).strict();
export const WorkspaceInput = z
  .object({ name: Label, description: Body, scope: z.array(Label).min(1).max(200) })
  .strict();
export type Actor = {
  id: string;
  team_id: string;
  name: string;
  role: 'admin' | 'member';
  // An API-key actor has no device or session (device_id null, session_id ''), so both are nullable.
  device_id: string | null;
  session_id: string;
  // The workspace an API key is bound to (least privilege); unset for session actors.
  apiKeyCtfId?: string;
};
export type Event = {
  id: string;
  seq: string;
  ctf_id: string;
  actor_id: string;
  type: string;
  payload: Record<string, unknown>;
  created_at: string;
};
export type Row = Record<string, any>;
export type Snapshot = {
  workspace: Row;
  targets: Row[];
  tasks: Row[];
  entries: Row[];
  proposals: Row[];
  acceptances: Row[];
  participants: Row[];
  scans: Row[];
  runs: Row[];
  commands: Row[];
  stuck: Row[];
  notifications: Row[];
  events: Event[];
  cursor: string;
};

// Defense in depth, not a guarantee that arbitrary pasted content is secret-free. Patterns are
// hoisted to module constants because redact() runs on every stored note/command; String#replace
// resets a global regex's lastIndex on each call, so sharing one instance is equivalent to the
// previous per-call literals. The replacement order below is unchanged.
const REDACT_PRIVATE_KEY =
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;
const REDACT_KEY = /\b(?:sk-or-v1-|sk-|jina_)[A-Za-z0-9_-]{12,}\b/g;
const REDACT_AUTH_HEADER =
  /((?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*)[^\r\n]+/gi;
const REDACT_SECRET_ASSIGN =
  /((?:password|passwd|api[_-]?key|secret|access[_-]?token|refresh[_-]?token)\s*[=:]\s*)[^\s,;]+/gi;
export function redact(text: string): string {
  return text
    .replace(REDACT_PRIVATE_KEY, '[REDACTED PRIVATE KEY]')
    .replace(REDACT_KEY, '[REDACTED KEY]')
    .replace(REDACT_AUTH_HEADER, '$1[REDACTED]')
    .replace(REDACT_SECRET_ASSIGN, '$1[REDACTED]');
}
const WORD_RE = /[\p{L}\p{N}]{3,}/gu;
export function overlap(a: string, b: string): number {
  const words = (s: string) => new Set(s.toLowerCase().normalize('NFKC').match(WORD_RE) || []);
  const aa = words(a),
    bb = words(b),
    union = new Set([...aa, ...bb]);
  return union.size ? [...aa].filter((w) => bb.has(w)).length / union.size : 0;
}
export const VERSION = '0.1.0';
