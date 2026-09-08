// Compact target knowledge rollup (specification section 25). Answers "what do we know about this
// target" with a small structured summary instead of dumping every record. Pure function over a
// snapshot; used by the MCP target-summary tool and the dashboard so the same rollup renders
// everywhere. It returns references and counts, not raw evidence bodies.

import type { Snapshot } from './protocol.ts';

export type TargetRollup = {
  target: string | null;
  status: string;
  participants: string[];
  known: string[];
  failedAttempts: string[];
  findings: number;
  currentStuck: string[];
  activeScans: number;
  artifacts: number;
};

export function targetRollup(snapshot: Snapshot, targetId: string): TargetRollup {
  const nameOf = (id: string | null | undefined) =>
    snapshot.participants.find((p) => p.id === id)?.name ?? 'Unknown';
  const target = snapshot.targets.find((t) => t.id === targetId);
  const tasks = snapshot.tasks.filter((t) => t.target_id === targetId);
  const entries = snapshot.entries.filter((e) => e.target_id === targetId);
  const stuck = snapshot.stuck.filter((s) => s.target_id === targetId && s.status === 'OPEN');
  const scans = snapshot.scans.filter(
    (s) => s.target_id === targetId && (s.status === 'STARTED' || s.status === 'ACTIVE'),
  );
  return {
    target: target?.label ?? null,
    status: target?.status ?? 'UNTOUCHED',
    participants: [
      ...new Set(
        tasks
          .filter((t) => t.owner_id && t.status !== 'DONE')
          .map((t) => `${nameOf(t.owner_id)} — ${t.title}`),
      ),
    ],
    known: entries
      .filter((e) => e.kind === 'observation')
      .slice(0, 10)
      .map((e) => e.title),
    failedAttempts: entries.filter((e) => e.kind === 'attempt').map((e) => e.title),
    findings: entries.filter((e) => e.kind === 'finding').length,
    currentStuck: stuck.map((s) => s.description),
    activeScans: scans.length,
    artifacts: entries.filter((e) => e.artifact_id).length,
  };
}
