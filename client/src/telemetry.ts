// Human terminal telemetry, Method A (specification section 15). `ctf run` wraps a security tool
// the participant invokes on their OWN machine: it registers the activity for duplicate detection,
// runs the tool locally, stores the raw output as an artifact, records structured observations, and
// finishes the scan. It executes only the local command the user asked for; it is not a general
// command surveillance system and it is not a server-issued shell.

import { BrainApi, ApiError } from './api.ts';
import { parseToolOutput } from '../../shared/src/parsers.ts';

export type Execution = { code: number; stdout: string; stderr: string };
export type Runner = (tool: string, args: string[]) => Promise<Execution>;

export type ScanTelemetryResult = {
  decision: string;
  scanId?: string;
  aborted?: boolean;
  observations: number;
  exitCode?: number;
};

export async function runScan(
  api: BrainApi,
  input: { targetId: string; tool: string; args: string[]; force?: boolean; reason?: string },
  runner: Runner,
  notify: (message: string) => void = console.error,
): Promise<ScanTelemetryResult> {
  const command = [input.tool, ...input.args].join(' ');
  let start;
  try {
    start = await api.command({
      type: 'scan.start',
      targetId: input.targetId,
      tool: input.tool,
      command,
      ...(input.force ? { force: true } : {}),
      ...(input.reason ? { reason: input.reason } : {}),
    });
  } catch (e) {
    if (e instanceof ApiError && e.status === 409) {
      notify(`Duplicate work: ${e.message}`);
      notify('Re-run with --force and a --reason only if independent validation is required.');
      return { decision: 'BLOCK_DUPLICATE', aborted: true, observations: 0 };
    }
    throw e;
  }
  const scanId: string = start.event.payload.id;
  const decision: string = start.event.payload.decision;
  if (decision === 'WARN' || decision === 'ALLOW_WITH_WARNING')
    notify(`Overlap detected (${decision}). Consider reusing existing team results.`);

  const heartbeat = setInterval(() => {
    void api.command({ type: 'scan.heartbeat', scanId }).catch(() => {});
  }, 30000);
  heartbeat.unref?.();

  let execution: Execution;
  try {
    execution = await runner(input.tool, input.args);
  } catch (e) {
    clearInterval(heartbeat);
    await api.command({ type: 'scan.finish', scanId, status: 'FAILED' }).catch(() => {});
    throw e;
  }
  clearInterval(heartbeat);

  // Store the raw output as an artifact (best effort; the server redacts common secrets).
  const raw = `${execution.stdout}\n${execution.stderr}`.trim();
  let artifactId: string | undefined;
  if (raw) {
    try {
      const artifact = await api.request<{ id: string }>(api.path('artifacts'), 'POST', {
        name: `${input.tool}-output.txt`,
        mime: 'text/plain',
        base64: Buffer.from(raw.slice(0, 2 * 1024 * 1024)).toString('base64'),
      });
      artifactId = artifact.id;
    } catch {
      // Continue without the artifact; structured observations still flow.
    }
  }

  const parsed = parseToolOutput(execution.stdout, { tool: input.tool, command });
  const observations = (parsed?.observations ?? []).slice(0, 50).map((o) => ({
    kind: o.kind,
    title: o.title.slice(0, 120),
    body: o.body.slice(0, 16000),
  }));
  const finish = await api.command({
    type: 'scan.finish',
    scanId,
    status: 'FINISHED',
    ...(artifactId ? { artifactId } : {}),
    ...(observations.length ? { observations } : {}),
  });
  const stored: number = finish.event.payload.observations ?? 0;
  notify(`Recorded ${stored} observation(s) from ${input.tool} (exit ${execution.code}).`);
  return { decision, scanId, observations: stored, exitCode: execution.code };
}
