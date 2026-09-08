import type { BrainApi } from './api.ts';
import type { ExecOutcome } from './sandbox.ts';

// The agentic loop, run locally by the MCP: start a documented run on the server, then repeatedly ask
// the backend brain for the next command (on the participant's own keys), execute it on the operator's
// LOCAL machine, and report the real output back — which both advances the brain and documents the
// step server-side for the whole team. Returns the full transcript plus the flag and writeup, so the
// orchestrating agent (Claude Code) sees exactly what happened, how, and with which tools.

export type Exec = (command: string) => Promise<ExecOutcome>;
export type LoopStep = { thought?: string; command: string; output: string; exitCode: number; blocked?: boolean };
export type LoopResult = {
  runId: string;
  done: boolean;
  status: string;
  flag?: string;
  summary?: string;
  steps: LoopStep[];
};

type NextResponse =
  | { action: 'shell'; command: string; thought?: string; step: number }
  | { action: 'done'; status: string; flag?: string; summary?: string };

type Api = Pick<BrainApi, 'request' | 'path'>;

export async function runAgentLoop(
  api: Api,
  exec: Exec,
  input: { objective: string; targetId?: string; category?: string },
  opts: { maxSteps?: number; stepTimeoutMs?: number; runId?: string } = {},
): Promise<LoopResult> {
  // Per-call budget kept modest so a single MCP tool call returns before a host tool-timeout; a solve
  // that needs more comes back PAUSED with a runId and is continued with ctf_agent_resume.
  const maxSteps = Math.min(Math.max(opts.maxSteps ?? 15, 1), 60);
  const stepTimeoutMs = opts.stepTimeoutMs ?? 120000;
  const runId =
    opts.runId ??
    (
      await api.request<{ runId: string }>(api.path('agent/runs'), 'POST', {
        objective: input.objective,
        ...(input.targetId ? { targetId: input.targetId } : {}),
        ...(input.category ? { category: input.category } : {}),
      })
    ).runId;
  const steps: LoopStep[] = [];
  let last: Record<string, unknown> = {};
  let done = false;
  let paused = false;
  // finally abandons the run ONLY on an UNEXPECTED exit (a thrown /next or exec error), so a client
  // that dies mid-loop never leaves a zombie RUNNING row. A clean done or a deliberate PAUSE leaves the
  // run active: a pause is resumable with the same runId, and the server reaper clears an unresumed one.
  try {
    for (let i = 0; i < maxSteps; i++) {
      const step = await api.request<NextResponse>(
        api.path(`agent/runs/${runId}/next`),
        'POST',
        last,
        stepTimeoutMs,
      );
      if (step.action === 'done') {
        done = true;
        return { runId, done: true, status: step.status, flag: step.flag, summary: step.summary, steps };
      }
      const result = await exec(step.command);
      const row: LoopStep = {
        thought: step.thought,
        command: step.command,
        output: result.output,
        exitCode: result.code,
        ...(result.blocked ? { blocked: true } : {}),
      };
      steps.push(row);
      last = { thought: step.thought, command: step.command, output: result.output, exitCode: result.code };
    }
    // Flush the final executed step to the server BEFORE pausing: a step is reported only on the next
    // iteration's /next, so the boundary command would otherwise never be persisted — the transcript
    // would miss it and a resume, re-deciding from stale history, could RE-RUN it on the live target.
    if (last.command) {
      const tail = await api.request<NextResponse>(
        api.path(`agent/runs/${runId}/next`),
        'POST',
        last,
        stepTimeoutMs,
      );
      if (tail.action === 'done') {
        done = true;
        return { runId, done: true, status: tail.status, flag: tail.flag, summary: tail.summary, steps };
      }
      // tail is the next command; discard it — it is re-fetched on resume against the now-complete
      // history, so nothing is executed here and there is no double-exec.
    }
    paused = true;
    return {
      runId,
      done: false,
      status: 'PAUSED',
      summary: `Reached this call's ${maxSteps}-step budget without finishing (the run is still active). Resume it with ctf_agent_resume (runId ${runId}) within ~15 minutes of inactivity, or it is auto-abandoned.`,
      steps,
    };
  } finally {
    if (!done && !paused)
      await api.request(api.path(`agent/runs/${runId}/abandon`), 'POST', {}).catch(() => {});
  }
}
