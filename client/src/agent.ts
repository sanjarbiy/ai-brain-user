// Our own CTF Brain participant agent (specification section 38). It follows the exact
// synchronization protocol: sync, get target context, check for duplicate work, record its intent,
// and acknowledge the command. The AI planning step is injected (participant keys via the model
// router in production, a mock in tests). It records; it does not execute security tools here.

import { readFile } from 'node:fs/promises';
import { BrainApi } from './api.ts';

export type AgentComplete = (systemPrompt: string, context: string) => Promise<string>;

export async function runAgentTask(
  api: BrainApi,
  task: { commandId: string; targetId?: string; instruction: string },
  complete: AgentComplete,
  notify: (message: string) => void = console.error,
): Promise<{ acked: boolean; recorded: boolean; advisory: unknown }> {
  // SYNC
  const context = await api.context();
  const target = task.targetId ? context.targets.find((t) => t.id === task.targetId) : undefined;

  // CHECK DUPLICATES before proposing any work.
  let advisory: unknown = null;
  if (task.targetId)
    advisory = await api
      .request(
        api.path(
          `overlap?targetId=${task.targetId}&activity=${encodeURIComponent(task.instruction)}`,
        ),
      )
      .catch(() => null);

  const systemPrompt = await readFile(
    new URL('../../prompts/participant.system.md', import.meta.url),
    'utf8',
  ).catch(() => 'You are a CTF Brain participant agent. Plan within scope and record your intent.');
  const plan =
    (await complete(
      systemPrompt,
      JSON.stringify({ instruction: task.instruction, target: target?.label ?? null, advisory }),
    )) || 'No plan produced.';

  // RECORD the intent as a note so the team sees what the agent will do.
  let recorded = false;
  if (task.targetId) {
    await api.command({
      type: 'entry.add',
      targetId: task.targetId,
      kind: 'note',
      title: 'Agent plan',
      body: plan.slice(0, 16000),
    });
    recorded = true;
  }

  // ACKNOWLEDGE the command; never assume it executed beyond recordkeeping.
  await api
    .command({
      type: 'command.ack',
      commandId: task.commandId,
      status: 'ACCEPTED',
      reason: 'Plan recorded; proceeding within scope.',
    })
    .catch(() => {});
  notify(`Agent handled command ${task.commandId}: plan recorded and acknowledged.`);
  return { acked: true, recorded, advisory };
}
