// Participant AI adapters (specification section 6). AI Brain is not coupled to one AI vendor.
// Each client (Claude, Codex, Agy, a generic MCP client, or our own agent) is wrapped by an adapter
// implementing one interface. External clients that cannot accept a background task are NOT faked:
// their adapter queues the task, notifies the user, and lets the task surface through the MCP inbox
// when the session is next active. Only our own agent accepts and runs a task directly.

export type AgentHealth = { available: boolean; detail: string };
export type AgentTask = {
  commandId: string;
  instruction: string;
  reason: string;
  targetId?: string;
  taskId?: string;
};
export type TaskAcceptance = {
  status: 'ACCEPTED' | 'QUEUED' | 'REJECTED' | 'AGENT_UNAVAILABLE';
  detail?: string;
};
export type AgentStatus = { busy: boolean };

export interface ParticipantAgentAdapter {
  name: string;
  detect(): Promise<boolean>;
  healthCheck(): Promise<AgentHealth>;
  sendTask(task: AgentTask): Promise<TaskAcceptance>;
  getStatus(): Promise<AgentStatus>;
}

// External AI clients (Claude, Codex, Agy, generic MCP): honest fallback, never faked delivery.
export class QueueingAdapter implements ParticipantAgentAdapter {
  constructor(
    public name: string,
    private deps: {
      enqueue: (task: AgentTask) => Promise<void>;
      notify: (message: string) => void;
      available?: () => boolean;
    },
  ) {}
  async detect(): Promise<boolean> {
    return this.deps.available ? this.deps.available() : true;
  }
  async healthCheck(): Promise<AgentHealth> {
    const available = await this.detect();
    return {
      available,
      detail: available
        ? `${this.name}: reachable via MCP inbox; background injection is not claimed`
        : `${this.name}: not configured`,
    };
  }
  async sendTask(task: AgentTask): Promise<TaskAcceptance> {
    if (!(await this.detect())) return { status: 'AGENT_UNAVAILABLE' };
    await this.deps.enqueue(task);
    this.deps.notify(
      `New task queued for ${this.name}. It will surface in the MCP inbox on the next active session.`,
    );
    return { status: 'QUEUED', detail: 'Queued for the next active session.' };
  }
  async getStatus(): Promise<AgentStatus> {
    return { busy: false };
  }
}

// Our own AI Brain agent can accept and run a structured task directly through the relay.
export class AiBrainAdapter implements ParticipantAgentAdapter {
  constructor(
    public name: string,
    private deps: { run: (task: AgentTask) => Promise<void>; available?: () => boolean },
  ) {}
  async detect(): Promise<boolean> {
    return this.deps.available ? this.deps.available() : true;
  }
  async healthCheck(): Promise<AgentHealth> {
    return { available: await this.detect(), detail: `${this.name}: built-in agent` };
  }
  async sendTask(task: AgentTask): Promise<TaskAcceptance> {
    if (!(await this.detect())) return { status: 'AGENT_UNAVAILABLE' };
    await this.deps.run(task);
    return { status: 'ACCEPTED' };
  }
  async getStatus(): Promise<AgentStatus> {
    return { busy: false };
  }
}
