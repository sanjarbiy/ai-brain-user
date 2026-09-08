import WebSocket from 'ws';
import { BrainApi, ApiError } from './api.ts';
import { LocalState } from './state.ts';

export function scopeKey(api: BrainApi, userId: string) {
  return `${api.origin}|${userId}|${api.ctfId}`;
}
export async function flushOutbox(api: BrainApi, state: LocalState, scope: string) {
  let sent = 0;
  for (const item of state.pending(scope)) {
    try {
      await api.command(item.command, item.id);
      state.sent(item.id);
      sent++;
    } catch (e) {
      if (e instanceof ApiError && [400, 403, 404, 409, 413].includes(e.status)) {
        state.failed(item.id, e.message);
        continue;
      }
      throw e;
    }
  }
  return { sent, needsReview: state.failures(scope) };
}
export function connectRelay(
  api: BrainApi,
  state: LocalState,
  userId: string,
  notify: (message: string) => void = console.error,
) {
  const scope = scopeKey(api, userId);
  let stopped = false,
    socket: WebSocket | undefined,
    retry: NodeJS.Timeout | undefined,
    heartbeat: NodeJS.Timeout | undefined,
    attempt = 0,
    processing = Promise.resolve();
  async function connect() {
    if (stopped) return;
    try {
      await flushOutbox(api, state, scope);
      const snapshot = await api.context();
      state.set(`context:${scope}`, snapshot);
      // Persist the snapshot before its cursor; an interrupted write can replay, never skip.
      state.set(`cursor:${scope}`, snapshot.cursor);
      const url = new URL('/v1/relay', api.origin);
      url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
      url.searchParams.set('ctfId', api.ctfId);
      url.searchParams.set('after', snapshot.cursor);
      socket = new WebSocket(url, {
        headers: { Authorization: `Bearer ${api.token}` },
        maxPayload: 1024 * 1024,
        handshakeTimeout: 10000,
      });
      socket.on('open', () => {
        attempt = 0;
        notify('Relay connected. Inbox synchronized.');
        socket?.send('{"type":"heartbeat"}');
        heartbeat = setInterval(
          () => socket?.readyState === 1 && socket.send('{"type":"heartbeat"}'),
          30000,
        );
      });
      socket.on('message', (data) => {
        processing = processing
          .then(async () => {
            const message = JSON.parse(String(data));
            if (message.type !== 'sync') return;
            await flushOutbox(api, state, scope);
            if (!message.events.length) return;
            const snapshot = await api.context();
            state.set(`context:${scope}`, snapshot);
            state.set(`cursor:${scope}`, snapshot.cursor);
            for (const event of message.events) {
              if (event.type === 'proposal.create' && event.payload.recipientId === userId)
                notify('New task proposal. Run: npm run agent -- inbox');
              if (event.type === 'command.issued' && event.payload.recipientId === userId)
                notify('New coordination command. Run: npm run agent -- commands');
            }
          })
          .catch(() => {
            socket?.close(1011, 'Synchronization failed');
          });
      });
      socket.on('error', () => {});
      socket.on('close', (code) => {
        clearInterval(heartbeat);
        if (code === 1008) {
          stopped = true;
          notify('Relay stopped: sign in again or check workspace membership.');
          return;
        }
        schedule();
      });
    } catch (e) {
      if (e instanceof ApiError && [401, 403, 404].includes(e.status)) {
        stopped = true;
        notify(e.message);
        return;
      }
      schedule();
    }
  }
  function schedule() {
    if (stopped) return;
    clearTimeout(retry);
    const delay =
      Math.min(60000, 1000 * 2 ** Math.min(attempt++, 6)) + Math.floor(Math.random() * 500);
    notify(`Connection unavailable; retry in ${Math.ceil(delay / 1000)}s.`);
    retry = setTimeout(() => void connect(), delay);
  }
  void connect();
  return {
    async stop() {
      stopped = true;
      clearTimeout(retry);
      clearInterval(heartbeat);
      socket?.close(1000);
      await processing;
    },
  };
}
