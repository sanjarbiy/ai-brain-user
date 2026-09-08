import { randomUUID } from 'node:crypto';
import { type Command, type Snapshot } from '../../shared/src/protocol.ts';
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
export function serverUrl(raw: string) {
  const url = new URL(raw);
  if (url.username || url.password || url.pathname !== '/' || url.search || url.hash)
    throw new Error('Use a server origin without a path or credentials');
  if (
    url.protocol !== 'https:' &&
    !(url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname))
  )
    throw new Error('HTTPS is required for remote servers');
  return url.origin;
}
export class BrainApi {
  readonly origin: string;
  constructor(
    origin: string,
    public token: string,
    public ctfId: string = '',
    // Stable per-computer device id. Sent as X-Device-Id so a personal API key locks to THIS machine
    // (trust-on-first-use); the server rejects the same token from any other device.
    public deviceId: string = '',
  ) {
    this.origin = serverUrl(origin);
  }
  async request<T = any>(
    path: string,
    method = 'GET',
    body?: unknown,
    timeoutMs = 15000,
  ): Promise<T> {
    const response = await fetch(`${this.origin}${path}`, {
      method,
      headers: {
        ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),
        ...(this.deviceId ? { 'X-Device-Id': this.deviceId } : {}),
        'Content-Type': 'application/json',
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      signal: AbortSignal.timeout(timeoutMs),
      redirect: 'error',
    });
    const raw = await response.text();
    let result: any;
    try {
      result = JSON.parse(raw);
    } catch {
      throw new ApiError(response.status, 'Unexpected server response');
    }
    if (!response.ok) throw new ApiError(response.status, result.error || 'Request failed');
    return result as T;
  }
  path(suffix: string) {
    if (!this.ctfId) throw new Error('Select a workspace with join first');
    return `/v1/ctfs/${this.ctfId}/${suffix}`;
  }
  context() {
    return this.request<Snapshot>(this.path('context'));
  }
  command(command: Command, idempotencyKey: string = randomUUID()) {
    return this.request(this.path('commands'), 'POST', { idempotencyKey, command });
  }
  sync(after = '0') {
    return this.request<{ events: any[]; cursor: string; hasMore: boolean }>(
      this.path(`events?after=${after}`),
    );
  }
}
