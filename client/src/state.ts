import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { mkdirSync, chmodSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { type Command } from '../../shared/src/protocol.ts';

// node:sqlite is a Node >=22.5 built-in. Load it LAZILY (via a sync require, only when local state is
// actually constructed) so importing this module — and therefore the whole CLI / MCP server — does NOT
// crash at import time on older Node. Callers that need local state (the offline queue + relay
// presence) get a clear, catchable error; an MCP session then degrades to online-only instead of the
// whole process dying with an opaque "failed to connect".
type Sqlite = typeof import('node:sqlite');
let sqliteModule: Sqlite | undefined;
function requireSqlite(): Sqlite {
  if (sqliteModule) return sqliteModule;
  try {
    sqliteModule = createRequire(import.meta.url)('node:sqlite') as Sqlite;
  } catch {
    throw new Error(
      'Local encrypted state needs Node 22.5+ (its built-in node:sqlite). The MCP session still works ' +
        'without it (offline queue + presence disabled); upgrade Node to enable them.',
    );
  }
  return sqliteModule;
}
type PreparedStatement = ReturnType<InstanceType<Sqlite['DatabaseSync']>['prepare']>;

export interface SecretStore {
  get(key: string): unknown;
  set(key: string, value: unknown): void;
  delete(key: string): void;
}
export class LocalState implements SecretStore {
  db: InstanceType<Sqlite['DatabaseSync']>;
  key: Buffer;
  private statements = new Map<string, PreparedStatement>();
  constructor(path: string, masterKey: string) {
    if (!/^[a-fA-F0-9]{64}$/.test(masterKey))
      throw new Error(
        'BRAIN_VAULT_KEY must be a 64-character hexadecimal key. Keep it in your password manager or environment, separate from the state file.',
      );
    const { DatabaseSync } = requireSqlite();
    this.key = Buffer.from(masterKey, 'hex');
    if (path !== ':memory:') {
      mkdirSync(dirname(resolve(path)), { recursive: true, mode: 0o700 });
    }
    this.db = new DatabaseSync(path);
    this.db.exec(
      "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS secrets(key TEXT PRIMARY KEY,value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS outbox(id TEXT PRIMARY KEY,scope TEXT NOT NULL,value TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'PENDING',error TEXT,created_at TEXT NOT NULL);",
    );
    if (path !== ':memory:' && process.platform !== 'win32') chmodSync(path, 0o600);
  }
  seal(value: unknown) {
    const iv = randomBytes(12),
      cipher = createCipheriv('aes-256-gcm', this.key, iv);
    const body = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), body]).toString('base64');
  }
  open(value: string) {
    try {
      const data = Buffer.from(value, 'base64'),
        cipher = createDecipheriv('aes-256-gcm', this.key, data.subarray(0, 12));
      cipher.setAuthTag(data.subarray(12, 28));
      return JSON.parse(
        Buffer.concat([cipher.update(data.subarray(28)), cipher.final()]).toString('utf8'),
      );
    } catch {
      throw new Error(
        'Cannot decrypt local state. Check BRAIN_VAULT_KEY; existing state has not been changed.',
      );
    }
  }
  // node:sqlite compiles SQL on every prepare() call and does not cache. Every statement here has
  // constant SQL and is re-run with fresh bound params, so compile each once per connection and reuse
  // it. Results are identical; only the per-call compile is avoided (matters in the relay flush loop
  // and the per-sync set() calls). Statements share this.db's lifetime and are discarded with it.
  private stmt(sql: string): PreparedStatement {
    let cached = this.statements.get(sql);
    if (!cached) {
      cached = this.db.prepare(sql);
      this.statements.set(sql, cached);
    }
    return cached;
  }
  get(key: string): any {
    const row = this.stmt('SELECT value FROM secrets WHERE key=?').get(key);
    return row ? this.open(String(row.value)) : undefined;
  }
  set(key: string, value: unknown) {
    this.stmt(
      'INSERT INTO secrets(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
    ).run(key, this.seal(value));
  }
  delete(key: string) {
    this.stmt('DELETE FROM secrets WHERE key=?').run(key);
  }
  enqueue(scope: string, id: string, command: Command) {
    if (command.type !== 'entry.add')
      throw new Error(
        'Only submitted notes/evidence may be queued offline; task decisions require a live server',
      );
    this.stmt('INSERT INTO outbox(id,scope,value,created_at) VALUES(?,?,?,?)').run(
      id,
      scope,
      this.seal(command),
      new Date().toISOString(),
    );
  }
  pending(scope: string) {
    return this.stmt(
      "SELECT * FROM outbox WHERE scope=? AND status='PENDING' ORDER BY created_at LIMIT 200",
    )
      .all(scope)
      .map((r) => ({ id: String(r.id), command: this.open(String(r.value)) as Command }));
  }
  sent(id: string) {
    this.stmt('DELETE FROM outbox WHERE id=?').run(id);
  }
  failed(id: string, error: string) {
    this.stmt("UPDATE outbox SET status='NEEDS_REVIEW',error=? WHERE id=?").run(
      this.seal(error),
      id,
    );
  }
  failures(scope: string) {
    return this.stmt("SELECT id,error FROM outbox WHERE scope=? AND status='NEEDS_REVIEW'")
      .all(scope)
      .map((r) => ({ id: r.id, error: this.open(String(r.error)) }));
  }
  close() {
    this.db.close();
    this.key.fill(0);
  }
}
