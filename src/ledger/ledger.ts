import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

// PLAN.md §6.8: append-only JSONL receipts. Each record carries the SHA-256 of the previous record,
// so edits, deletions and reordering are detectable (tamper-evident, not tamper-proof).
// A record is fsync'ed before the action it describes runs (write-ahead).

export type RecordType = 'planned' | 'done' | 'failed' | 'restored' | 'purged';

export interface LedgerRecord {
  seq: number;
  ts: string;
  tx: string;
  type: RecordType;
  data: unknown;
  prev: string;
  hash: string;
}

const GENESIS = '0'.repeat(64);

/** Deterministic JSON: object keys sorted recursively (RFC 8785-style for the values we write). */
export function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj).filter((k) => obj[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`).join(',')}}`;
}

const hashOf = (r: Omit<LedgerRecord, 'hash'>) => createHash('sha256').update(canonical(r)).digest('hex');

export type VerifyResult = { ok: true; count: number; head: string } | { ok: false; brokenAt: number; reason: string };

export class Ledger {
  readonly file: string;
  private readonly lockFile: string;
  private lockFd: number | undefined;

  constructor(readonly dir: string) {
    fs.mkdirSync(dir, { recursive: true });
    this.file = path.join(dir, 'ledger.jsonl');
    this.lockFile = path.join(dir, 'ledger.lock');
  }

  /** One writer at a time across processes (agent + human). Stale locks from dead processes are reclaimed. */
  lock(): void {
    try {
      this.lockFd = fs.openSync(this.lockFile, 'wx');
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
      const pid = Number(fs.readFileSync(this.lockFile, 'utf8'));
      if (pid && pidAlive(pid)) throw new Error(`ledger is locked by running process ${pid}`);
      fs.rmSync(this.lockFile, { force: true });
      this.lockFd = fs.openSync(this.lockFile, 'wx');
    }
    fs.writeSync(this.lockFd, String(process.pid));
    fs.fsyncSync(this.lockFd);
  }

  unlock(): void {
    if (this.lockFd === undefined) return;
    fs.closeSync(this.lockFd);
    this.lockFd = undefined;
    fs.rmSync(this.lockFile, { force: true });
  }

  records(): LedgerRecord[] {
    if (!fs.existsSync(this.file)) return [];
    return fs.readFileSync(this.file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l) as LedgerRecord);
  }

  verify(): VerifyResult {
    let prev = GENESIS;
    let records: LedgerRecord[];
    try { records = this.records(); } catch { return { ok: false, brokenAt: -1, reason: 'unparseable ledger' }; }
    for (const [i, r] of records.entries()) {
      if (r.seq !== i + 1) return { ok: false, brokenAt: i + 1, reason: `expected seq ${i + 1}, found ${r.seq}` };
      if (r.prev !== prev) return { ok: false, brokenAt: r.seq, reason: 'prev hash does not match previous record' };
      const { hash, ...rest } = r;
      if (hashOf(rest) !== hash) return { ok: false, brokenAt: r.seq, reason: 'record content does not match its hash' };
      prev = hash;
    }
    return { ok: true, count: records.length, head: prev };
  }

  /** Append and fsync. Throws on any write failure; callers must not run the action if this throws. */
  append(tx: string, type: RecordType, data: unknown): LedgerRecord {
    if (this.lockFd === undefined) throw new Error('ledger.append requires lock()');
    const v = this.verify();
    if (!v.ok) throw new Error(`ledger chain broken at ${v.brokenAt}: ${v.reason}`);
    const body = { seq: v.count + 1, ts: new Date().toISOString(), tx, type, data, prev: v.head };
    const record: LedgerRecord = { ...body, hash: hashOf(body) };
    // ponytail: re-verifies the whole file on every append (O(n)); cache the head if ledgers grow large.
    const fd = fs.openSync(this.file, 'a');
    try {
      fs.writeSync(fd, JSON.stringify(record) + '\n');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    return record;
  }
}

function pidAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (e) { return (e as NodeJS.ErrnoException).code === 'EPERM'; }
}
