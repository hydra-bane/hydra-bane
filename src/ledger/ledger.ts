import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

// PLAN.md §6.8: append-only JSONL receipts. Each record carries the SHA-256 of the previous record,
// so edits, deletions and reordering are detectable (tamper-evident, not tamper-proof).
// A record is fsync'ed before the action it describes runs (write-ahead).
// Torn tail: every record goes out as one `JSON + "\n"` write, so a last line without its newline can only come from
// an interrupted append, and its action never ran (write-ahead). Readers ignore it; the next writer moves it to
// `ledger.jsonl.torn` (kept as evidence) before appending. A complete line that does not chain is still a break.

/**
 * Test-only crash injection (PLAN.md §6.11). Inert unless HYDRA_BANE_TEST_KILL_AT is `<point>` or `<point>:<n>`
 * (exit 137 on the n-th hit, default 1). Points: after-planned, quarantine-after-intent, quarantine-after-rename,
 * after-move-before-done, after-delete-before-done, mid-ledger-append, undo-after-restore-item.
 */
const killHits = new Map<string, number>();
export function killPoint(name: string, beforeExit?: () => void): void {
  const spec = process.env.HYDRA_BANE_TEST_KILL_AT;
  if (!spec) return;
  const [point, nth = '1'] = spec.split(':');
  if (point !== name) return;
  const n = (killHits.get(name) ?? 0) + 1;
  killHits.set(name, n);
  if (n !== Number(nth)) return;
  beforeExit?.();
  process.exit(137);
}

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
  readonly dir: string;
  readonly file: string;
  private readonly lockFile: string;
  private lockFd: number | undefined;

  constructor(dir: string) {
    this.dir = dir;
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

  /** Committed records only: a torn (unterminated) last line is ignored. */
  records(): LedgerRecord[] {
    if (!fs.existsSync(this.file)) return [];
    const text = fs.readFileSync(this.file, 'utf8');
    return text.slice(0, text.lastIndexOf('\n') + 1).split('\n').filter(Boolean).map((l) => JSON.parse(l) as LedgerRecord);
  }

  /** Moves a torn last line into `ledger.jsonl.torn` and truncates it off. Returns the torn text, if any. Needs lock(). */
  repairTornTail(): string | undefined {
    if (this.lockFd === undefined) throw new Error('ledger.repairTornTail requires lock()');
    if (!fs.existsSync(this.file)) return undefined;
    const buf = fs.readFileSync(this.file);
    const keep = buf.lastIndexOf(0x0a) + 1;
    if (keep === buf.length) return undefined;
    const torn = buf.subarray(keep).toString('utf8');
    const tfd = fs.openSync(this.file + '.torn', 'a');
    try { fs.writeSync(tfd, `${new Date().toISOString()} ${torn}\n`); fs.fsyncSync(tfd); } finally { fs.closeSync(tfd); }
    const fd = fs.openSync(this.file, 'r+');
    try { fs.ftruncateSync(fd, keep); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    return torn;
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
    this.repairTornTail();
    const v = this.verify();
    if (!v.ok) throw new Error(`ledger chain broken at ${v.brokenAt}: ${v.reason}`);
    const body = { seq: v.count + 1, ts: new Date().toISOString(), tx, type, data, prev: v.head };
    const record: LedgerRecord = { ...body, hash: hashOf(body) };
    // ponytail: re-verifies the whole file on every append (O(n)); cache the head if ledgers grow large.
    const fd = fs.openSync(this.file, 'a');
    try {
      const line = JSON.stringify(record) + '\n';
      killPoint('mid-ledger-append', () => { fs.writeSync(fd, line.slice(0, line.length >> 1)); fs.fsyncSync(fd); });
      fs.writeSync(fd, line);
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
