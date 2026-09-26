import { createHash, timingSafeEqual } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { gunzipSync } from 'node:zlib';
import type { ItemOutcome } from '../core/apply.ts';
import { executeAdminItem, isElevated, userWritable, type AdminApplyDeps } from '../core/admin.ts';
import { planHash, type Plan } from '../core/plan.ts';
import { regQuery, type RegValue } from '../guard/protected.ts';
import { isSameOrDescendant, normalizeWinPath } from '../guard/normalize.ts';

// PLAN.md §6.7: elevated work only ever runs code from %ProgramData%\hydra-bane\helper\<version>, a folder only
// Administrators and SYSTEM can write, filled from the npm registry tarball whose sha512 integrity we check
// ourselves. The elevated process trusts nothing from its parent: it copies the plan, re-hashes it and
// re-runs the guard, P and DACL checks.

type Env = Record<string, string | undefined>;
type Result<T> = ({ ok: true } & T) | { ok: false; code: string; detail: string };
const fail = (code: string, detail: string) => ({ ok: false as const, code, detail });

const VERSION_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const PLAN_ID_RE = /^[a-z0-9]+$/;
const HASH_RE = /^[0-9a-f]{64}$/;
/** Only real local/domain user accounts: the folder owner we protect (PLAN §6.7). */
const USER_SID_RE = /^S-1-5-21(-\d+){3,}$/;
const SAFE_LITERAL = /^[A-Za-z]:\\[A-Za-z0-9 _.\\()-]*$/;
const ADMINS = '*S-1-5-32-544', SYSTEM = '*S-1-5-18', USERS = '*S-1-5-32-545';

export function adminBase(env: Env = process.env): string {
  const n = normalizeWinPath(env.ProgramData ?? '');
  if (!n.ok) throw new Error('ProgramData is not set to an absolute path');
  return path.win32.join(n.path, 'hydra-bane');
}
export function helperDir(version: string, env: Env = process.env): string {
  if (!VERSION_RE.test(version)) throw new Error(`bad version ${version}`);
  return path.win32.join(adminBase(env), 'helper', version);
}
export const adminPlansDir = (env: Env = process.env) => path.win32.join(adminBase(env), 'plans');

// --- npm registry ---

export type FetchLike = (url: string) => Promise<{ ok: boolean; status: number; json(): Promise<unknown>; arrayBuffer(): Promise<ArrayBuffer> }>;

/** Downloads hydra-bane@version from registry.npmjs.org over HTTPS and checks dist.integrity. Never reads local files. */
export async function verifyAgainstRegistry(version: string, fetchImpl: FetchLike = fetch): Promise<Result<{ tarball: Buffer; integrity: string }>> {
  if (!VERSION_RE.test(version)) return fail('BAD_VERSION', version);
  const meta = await fetchImpl(`https://registry.npmjs.org/hydra-bane/${version}`);
  if (!meta.ok) return fail('REGISTRY', `metadata HTTP ${meta.status}`);
  const dist = ((await meta.json()) as { dist?: { integrity?: string; tarball?: string } }).dist;
  const expectedUrl = `https://registry.npmjs.org/hydra-bane/-/hydra-bane-${version}.tgz`;
  if (dist?.tarball !== expectedUrl) return fail('REGISTRY', `unexpected tarball URL ${dist?.tarball}`);
  const integrity = dist.integrity ?? '';
  const want = /^sha512-([A-Za-z0-9+/]+={0,2})$/.exec(integrity)?.[1];
  if (!want) return fail('REGISTRY', `no sha512 integrity (${integrity})`);
  const res = await fetchImpl(expectedUrl);
  if (!res.ok) return fail('REGISTRY', `tarball HTTP ${res.status}`);
  const tarball = Buffer.from(await res.arrayBuffer());
  const got = createHash('sha512').update(tarball).digest();
  const exp = Buffer.from(want, 'base64');
  if (exp.length !== got.length || !timingSafeEqual(exp, got)) return fail('INTEGRITY_MISMATCH', 'downloaded tarball does not match the registry sha512');
  return { ok: true, tarball, integrity };
}

// --- .tgz reader: ustar regular files only ---

function field(h: Buffer, off: number, len: number): string {
  const s = h.subarray(off, off + len);
  const z = s.indexOf(0);
  return s.subarray(0, z === -1 ? len : z).toString('utf8');
}
function octal(h: Buffer, off: number, len: number): number {
  if (h[off]! & 0x80) throw new Error('base-256 sizes are not supported');
  const s = field(h, off, len).trim();
  if (!/^[0-7]*$/.test(s)) throw new Error('bad octal field');
  return s ? parseInt(s, 8) : 0;
}

/** Relative path under package/, or throws. Rejects absolute, drive, UNC, .., ADS, backslashes and Windows-hostile names. */
function safeEntryName(name: string): string {
  if (!name.startsWith('package/')) throw new Error(`entry outside package/: ${name}`);
  const rel = name.slice('package/'.length).replace(/\/$/, '');
  const segs = rel.split('/');
  if (!rel || segs.some((s) => !s || s === '.' || s === '..' || /[\\:*?"<>|\0]/.test(s) || /[. ]$/.test(s))) throw new Error(`unsafe entry name: ${name}`);
  return segs.join('\\');
}

/** Extracts regular files from an npm .tgz into memory. Links, devices and anything unusual reject the whole archive. */
export function readTgz(tgz: Buffer): Map<string, Buffer> {
  const tar = gunzipSync(tgz);
  const files = new Map<string, Buffer>();
  let paxPath: string | undefined;
  for (let off = 0; off + 512 <= tar.length;) {
    const h = tar.subarray(off, off + 512);
    if (h.every((b) => b === 0)) break;
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : h[i]!;
    if (sum !== octal(h, 148, 8)) throw new Error(`bad header checksum at ${off}`);
    const size = octal(h, 124, 12);
    const type = String.fromCharCode(h[156]!);
    const prefix = field(h, 345, 155);
    const name = paxPath ?? (prefix ? `${prefix}/${field(h, 0, 100)}` : field(h, 0, 100));
    const body = tar.subarray(off + 512, off + 512 + size);
    if (body.length !== size) throw new Error('truncated archive');
    off += 512 + Math.ceil(size / 512) * 512;
    if (type === 'x') {
      paxPath = /(?:^|\n)\d+ path=([^\n]*)\n/.exec(body.toString('utf8'))?.[1];
      continue;
    }
    paxPath = undefined;
    if (type === 'g') continue;
    if (type === '5') { safeEntryName(name); continue; }
    if (type !== '0' && type !== '\0') throw new Error(`unsupported entry type '${type}' for ${name}`);
    const rel = safeEntryName(name);
    if ([...files.keys()].some((k) => k.toLowerCase() === rel.toLowerCase())) throw new Error(`duplicate entry ${name}`);
    files.set(rel, Buffer.from(body));
  }
  return files;
}

// --- Helper installation (runs elevated) ---

export interface InstallDeps {
  env?: Env;
  fetchImpl?: FetchLike;
  /** Runs icacls.exe with these arguments (no shell); returns status and stdout. */
  icaclsRun?: (args: string[]) => { status: number | null; stdout: string };
  /** Raw `icacls <path>` listing for the DACL check. */
  icacls?: (target: string) => string;
  elevated?: boolean;
  /** Installed npm package root (the one the user runs). When given, its files must equal the registry's. */
  localRoot?: string;
}

const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');

function defaultIcaclsRun(args: string[]) {
  const r = spawnSync(path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'icacls.exe'), args, { encoding: 'utf8', windowsHide: true, timeout: 60_000 });
  return { status: r.status, stdout: (r.stdout ?? '') + (r.stderr ?? '') };
}

/** Lists every entry under `dir`: files by relative path, and any link/reparse point as a problem. */
function walk(dir: string): { files: Map<string, string>; problems: string[] } {
  const files = new Map<string, string>(), problems: string[] = [];
  const stack = [''];
  while (stack.length) {
    const rel = stack.pop()!;
    for (const e of fs.readdirSync(path.win32.join(dir, rel), { withFileTypes: true })) {
      const r = rel ? `${rel}\\${e.name}` : e.name;
      if (e.isSymbolicLink()) problems.push(`link ${r}`);
      else if (e.isDirectory()) stack.push(r);
      else if (e.isFile()) files.set(r, sha(fs.readFileSync(path.win32.join(dir, r))));
      else problems.push(`special ${r}`);
    }
  }
  return { files, problems };
}

/** Exact file set and SHA-256 per file; any extra, missing, changed or linked entry is a mismatch. */
export function verifyInstalled(dir: string, expected: Map<string, Buffer>): string[] {
  let got: ReturnType<typeof walk>;
  try { got = walk(dir); } catch (e) { return [`unreadable: ${(e as Error).message}`]; }
  const out = [...got.problems];
  const want = new Map([...expected].map(([k, v]) => [k.toLowerCase(), sha(v)]));
  for (const [k, h] of got.files) { const w = want.get(k.toLowerCase()); if (!w) out.push(`extra ${k}`); else if (w !== h) out.push(`changed ${k}`); }
  const have = new Set([...got.files.keys()].map((k) => k.toLowerCase()));
  for (const k of want.keys()) if (!have.has(k)) out.push(`missing ${k}`);
  return out;
}

/** Files that differ between the registry tarball and the locally installed package (PLAN §6.7 step 3). */
export function localMismatches(files: Map<string, Buffer>, localRoot: string): string[] {
  const out: string[] = [];
  for (const [rel, body] of files) {
    try { if (sha(fs.readFileSync(path.win32.join(localRoot, rel))) !== sha(body)) out.push(rel); } catch { out.push(rel); }
  }
  return out;
}

const isLink = (p: string) => { try { return fs.lstatSync(p).isSymbolicLink(); } catch { return false; } };

/** A folder we will use elevated: must not be a link and must not be writable by non-admins. */
function checkAdminDir(dir: string, deps: InstallDeps): string | undefined {
  if (isLink(dir)) return `${dir} is a link or junction`;
  const w = userWritable(dir, deps.icacls ? { icacls: deps.icacls } : {});
  if (w === 'UNKNOWN') return `cannot read the ACL of ${dir}`;
  if (w.length) return `${dir} is writable by ${w.join(', ')}`;
  return undefined;
}

/** mkdir + admin-only ACL (inheritance removed; Administrators and SYSTEM full, Users read/execute) + owner Administrators. */
function lockDown(dir: string, deps: InstallDeps): string | undefined {
  if (isLink(dir)) return `${dir} is a link or junction`;
  fs.mkdirSync(dir, { recursive: true });
  const run = deps.icaclsRun ?? defaultIcaclsRun;
  const steps = [
    [dir, '/inheritance:r', '/grant:r', `${ADMINS}:(OI)(CI)F`, `${SYSTEM}:(OI)(CI)F`, `${USERS}:(OI)(CI)RX`],
    [dir, '/setowner', ADMINS],
  ];
  for (const args of steps) {
    const r = run(args);
    if (r.status !== 0) return `icacls ${args.slice(1).join(' ')} failed: ${r.stdout.slice(0, 200)}`;
  }
  return checkAdminDir(dir, deps);
}

export async function installHelper(version: string, deps: InstallDeps = {}): Promise<Result<{ dir: string; files: number; reused: boolean }>> {
  if (!(deps.elevated ?? isElevated())) return fail('NOT_ELEVATED', 'admin-install must run elevated');
  const env = deps.env ?? process.env;
  let dir: string;
  try { dir = helperDir(version, env); } catch (e) { return fail('BAD_VERSION', (e as Error).message); }
  const v = await verifyAgainstRegistry(version, deps.fetchImpl);
  if (!v.ok) return v;
  let files: Map<string, Buffer>;
  try { files = readTgz(v.tarball); } catch (e) { return fail('BAD_TARBALL', (e as Error).message); }
  if (deps.localRoot) {
    const m = localMismatches(files, deps.localRoot);
    if (m.length) return fail('LOCAL_MISMATCH', `local package differs from the registry: ${m.slice(0, 5).join(', ')}`);
  }

  // ProgramData lets users create folders, so a pre-existing base may be attacker-made: ACL it ourselves, then verify.
  for (const d of [adminBase(env), path.win32.dirname(dir), adminPlansDir(env)]) {
    const bad = lockDown(d, deps);
    if (bad) return fail('BASE_UNSAFE', bad);
  }
  if (fs.existsSync(dir)) {
    const bad = checkAdminDir(dir, deps);
    const diff = bad ? [bad] : verifyInstalled(dir, files);
    // Never delete elevated inside a folder we did not create: the human removes it and runs admin-install again.
    return diff.length ? fail('HELPER_DIR_UNTRUSTED', `${dir} exists and does not match the registry (${diff.slice(0, 5).join('; ')}); delete it and retry`) : { ok: true, dir, files: files.size, reused: true };
  }
  const staging = `${dir}.staging-${process.pid}`;
  if (fs.existsSync(staging)) return fail('HELPER_DIR_UNTRUSTED', `${staging} already exists; delete it and retry`);
  fs.mkdirSync(staging); // inherits the admin-only ACL from helper\
  for (const [rel, body] of files) {
    const p = path.win32.join(staging, rel);
    fs.mkdirSync(path.win32.dirname(p), { recursive: true });
    fs.writeFileSync(p, body, { flag: 'wx' });
  }
  const diff = verifyInstalled(staging, files);
  const bad = checkAdminDir(staging, deps);
  if (diff.length || bad) return fail('VERIFY_FAILED', [bad, ...diff].filter(Boolean).slice(0, 5).join('; '));
  fs.renameSync(staging, dir);
  return { ok: true, dir, files: files.size, reused: false };
}

// --- Launching and running admin-apply ---

/**
 * The command the non-elevated CLI runs to request elevation. The plan hash is on node's command line, so the
 * UAC prompt ("Show more details") shows it. Refuses a node.exe in a folder non-admins can write (PLAN §6.7:
 * UAC would only show a signed node.exe while the file was swapped).
 */
export function elevatedApplyCommand(planId: string, hash: string, userSid: string, opts: { version: string; nodeExe?: string; env?: Env; icacls?: (t: string) => string }): Result<{ file: string; args: string[]; elevated: { file: string; args: string[] } }> {
  if (!PLAN_ID_RE.test(planId) || !HASH_RE.test(hash) || !USER_SID_RE.test(userSid)) return fail('BAD_ARGS', 'plan id, hash or SID malformed');
  const env = opts.env ?? process.env;
  const node = opts.nodeExe ?? process.execPath;
  const cli = path.win32.join(helperDir(opts.version, env), 'dist', 'cli.js');
  if (!SAFE_LITERAL.test(node) || !SAFE_LITERAL.test(cli)) return fail('BAD_PATH', `${node} / ${cli}`);
  const w = userWritable(path.win32.dirname(node), opts.icacls ? { icacls: opts.icacls } : {});
  if (w === 'UNKNOWN' || w.length) return fail('NODE_USER_WRITABLE', `${node} is in a folder non-admins can write (${w === 'UNKNOWN' ? 'ACL unreadable' : w.join(', ')}); install Node.js for all users (Program Files) to use admin items`);
  const args = [cli, 'admin-apply', planId, '--plan-hash', hash, '--user-sid', userSid];
  const ps = path.win32.join(env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const list = args.map((a) => `'${a}'`).join(',');
  const script = `$p = Start-Process -FilePath '${node}' -ArgumentList ${list} -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode`;
  return { ok: true, file: ps, args: ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], elevated: { file: node, args } };
}

/** %LOCALAPPDATA%\hydra-bane of the target user, from the registry profile path (the elevated env may be another admin's). */
export function userStateDir(userSid: string, reg: (key: string) => RegValue[] = regQuery): string | undefined {
  if (!USER_SID_RE.test(userSid)) return undefined;
  const p = reg(`HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\${userSid}`).find((v) => v.name === 'ProfileImagePath')?.data;
  const n = p ? normalizeWinPath(p) : undefined;
  return n?.ok ? path.win32.join(n.path, 'AppData', 'Local', 'hydra-bane') : undefined;
}

export interface CopyDeps { env?: Env; now?: () => Date; host?: string; reg?: (key: string) => RegValue[] }

/** Reads the user's plan once, writes that exact copy to the admin-only plans folder, then parses and checks the copy. */
export function copyPlanForAdmin(planId: string, expectedHash: string, userSid: string, deps: CopyDeps = {}): Result<{ plan: Plan; copy: string }> {
  if (!PLAN_ID_RE.test(planId) || !HASH_RE.test(expectedHash)) return fail('BAD_ARGS', 'plan id or hash malformed');
  const state = userStateDir(userSid, deps.reg);
  if (!state) return fail('NO_USER', `no profile for ${userSid}`);
  let bytes: Buffer;
  try { bytes = fs.readFileSync(path.win32.join(state, 'plans', `${planId}.json`)); } catch { return fail('NOT_FOUND', planId); }
  const dir = adminPlansDir(deps.env ?? process.env);
  const copy = path.win32.join(dir, `${planId}.json`);
  fs.mkdirSync(dir, { recursive: true });
  // A pre-planted link at this name is removed as a link, never written through.
  fs.rmSync(copy, { force: true });
  fs.writeFileSync(copy, bytes, { flag: 'wx' });
  let plan: Plan;
  try { plan = JSON.parse(fs.readFileSync(copy, 'utf8')) as Plan; } catch { return fail('TAMPERED', 'plan is not JSON'); }
  const { hash, ...body } = plan;
  if (planHash(body) !== hash || hash !== expectedHash) return fail('TAMPERED', 'plan contents do not match the hash shown in the UAC prompt');
  if ((deps.now ?? (() => new Date()))() > new Date(plan.expiresAt)) return fail('EXPIRED', plan.expiresAt);
  if (plan.sid !== userSid || plan.host !== (deps.host ?? process.env.COMPUTERNAME ?? '')) return fail('OTHER_USER', 'plan was made for another user or machine');
  return { ok: true, plan, copy };
}

export interface AdminApplyArgs { planId: string; hash: string; userSid: string }

export function parseAdminApplyArgs(argv: string[]): AdminApplyArgs | undefined {
  const [planId, ...rest] = argv;
  const get = (f: string) => { const i = rest.indexOf(f); return i >= 0 ? rest[i + 1] : undefined; };
  const hash = get('--plan-hash'), userSid = get('--user-sid');
  return planId && hash && userSid && PLAN_ID_RE.test(planId) && HASH_RE.test(hash) && USER_SID_RE.test(userSid) ? { planId, hash, userSid } : undefined;
}

export interface RunAdminDeps extends Omit<AdminApplyDeps, 'protectedPaths'>, CopyDeps {
  elevated?: boolean;
  /** This script's own path; must be inside the helper folder. */
  selfPath: string;
  version: string;
  /** Rebuilt in this process: buildProtectedPaths(). */
  protectedPaths: () => string[];
}

/**
 * The body of `hydra-bane admin-apply` in the elevated helper. Only needsAdmin items run; everything else is
 * the parent's job. Writes <plans>\<id>.result.json for the parent to read into its ledger.
 */
export function runAdminApply(a: AdminApplyArgs, deps: RunAdminDeps): Result<{ outcomes: ItemOutcome[]; resultFile: string }> {
  if (!(deps.elevated ?? isElevated())) return fail('NOT_ELEVATED', 'admin-apply must run elevated');
  const env = deps.env ?? process.env;
  const self = normalizeWinPath(deps.selfPath);
  if (!self.ok || !isSameOrDescendant(self.path, helperDir(deps.version, env))) return fail('NOT_FROM_HELPER', `${deps.selfPath} is not inside the admin-only helper folder; run admin-install first`);
  const plans = adminPlansDir(env);
  const unsafe = checkAdminDir(adminBase(env), deps) ?? (fs.mkdirSync(plans, { recursive: true }), checkAdminDir(plans, deps));
  if (unsafe) return fail('BASE_UNSAFE', unsafe);
  const c = copyPlanForAdmin(a.planId, a.hash, a.userSid, deps);
  if (!c.ok) return c;
  const protectedPaths = deps.protectedPaths();
  const outcomes = c.plan.items.filter((i) => i.needsAdmin && i.op !== 'report_only').flatMap((i) => executeAdminItem(i, { ...deps, env, protectedPaths }));
  const resultFile = path.win32.join(plans, `${a.planId}.result.json`);
  fs.rmSync(resultFile, { force: true });
  fs.writeFileSync(resultFile, JSON.stringify({ planId: a.planId, hash: a.hash, finishedAt: new Date().toISOString(), outcomes }, null, 2), { flag: 'wx' });
  return { ok: true, outcomes, resultFile };
}

/** Parent side: read what the elevated child did. The plans folder is admin-only, so users cannot forge it. */
export function readAdminResult(planId: string, hash: string, env: Env = process.env): { outcomes: ItemOutcome[] } | undefined {
  try {
    const r = JSON.parse(fs.readFileSync(path.win32.join(adminPlansDir(env), `${planId}.result.json`), 'utf8')) as { hash: string; outcomes: ItemOutcome[] };
    return r.hash === hash ? { outcomes: r.outcomes } : undefined;
  } catch { return undefined; }
}

/** Launches the elevated command. Injectable; tests never call the default. */
export function launchElevated(cmd: { file: string; args: string[] }, spawn: (file: string, args: string[]) => number | null = (f, a) => spawnSync(f, a, { windowsHide: true, stdio: 'inherit' }).status): number | null {
  return spawn(cmd.file, cmd.args);
}
