import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { regQuery } from '../guard/protected.ts';
import type { Program } from './programs.ts';

// User report of an unwanted program for the Atlas (PLAN.md §7.7). Built locally, shown in full, and sent only
// after the user approves. It must never carry who or which PC it came from.

export const ATLAS_REPO = 'hydra-bane/atlas';
const MAX_HASH_BYTES = 256 * 2 ** 20;

export interface Identity {
  username: string;
  hostname: string;
  env: Record<string, string | undefined>;
}

export const currentIdentity = (): Identity => ({ username: os.userInfo().username, hostname: os.hostname(), env: process.env });

// Longest first, so %LOCALAPPDATA% wins over %USERPROFILE%.
const ENV_PREFIXES = ['LOCALAPPDATA', 'APPDATA', 'TEMP', 'OneDrive', 'USERPROFILE', 'ProgramFiles(x86)', 'ProgramFiles', 'ProgramW6432', 'ProgramData', 'PUBLIC', 'SystemRoot'];
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Replace anything that identifies the user or the PC. Paths become %VAR%-relative. */
export function sanitize(value: string, id: Identity): string {
  let s = value;
  const prefixes = ENV_PREFIXES.map((name) => ({ name, dir: id.env[name] })).filter((p): p is { name: string; dir: string } => !!p.dir && p.dir.length > 3)
    .sort((a, b) => b.dir.length - a.dir.length);
  for (const p of prefixes) s = s.replace(new RegExp(escapeRe(p.dir.replace(/[\\/]+$/, '')) + '(?=[\\\\/"\',;]|$)', 'gi'), `%${p.name}%`);
  s = s.replace(/[a-z]:[\\/]+(?:users|documents and settings)[\\/]+[^\\/"',;]+/gi, '%USERPROFILE%'); // any profile left
  s = s.replace(/\bS-1-5-21(?:-\d+)+\b/gi, '<sid>');
  s = s.replace(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g, '<email>');
  const words = [id.hostname, ...(id.username.length >= 3 ? [id.username] : [])].filter((w) => w.length >= 2);
  for (const w of words) s = s.replace(new RegExp(`(?<![\\w-])${escapeRe(w)}(?![\\w-])`, 'gi'), '<redacted>');
  return s;
}

export interface Signer { status: string; subject?: string | undefined; thumbprint?: string | undefined }
export type SignerOf = (file: string) => Signer | undefined;

export const authenticode: SignerOf = (file) => {
  // Path goes through an environment variable, never through the command text.
  const ps = "$s = Get-AuthenticodeSignature -LiteralPath $env:HB_FILE; @{status=[string]$s.Status; subject=$s.SignerCertificate.Subject; thumbprint=$s.SignerCertificate.Thumbprint} | ConvertTo-Json -Compress";
  const r = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], { encoding: 'utf8', windowsHide: true, timeout: 30_000, env: { ...process.env, HB_FILE: file } });
  try { const j = JSON.parse(r.stdout) as Signer; return { status: j.status, subject: j.subject ?? undefined, thumbprint: j.thumbprint ?? undefined }; } catch { return undefined; }
};

export function countryCode(): string | undefined {
  const geo = regQuery('HKCU\\Control Panel\\International\\Geo').find((v) => v.name === 'Name')?.data;
  if (geo && /^[A-Z]{2}$/.test(geo)) return geo;
  const region = new Intl.Locale(Intl.DateTimeFormat().resolvedOptions().locale).region;
  return region && /^[A-Z]{2}$/.test(region) ? region : undefined;
}

/** The program's own executable, from DisplayIcon or the uninstaller path. Windows Installer is not the program. */
export function mainExecutable(p: Program, env: Record<string, string | undefined> = process.env): string | undefined {
  for (const raw of [p.displayIcon, p.uninstallString]) {
    if (!raw) continue;
    const m = /^\s*"([^"]+\.exe)"|^\s*([^"]+?\.exe)\b/i.exec(raw);
    const file = (m?.[1] ?? m?.[2])?.replace(/%([^%]+)%/g, (all, n: string) => env[n] ?? all);
    if (file && !/\\(?:msiexec|rundll32|cmd|powershell)\.exe$/i.test(file) && path.isAbsolute(file)) return file;
  }
  return undefined;
}

function fileFacts(file: string): { sha256?: string | undefined; size?: number | undefined } {
  try {
    const st = fs.statSync(file);
    if (!st.isFile()) return {};
    return { size: st.size, sha256: st.size <= MAX_HASH_BYTES ? crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex') : undefined };
  } catch { return {}; }
}

export interface AtlasReport {
  schema: 1;
  kind: 'atlas-report';
  suggested_id: string;
  program: { name: string; publisher?: string | undefined; version?: string | undefined };
  detect: {
    uninstall_key: { hive: string; view: string; key_name: string; display_name: string; publisher?: string | undefined };
    msi_product_code?: string | undefined;
    signer?: Signer | undefined;
    file?: { path: string; sha256?: string | undefined; size?: number | undefined } | undefined;
  };
  install_location?: string | undefined;
  country?: string | undefined;
  note?: string | undefined;
  reporter_tool: string;
}

const slug = (s: string | undefined) => (s ?? 'unknown').toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'unknown';

export interface ReportDeps { id?: Identity; signerOf?: SignerOf; country?: string | undefined; version: string }

export function buildReport(p: Program, note: string | undefined, deps: ReportDeps): AtlasReport {
  const id = deps.id ?? currentIdentity();
  const clean = (v: string | undefined) => (v === undefined ? undefined : sanitize(v, id));
  const exe = mainExecutable(p, id.env);
  const signer = exe ? (deps.signerOf ?? authenticode)(exe) : undefined;
  const r: AtlasReport = {
    schema: 1,
    kind: 'atlas-report',
    suggested_id: `${slug(clean(p.publisher))}.${slug(clean(p.name))}`,
    program: { name: clean(p.name)!, publisher: clean(p.publisher), version: clean(p.version) },
    detect: {
      uninstall_key: { hive: p.hive, view: p.view, key_name: clean(p.keyName)!, display_name: clean(p.name)!, publisher: clean(p.publisher) },
      msi_product_code: p.msiProductCode,
      signer: signer && { status: signer.status, subject: clean(signer.subject), thumbprint: signer.thumbprint },
      file: exe ? { path: clean(exe)!, ...fileFacts(exe) } : undefined,
    },
    install_location: clean(p.installLocation),
    country: deps.country,
    note: clean(note?.slice(0, 300)),
    reporter_tool: `hydra-bane ${deps.version}`,
  };
  return JSON.parse(JSON.stringify(r)) as AtlasReport; // drop undefined fields
}

export const issueTitle = (r: AtlasReport) => `[report] ${r.program.name}${r.program.publisher ? ` (${r.program.publisher})` : ''}`;

export const issueBody = (r: AtlasReport) => [
  'Submitted with `hydra-bane report`. The user reviewed this exact content before sending.',
  '',
  '```json',
  JSON.stringify(r, null, 2),
  '```',
].join('\n');

/** Pre-filled issue form link, for users without an authenticated gh. The form's field id is `report`. */
export const issueUrl = (r: AtlasReport) =>
  `https://github.com/${ATLAS_REPO}/issues/new?template=report.yml&title=${encodeURIComponent(issueTitle(r))}&report=${encodeURIComponent(JSON.stringify(r, null, 2))}`;

export type Gh = (args: string[], input?: string) => { status: number | null; stdout: string };
export const defaultGh: Gh = (args, input) => {
  const r = spawnSync('gh', args, { encoding: 'utf8', windowsHide: true, timeout: 60_000, input });
  return { status: r.status, stdout: r.stdout ?? '' };
};

export function submit(r: AtlasReport, gh: Gh = defaultGh): { via: 'gh'; url: string } | { via: 'link'; url: string } {
  if (gh(['auth', 'status']).status === 0) {
    const res = gh(['issue', 'create', '-R', ATLAS_REPO, '--title', issueTitle(r), '--body-file', '-'], issueBody(r));
    const url = res.stdout.trim().split(/\r?\n/).pop() ?? '';
    if (res.status === 0 && url.startsWith('https://')) return { via: 'gh', url };
  }
  return { via: 'link', url: issueUrl(r) };
}
