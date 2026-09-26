import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { ScanItem } from '../core/scan.ts';
import { advisoryApplies, atlasItemId, keyMatches, signerMatches, type Advisory, type Applies, type AtlasBundle, type AtlasEntry } from './entry.ts';
import { measureFacts, type FactsRunner, type ProgramFacts } from './facts.ts';
import { listPrograms as defaultListPrograms, UNINSTALL_ROOTS, type Program } from './programs.ts';
import { mainExecutable, type Signer } from './report.ts';
import { buildUninstall, type UninstallDeps } from './uninstall.ts';

// Atlas matching (PLAN.md §7, schema 2): installed programs against the signed bundle. Items state facts only:
// what the entry says the program is, what it does on this PC (facts.ts), and advisories that cover this version.

export type SignersOf = (files: string[]) => Map<string, Signer | undefined>;

/** One PowerShell for all files. Paths go through a UTF-8 temp file, never through the command text. */
export const authenticodeMany: SignersOf = (files) => {
  const out = new Map<string, Signer | undefined>();
  if (!files.length) return out;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hb-sig-'));
  try {
    const list = path.join(dir, 'files.json');
    fs.writeFileSync(list, JSON.stringify(files));
    const ps = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; $f = Get-Content -Raw -Encoding UTF8 -LiteralPath $env:HB_LIST | ConvertFrom-Json; " +
      "ConvertTo-Json -Compress -InputObject @($f | ForEach-Object { $s = Get-AuthenticodeSignature -LiteralPath $_ -ErrorAction SilentlyContinue; @{status=[string]$s.Status; subject=$s.SignerCertificate.Subject; thumbprint=$s.SignerCertificate.Thumbprint} })";
    const r = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], { encoding: 'utf8', windowsHide: true, timeout: 180_000, env: { ...process.env, HB_LIST: list } });
    const arr = JSON.parse(r.stdout) as Signer[];
    files.forEach((f, i) => { const s = arr[i]; out.set(f, s?.status ? { status: s.status, subject: s.subject ?? undefined, thumbprint: s.thumbprint ?? undefined } : undefined); });
  } catch { /* unreadable: no signer matches */ } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  return out;
};

export interface AtlasScanDeps extends UninstallDeps {
  bundle: AtlasBundle | undefined;
  listPrograms?: () => Program[];
  signersOf?: SignersOf;
  /** Folder for the signature cache (the state dir). Detection only: apply re-checks signatures live. */
  cacheDir?: string;
  /** Read-only measurement of this PC; runs once, and only when a program matched. */
  factsRunner?: FactsRunner;
}

/** Caches lookups by path + size + mtime. A replaced file changes size or mtime and is looked up again. */
export function cachedSigners(dir: string, inner: SignersOf): SignersOf {
  return (files) => {
    const file = path.join(dir, 'atlas', 'signers-cache.json');
    let cache: Record<string, { k: string; s: Signer | null }> = {};
    try { cache = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { /* first run */ }
    const key = (f: string) => { try { const st = fs.statSync(f); return `${st.size}:${st.mtimeMs}`; } catch { return 'missing'; } };
    const out = new Map<string, Signer | undefined>();
    const todo = files.filter((f) => { const c = cache[f.toLowerCase()]; if (c && c.k === key(f)) { out.set(f, c.s ?? undefined); return false; } return true; });
    if (todo.length) {
      for (const [f, s] of inner(todo)) { out.set(f, s); cache[f.toLowerCase()] = { k: key(f), s: s ?? null }; }
      try { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, JSON.stringify(cache)); } catch { /* cache is optional */ }
    }
    return out;
  };
}

const keyPath = (p: Program) => `${UNINSTALL_ROOTS.find((r) => r.hive === p.hive && r.view === p.view)?.key ?? p.hive}\\${p.keyName}`;
const size = (b: number) => (b >= 2 ** 30 ? `${(b / 2 ** 30).toFixed(1)} GB` : `${Math.max(1, Math.round(b / 2 ** 20))} MB`);

/** Structured Atlas data on a scan item, for agents. */
export interface AtlasItemData {
  entryId: string;
  context: string;
  facts: ProgramFacts;
  advisories: (Advisory & { applies: Applies })[];
}

const emptyFacts = (p: Program): ProgramFacts => ({ version: p.version, installDate: undefined, bytes: p.estimatedBytes, dirs: [], rootCerts: [], listeners: [], services: [] });

function advisoryLine(a: Advisory & { applies: Applies }, version: string | undefined): string {
  const head = `${who(a)} ${a.date}: "${a.title}"${a.cve?.length ? ` (${a.cve.join(', ')})` : ''}${a.kev ? ' [in CISA Known Exploited Vulnerabilities]' : ''} ${a.url}`;
  const range = a.affected && `${a.affected.inclusive ? 'up to and including' : 'before'} ${a.affected.up_to}`;
  if (a.applies === 'applies') return `${head}. Covers your version ${version} (the advisory covers versions ${range}).`;
  if (a.applies === 'not-applicable') return `${head}. Does not cover your version ${version}: your version is newer than the ${a.affected!.inclusive ? 'last affected' : 'fixed'} version ${a.affected!.up_to}.`;
  return `${head}. ${a.affected ? `Your installed version could not be read; the advisory covers versions ${range}.` : 'The advisory names no version range.'}`;
}

const who = (a: Advisory) => (a.publisher === 'other' ? 'third-party' : a.publisher);
const shortCert = (s: string) => /CN=([^,]+)/.exec(s)?.[1] ?? /O=([^,]+)/.exec(s)?.[1] ?? s;

/** One-line title of measured facts; the full detail goes to instructions (people) and `atlas` (agents). */
export function atlasItem(p: Program, e: AtlasEntry, deps: UninstallDeps = {}, facts: ProgramFacts = emptyFacts(p)): ScanItem {
  const spec = buildUninstall(p, e, deps);
  const advisories = e.advisories.map((a) => ({ ...a, applies: advisoryApplies(a, p.version) }));
  const applying = advisories.filter((a) => a.applies === 'applies');
  const ports = (net: boolean) => facts.listeners.filter((l) => l.network === net).map((l) => l.port);
  const plural = (n: number[]) => `port${n.length > 1 ? 's' : ''} ${n.join(', ')}`;
  const network = ports(true), local = ports(false), auto = facts.services.filter((s) => s.startsWithWindows);
  const parts = [
    network.length && `accepts network connections on ${plural(network)}`,
    local.length && `runs a local server on ${plural(local)}`,
    facts.rootCerts.length && `installed trusted root certificate ${facts.rootCerts.map((c) => `"${shortCert(c.subject)}"`).join(', ')}`,
    auto.length && `starts with Windows (service ${auto.map((s) => s.name).join(', ')})`,
    applying.length && `${who(applying[0]!)} advisory ${applying[0]!.date} covers your version${applying.length > 1 ? ` (+${applying.length - 1} more)` : ''}`,
  ].filter((x): x is string => !!x);
  if (!parts.length) parts.push(`installed${facts.installDate ? ` ${facts.installDate}` : ''}${facts.bytes ? `, ${size(facts.bytes)}` : ''}`);
  const title = `${e.names[0]} by ${e.vendor.name}${p.name !== e.names[0] ? ` (installed as "${p.name}")` : ''}: ${parts.join('; ')}${e.dispute.status === 'open' ? '; vendor dispute open' : ''}`;

  const details = [
    `What it is: ${e.context} (source: ${e.sources[0]!.url})`,
    `Installed: version ${p.version ?? 'unknown'}${facts.installDate ? `, on ${facts.installDate}` : ''}${facts.bytes ? `, ${size(facts.bytes)}` : ''}${facts.dirs.length ? `, in ${facts.dirs.join('; ')}` : ''}.`,
    ...facts.rootCerts.map((c) => `Trusted root certificate "${c.subject}" (thumbprint ${c.thumbprint}, valid from ${c.notBefore}) is in the ${c.stores.join(' and ')} root store${c.stores.length > 1 ? 's' : ''}. Windows trusts sites and code this certificate vouches for.`),
    ...facts.listeners.map((l) => `Listens on TCP port ${l.port} (${l.address}, ${l.network ? 'other machines can connect unless a firewall blocks them' : 'this PC only'}): ${l.process}`),
    ...facts.services.map((s) => `Service "${s.name}": start mode ${s.startMode}${s.startsWithWindows ? ' (starts with Windows)' : ''}, ${s.state.toLowerCase()}: ${s.exe}`),
    ...(advisories.length ? advisories.map((a) => `Advisory: ${advisoryLine(a, p.version)}`) : ['Advisories: none recorded in the Atlas for this program.']),
    e.reinstall_note && `If you need it again: ${e.reinstall_note}`,
    e.dispute.status !== 'none' && `Vendor dispute (${e.dispute.status})${e.dispute.url ? `: ${e.dispute.url}` : ''}.`,
    ...e.vendor_response.map((r) => `Vendor response (${r.date}): ${r.url}`),
  ].filter((x): x is string => !!x);
  const target = p.installLocation && /^[a-z]:\\/i.test(p.installLocation) ? p.installLocation : keyPath(p);
  const base = {
    id: atlasItemId(e.id, p.id), category: 'atlas' as const, title, targets: [target], allowRoot: target,
    bytes: p.estimatedBytes ?? 0, files: 0, risk: 'caution' as const, reversible: 'reinstall-only' as const,
    atlas: { entryId: e.id, context: e.context, facts, advisories },
  };
  if ('reason' in spec) {
    return { ...base, op: 'report_only', instructions: [`Remove it from Settings > Apps > Installed apps (look for "${p.name}"). Hydra-bane will not run its uninstaller: ${spec.reason}.`, ...details].join('\n') };
  }
  // ponytail: per-machine EXE uninstallers usually demand elevation, and CreateProcess cannot raise UAC; MSI elevates itself.
  return { ...base, op: 'uninstall', uninstall: spec, ...(p.hive === 'HKLM' && spec.kind === 'exe' ? { needsAdmin: true } : {}), instructions: details.join('\n') };
}

/** First matching entry per installed program. Nothing is selected here; atlas items are never risk 'safe'. */
export function scanAtlas(deps: AtlasScanDeps): ScanItem[] {
  const bundle = deps.bundle;
  if (!bundle?.entries.length) return [];
  const programs = (deps.listPrograms ?? (() => defaultListPrograms()))();
  const env = deps.env ?? process.env;
  const exes = new Map(programs.map((p) => [p.id, mainExecutable(p, env)]));
  // Programs matched by their uninstall key need no signature lookup here; the rest are checked so that renamed
  // bundleware is still caught by its signer. Lookups cost ~0.2 s per file, so results are cached per file state.
  const needSigners = bundle.entries.some((e) => e.detect.signers.length);
  const files = needSigners ? [...new Set(programs.filter((p) => !bundle.entries.some((x) => keyMatches(x, p))).map((p) => exes.get(p.id)).filter((f): f is string => !!f))] : [];
  const lookup = deps.signersOf ?? (deps.cacheDir ? cachedSigners(deps.cacheDir, authenticodeMany) : authenticodeMany);
  const signers = files.length ? lookup(files) : new Map<string, Signer | undefined>();
  const matched: Program[] = [], entries: AtlasEntry[] = [];
  for (const p of programs) {
    const exe = exes.get(p.id);
    const signer = exe ? signers.get(exe) : undefined;
    const e = bundle.entries.find((x) => keyMatches(x, p) || signerMatches(x, signer));
    if (e) { matched.push(p); entries.push(e); }
  }
  const facts = measureFacts(matched, entries, deps.factsRunner, env);
  return matched.map((p, i) => atlasItem(p, entries[i]!, deps, facts[i]));
}
