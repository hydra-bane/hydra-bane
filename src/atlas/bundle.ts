import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { validateEntry, type AtlasBundle, type AtlasEntry } from './entry.ts';

// Signed Atlas bundle (PLAN.md §7.4). Ed25519 via node:crypto instead of minisign: same primitive, no dependency.
// The .sig file is the base64 of the raw 64-byte Ed25519 signature over the exact bytes of atlas-bundle.json.

export const ATLAS_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA4KB00lv83/aH04JUgObXNipstROZDKFo4Giu2Cgp5+k=
-----END PUBLIC KEY-----
`;
export const BUNDLE_URL = 'https://github.com/hydra-bane/atlas/releases/latest/download/atlas-bundle.json';
const MAX_BUNDLE_BYTES = 16 * 2 ** 20;

export type VerifyResult = { ok: true; bundle: AtlasBundle } | { ok: false; error: string };

export function verifyBundle(bytes: Buffer, sigBase64: string, publicKeyPem = ATLAS_PUBLIC_KEY_PEM): VerifyResult {
  const sig = Buffer.from(sigBase64.trim(), 'base64');
  if (sig.length !== 64) return { ok: false, error: 'signature is not a 64-byte Ed25519 signature' };
  let good = false;
  try { good = crypto.verify(null, bytes, crypto.createPublicKey(publicKeyPem), sig); } catch { /* bad key or signature */ }
  if (!good) return { ok: false, error: 'bad signature' };
  let b: any;
  try { b = JSON.parse(bytes.toString('utf8')); } catch { return { ok: false, error: 'bundle is not JSON' }; }
  if (b?.schema !== 2) return { ok: false, error: `bundle schema ${String(b?.schema)} is not supported (this Hydra-bane reads schema 2)` };
  if (!Number.isSafeInteger(b.bundle_seq) || b.bundle_seq < 1 || typeof b.created !== 'string' || !Array.isArray(b.entries)) return { ok: false, error: 'bundle header is invalid' };
  return { ok: true, bundle: b as AtlasBundle };
}

/** Client-side re-check of every entry (§7.2): invalid or duplicate entries are dropped, the rest are usable. */
function usableEntries(b: AtlasBundle): { entries: AtlasEntry[]; dropped: string[] } {
  const entries: AtlasEntry[] = [], dropped: string[] = [], seen = new Set<string>();
  for (const e of b.entries as unknown[]) {
    const id = typeof (e as any)?.id === 'string' ? (e as any).id as string : '<no id>';
    if (validateEntry(e).length || seen.has(id)) { dropped.push(id); continue; }
    seen.add(id);
    entries.push(e as AtlasEntry);
  }
  return { entries, dropped };
}

const atlasDir = (stateDir: string) => path.join(stateDir, 'atlas');
const storedSeq = (stateDir: string): number => {
  try { const n = (JSON.parse(fs.readFileSync(path.join(atlasDir(stateDir), 'state.json'), 'utf8')) as { bundle_seq?: unknown }).bundle_seq; return Number.isSafeInteger(n) ? n as number : 0; } catch { return 0; }
};
const writeAtomic = (file: string, data: string | Buffer) => { fs.writeFileSync(file + '.tmp', data); fs.renameSync(file + '.tmp', file); };

export type InstallResult = { ok: true; bundle: AtlasBundle; dropped: string[] } | { ok: false; error: string };

export function installBundle(stateDir: string, bytes: Buffer, sig: string, now: Date = new Date(), publicKeyPem = ATLAS_PUBLIC_KEY_PEM): InstallResult {
  const v = verifyBundle(bytes, sig, publicKeyPem);
  if (!v.ok) return v;
  const prev = storedSeq(stateDir);
  if (v.bundle.bundle_seq < prev) return { ok: false, error: `bundle_seq ${v.bundle.bundle_seq} is older than the installed ${prev} (rollback refused)` };
  const dir = atlasDir(stateDir);
  fs.mkdirSync(dir, { recursive: true });
  // The exact signed bytes are stored, so every load can re-verify them. A crash between the renames leaves a
  // pair that fails verification, which reads as "not installed" until the next update.
  writeAtomic(path.join(dir, 'bundle.json'), bytes);
  writeAtomic(path.join(dir, 'bundle.json.sig'), sig.trim());
  writeAtomic(path.join(dir, 'state.json'), JSON.stringify({ bundle_seq: v.bundle.bundle_seq, installed_at: now.toISOString() }, null, 2));
  const u = usableEntries(v.bundle);
  return { ok: true, bundle: { ...v.bundle, entries: u.entries }, dropped: u.dropped };
}

/** Re-verifies the signature on every load: the files are user-writable. undefined means "atlas: not installed". */
export function loadInstalledBundle(stateDir: string, publicKeyPem = ATLAS_PUBLIC_KEY_PEM): AtlasBundle | undefined {
  const dir = atlasDir(stateDir);
  let bytes: Buffer, sig: string;
  try { bytes = fs.readFileSync(path.join(dir, 'bundle.json')); sig = fs.readFileSync(path.join(dir, 'bundle.json.sig'), 'utf8'); } catch { return undefined; }
  const v = verifyBundle(bytes, sig, publicKeyPem);
  if (!v.ok || v.bundle.bundle_seq < storedSeq(stateDir)) return undefined;
  return { ...v.bundle, entries: usableEntries(v.bundle).entries };
}

export type AtlasStatus = { installed: false } | { installed: true; bundle_seq: number; created: string; entries: number };
export function atlasStatus(stateDir: string, publicKeyPem = ATLAS_PUBLIC_KEY_PEM): AtlasStatus {
  const b = loadInstalledBundle(stateDir, publicKeyPem);
  return b ? { installed: true, bundle_seq: b.bundle_seq, created: b.created, entries: b.entries.length } : { installed: false };
}

type Fetch = (url: string) => Promise<{ ok: boolean; status: number; arrayBuffer(): Promise<ArrayBuffer> }>;

/** `hydra-bane atlas update` only. Never called automatically. */
export async function updateBundle(stateDir: string, fetchImpl: Fetch = fetch, now: Date = new Date(), publicKeyPem = ATLAS_PUBLIC_KEY_PEM): Promise<InstallResult> {
  const get = async (url: string) => {
    const r = await fetchImpl(url);
    if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
    const buf = Buffer.from(await r.arrayBuffer());
    if (buf.length > MAX_BUNDLE_BYTES) throw new Error(`${url}: larger than ${MAX_BUNDLE_BYTES} bytes`);
    return buf;
  };
  try {
    const [bytes, sig] = await Promise.all([get(BUNDLE_URL), get(`${BUNDLE_URL}.sig`)]);
    return installBundle(stateDir, bytes, sig.toString('utf8'), now, publicKeyPem);
  } catch (e) {
    return { ok: false, error: `download failed: ${(e as Error).message}` };
  }
}
