import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ATLAS_PUBLIC_KEY_PEM, atlasStatus, installBundle, loadInstalledBundle, updateBundle, verifyBundle } from '../src/atlas/bundle.ts';
import { atlasItemId, validateEntry, type AtlasBundle, type AtlasEntry } from '../src/atlas/entry.ts';
import { scanAtlas } from '../src/atlas/match.ts';
import type { Program } from '../src/atlas/programs.ts';
import type { Signer } from '../src/atlas/report.ts';
import { buildUninstall, parseUninstallString, runUninstall } from '../src/atlas/uninstall.ts';

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const PEM = publicKey.export({ type: 'spki', format: 'pem' }).toString();
const sign = (b: Buffer) => crypto.sign(null, b, privateKey).toString('base64');

const TP = 'A'.repeat(40), OTHER_TP = 'B'.repeat(40);
const GUID = '{11111111-2222-3333-4444-555555555555}';

const entry = (over: Partial<AtlasEntry> = {}): AtlasEntry => ({
  schema: 2, id: 'kr.example.clipdown', names: ['CLIPDOWN'], vendor: { name: 'Example Ads Co.', country: 'KR' },
  context: 'A download helper that some Korean video sites install alongside their player.', tags: { countries: ['KR'] },
  detect: { signers: [{ subject: 'CN=Example Ads Co.*', thumbprints: [TP] }], uninstall_keys: [{ display_name: '^CLIPDOWN', publisher: 'Example Ads Co.' }], root_certs: [] },
  uninstall: { command_source: 'signed-exe', msi_product_codes: [], exe_name: 'uninst.exe' },
  residue: 'report-only', reversible: 'reinstall-only', reinstall_note: 'Nothing needs it.',
  sources: [{ url: 'https://example.org/research', kind: 'security-research', date: '2026-01-01' }], advisories: [],
  source: 'original', vendor_response: [], dispute: { status: 'none' }, verified: false, verified_by: null, added: '2026-09-25', last_reviewed: '2026-09-25',
  ...over,
});

const bundleBytes = (seq: number, entries: unknown[]) => Buffer.from(JSON.stringify({ schema: 2, bundle_seq: seq, created: '2026-09-26', entries }));
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'hb-atlas-'));

const UNINST = 'C:\\Program Files\\Clipdown\\uninst.exe';
const prog = (over: Partial<Program> = {}): Program => ({
  id: 'P-abc123', name: 'CLIPDOWN', publisher: 'Example Ads Co.', hive: 'HKLM', view: '64', keyName: 'Clipdown',
  installLocation: 'C:\\Program Files\\Clipdown', uninstallString: `"${UNINST}"`, estimatedBytes: 1024, ...over,
});
const valid: Signer = { status: 'Valid', subject: 'CN=Example Ads Co., O=Example', thumbprint: TP };
const noFacts = () => ({ certs: [], listeners: [], services: [] });
const deps = (signer: Signer | undefined = valid) => ({ exists: () => true, signerOf: () => signer, env: { SystemRoot: 'C:\\Windows' }, factsRunner: noFacts });

describe('bundle', () => {
  it('fixture entry is valid', () => expect(validateEntry(entry())).toEqual([]));

  it('refuses a schema 1 bundle', () => {
    const b = Buffer.from(JSON.stringify({ schema: 1, bundle_seq: 1, created: '2026-09-26', entries: [] }));
    expect(verifyBundle(b, sign(b), PEM)).toEqual({ ok: false, error: expect.stringMatching(/schema 1 is not supported/) });
  });

  it('verifies a good signature and rejects bad, tampered and foreign-key signatures', () => {
    const b = bundleBytes(1, [entry()]);
    expect(verifyBundle(b, sign(b), PEM).ok).toBe(true);
    expect(verifyBundle(b, Buffer.alloc(64).toString('base64'), PEM)).toEqual({ ok: false, error: 'bad signature' });
    expect(verifyBundle(b, 'short', PEM).ok).toBe(false);
    const tampered = Buffer.from(b); tampered[tampered.length - 2]! ^= 1;
    expect(verifyBundle(tampered, sign(b), PEM).ok).toBe(false);
    expect(verifyBundle(b, sign(b)).ok).toBe(false); // production key did not sign it
    expect(ATLAS_PUBLIC_KEY_PEM).toContain('MCowBQYDK2VwAyEA4KB00lv83/aH04JUgObXNipstROZDKFo4Giu2Cgp5+k=');
  });

  it('installs, drops invalid entries, refuses rollback, re-verifies on load', () => {
    const dir = tmp();
    expect(loadInstalledBundle(dir, PEM)).toBeUndefined();
    expect(atlasStatus(dir, PEM)).toEqual({ installed: false });
    const b2 = bundleBytes(2, [entry(), { ...entry(), id: 'kr.bad.one', names: ['Some malware'] }, { id: 'nope' }]);
    const r = installBundle(dir, b2, sign(b2), new Date('2026-09-26T00:00:00Z'), PEM);
    expect(r.ok && r.dropped).toEqual(['kr.bad.one', 'nope']);
    expect(loadInstalledBundle(dir, PEM)?.entries.map((e) => e.id)).toEqual(['kr.example.clipdown']);
    expect(atlasStatus(dir, PEM)).toMatchObject({ installed: true, bundle_seq: 2, entries: 1 });

    const b1 = bundleBytes(1, [entry()]);
    const back = installBundle(dir, b1, sign(b1), new Date(), PEM);
    expect(back.ok).toBe(false);
    expect(!back.ok && back.error).toMatch(/rollback/);
    expect(installBundle(dir, b2, sign(b2), new Date(), PEM).ok).toBe(true); // same seq is fine

    // a validly signed older bundle copied over the files is refused at load time too
    fs.writeFileSync(path.join(dir, 'atlas', 'bundle.json'), b1);
    fs.writeFileSync(path.join(dir, 'atlas', 'bundle.json.sig'), sign(b1));
    expect(loadInstalledBundle(dir, PEM)).toBeUndefined();
    // user edits the stored bundle
    fs.writeFileSync(path.join(dir, 'atlas', 'bundle.json'), Buffer.from(b2.toString().replace('download helper', 'upload helper')));
    fs.writeFileSync(path.join(dir, 'atlas', 'bundle.json.sig'), sign(b2));
    expect(loadInstalledBundle(dir, PEM)).toBeUndefined();
  });

  it('update downloads bundle and signature', async () => {
    const dir = tmp();
    const b = bundleBytes(3, [entry()]);
    const files: Record<string, Buffer> = { 'atlas-bundle.json': b, 'atlas-bundle.json.sig': Buffer.from(sign(b)) };
    const fetchImpl = async (url: string) => {
      const f = files[url.split('/').pop()!];
      return { ok: !!f, status: f ? 200 : 404, arrayBuffer: async () => new Uint8Array(f ?? []).buffer };
    };
    expect((await updateBundle(dir, fetchImpl, new Date(), PEM)).ok).toBe(true);
    delete files['atlas-bundle.json.sig'];
    const r = await updateBundle(dir, fetchImpl, new Date(), PEM);
    expect(!r.ok && r.error).toMatch(/404/);
  });
});

describe('match', () => {
  const bundle = (e: AtlasEntry[]): AtlasBundle => ({ schema: 2, bundle_seq: 1, created: '2026-09-26', entries: e });

  it('matches by DisplayName regex and publisher, builds a neutral uninstall item', () => {
    const items = scanAtlas({ bundle: bundle([entry()]), listPrograms: () => [prog(), prog({ id: 'P-other', name: 'Notepad++', publisher: 'Don Ho' })], signersOf: () => new Map(), ...deps() });
    expect(items).toHaveLength(1);
    const i = items[0]!;
    expect(i).toMatchObject({ id: atlasItemId('kr.example.clipdown', 'P-abc123'), category: 'atlas', op: 'uninstall', risk: 'caution', reversible: 'reinstall-only', bytes: 1024, targets: ['C:\\Program Files\\Clipdown'], allowRoot: 'C:\\Program Files\\Clipdown', needsAdmin: true });
    expect(i.id).toMatch(/^ATLAS-[0-9a-f]{6}$/);
    expect(i.title).toBe('CLIPDOWN by Example Ads Co.: installed, 1 MB');
    expect(i.atlas).toMatchObject({ entryId: 'kr.example.clipdown', context: expect.stringContaining('download helper'), advisories: [] });
    expect(i.instructions).toContain('What it is: A download helper');
    expect(i.uninstall).toEqual({ entryId: 'kr.example.clipdown', kind: 'exe', file: UNINST, args: [], signers: [TP] });
  });

  it('does not match on publisher mismatch', () => {
    const items = scanAtlas({ bundle: bundle([entry({ detect: { signers: [], uninstall_keys: [{ display_name: '^CLIPDOWN', publisher: 'Example Ads Co.' }], root_certs: [] } })]), listPrograms: () => [prog({ publisher: 'Someone Else' })], ...deps() });
    expect(items).toEqual([]);
  });

  it('matches by signer thumbprint of the main executable', () => {
    const p = prog({ name: 'Renamed Helper', publisher: 'x', displayIcon: 'C:\\Program Files\\Clipdown\\helper.exe,0' });
    const e = entry({ detect: { signers: [{ subject: 'CN=Nothing*', thumbprints: [TP] }], uninstall_keys: [], root_certs: [] } });
    const signersOf = (files: string[]) => new Map(files.map((f) => [f, f.endsWith('helper.exe') ? valid : undefined]));
    expect(scanAtlas({ bundle: bundle([e]), listPrograms: () => [p], signersOf, ...deps() })).toHaveLength(1);
    const untrusted = (files: string[]) => new Map(files.map((f) => [f, { ...valid, status: 'NotTrusted' }]));
    expect(scanAtlas({ bundle: bundle([e]), listPrograms: () => [p], signersOf: untrusted, ...deps() })).toEqual([]);
  });

  it('always caution; open dispute still shows; failed checks become report_only', () => {
    const e = entry({ dispute: { status: 'open', url: 'https://example.org/d' } });
    const [i] = scanAtlas({ bundle: bundle([e]), listPrograms: () => [prog()], ...deps({ ...valid, thumbprint: OTHER_TP }) });
    expect(i).toMatchObject({ risk: 'caution', op: 'report_only' });
    expect(i!.instructions).toContain('Vendor dispute (open): https://example.org/d');
    expect(i!.title).toContain('vendor dispute open');
    expect(i!.instructions).toMatch(/Settings > Apps > Installed apps/);
    expect(i!.uninstall).toBeUndefined();
  });
});

describe('uninstall rules', () => {
  const msiEntry = (codes: string[] = []) => entry({ uninstall: { command_source: 'msi-product-code', msi_product_codes: codes } });

  it('MSI command comes only from the product code, never from UninstallString', () => {
    const p = prog({ keyName: GUID, msiProductCode: GUID, uninstallString: 'cmd.exe /c evil & MsiExec.exe /X{...}' });
    expect(buildUninstall(p, msiEntry([GUID]), deps())).toEqual({ entryId: 'kr.example.clipdown', kind: 'msi', file: 'C:\\Windows\\System32\\msiexec.exe', args: ['/x', GUID], signers: [] });
    expect(buildUninstall(p, msiEntry(), deps())).toMatchObject({ kind: 'msi' }); // none listed, key matched
    expect(buildUninstall(p, msiEntry(['{99999999-2222-3333-4444-555555555555}']), deps())).toHaveProperty('reason');
    expect(buildUninstall(prog({ msiProductCode: undefined }), msiEntry(), deps())).toHaveProperty('reason');
    expect(buildUninstall({ ...p, publisher: 'Other' }, msiEntry(), deps())).toHaveProperty('reason'); // no list, key does not match
  });

  it('rejects shells, metacharacters, wrong names, missing files, bad signatures', () => {
    const e = entry();
    const reason = (uninstallString: string, d: object = deps()) => (buildUninstall(prog({ uninstallString }), e, d) as { reason?: string }).reason;
    expect(reason('cmd.exe /c "C:\\Program Files\\Clipdown\\uninst.exe"')).toMatch(/cmd\.exe/);
    expect(reason('C:\\Windows\\System32\\cmd.exe /c del x')).toMatch(/cmd\.exe/);
    expect(reason('rundll32.exe C:\\x.dll,Uninstall')).toMatch(/rundll32/);
    expect(reason('"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -c x')).toMatch(/powershell/);
    expect(reason(`"${UNINST}" & calc`)).toMatch(/metacharacters/);
    expect(reason(`"${UNINST}" | x`)).toMatch(/metacharacters/);
    expect(reason(`"${UNINST}" ^x`)).toMatch(/metacharacters/);
    expect(reason('"%NOPE%\\uninst.exe"')).toMatch(/VARIABLE/);
    expect(reason('"C:\\Program Files\\Clipdown\\other.exe"')).toMatch(/not the one/);
    expect(reason('"uninst.exe"')).toMatch(/absolute/);
    expect(reason('"\\\\server\\share\\uninst.exe"')).toMatch(/absolute/);
    expect(reason(`"${UNINST}" _?=C:\\Users\\alice`)).toMatch(/_\?=/);
    expect(reason(`"${UNINST}" /log C:\\Users\\alice\\x`)).toMatch(/outside/);
    expect(reason(`"${UNINST}"`, { ...deps(), exists: () => false })).toMatch(/not found/);
    expect(reason(`"${UNINST}"`, deps({ ...valid, status: 'HashMismatch' }))).toMatch(/HashMismatch/);
    expect(reason(`"${UNINST}"`, deps({ ...valid, thumbprint: OTHER_TP }))).toMatch(/not a certificate/);
    expect(reason(`"${UNINST}"`, { ...deps(), signerOf: () => undefined })).toMatch(/unreadable/);
    expect(reason(`"${UNINST}" /S "C:\\Program Files\\Clipdown\\log.txt"`)).toBeUndefined();
    expect(reason('C:\\Program Files\\Clipdown\\uninst.exe /S')).toBeUndefined();
  });

  it('HKCU keys pass only with a pinned signature', () => {
    const p = prog({ hive: 'HKCU' });
    expect(buildUninstall(p, entry(), deps())).toMatchObject({ kind: 'exe' });
    expect(buildUninstall(p, entry(), deps({ ...valid, thumbprint: OTHER_TP }))).toHaveProperty('reason');
  });

  it('parses quoted and unquoted strings and expands variables', () => {
    expect(parseUninstallString('"%ProgramFiles%\\A B\\u.exe" /S "x y"', { ProgramFiles: 'C:\\Program Files' })).toEqual({ file: 'C:\\Program Files\\A B\\u.exe', args: ['/S', 'x y'] });
    expect(parseUninstallString('C:\\A B\\u.exe /S')).toEqual({ file: 'C:\\A B\\u.exe', args: ['/S'] });
  });
});

describe('runUninstall', () => {
  const b: AtlasBundle = { schema: 2, bundle_seq: 1, created: '2026-09-26', entries: [entry()] };

  it('runs the checked command without a shell and maps exit codes', () => {
    const [item] = scanAtlas({ bundle: b, listPrograms: () => [prog()], ...deps() });
    let installed = true;
    const calls: [string, string[]][] = [];
    const spawn = (f: string, a: string[]) => { calls.push([f, a]); installed = false; return { status: 3010 }; };
    const r = runUninstall(item!, { bundle: b, listPrograms: () => (installed ? [prog()] : []), spawn, ...deps() });
    expect(calls).toEqual([[UNINST, []]]);
    expect(r).toMatchObject({ ok: true, code: 3010, rebootRequired: true, stillInstalled: false });
    const cancel = runUninstall(item!, { bundle: b, listPrograms: () => [prog()], spawn: () => ({ status: 1602 }), ...deps() });
    expect(cancel).toMatchObject({ ok: false, code: 1602, stillInstalled: true });
    expect(cancel.detail).toMatch(/cancelled/);
  });

  it('refuses when the signature changed between scan and apply', () => {
    const [item] = scanAtlas({ bundle: b, listPrograms: () => [prog()], ...deps() });
    let spawned = false;
    const spawn = () => { spawned = true; return { status: 0 }; };
    for (const signer of [{ ...valid, thumbprint: OTHER_TP }, { ...valid, status: 'NotSigned' }]) {
      const r = runUninstall(item!, { bundle: b, listPrograms: () => [prog()], spawn, ...deps(signer) });
      expect(r.ok).toBe(false);
      expect(r.detail).toMatch(/^refused/);
    }
    // uninstall key rewritten to another command, program gone, entry gone
    expect(runUninstall(item!, { bundle: b, listPrograms: () => [prog({ uninstallString: `"${UNINST}" /S` })], spawn, ...deps() }).detail).toMatch(/changed/);
    expect(runUninstall(item!, { bundle: b, listPrograms: () => [], spawn, ...deps() }).detail).toMatch(/no longer listed/);
    expect(runUninstall(item!, { bundle: { ...b, entries: [] }, listPrograms: () => [prog()], spawn, ...deps() }).detail).toMatch(/not in the installed bundle/);
    expect(runUninstall(item!, { bundle: b, listPrograms: () => [prog({ publisher: 'Other' })], spawn, ...deps({ ...valid, status: 'NotSigned' }) }).detail).toMatch(/no longer matches/);
    expect(spawned).toBe(false);
  });
});

describe('signature cache', () => {
  it('looks a file up once, and again only after it changes', async () => {
    const { cachedSigners } = await import('../src/atlas/match.ts');
    const fsm = await import('node:fs'), osm = await import('node:os'), pm = await import('node:path');
    const dir = fsm.mkdtempSync(pm.join(osm.tmpdir(), 'hb-sc-'));
    const f = pm.join(dir, 'a.exe');
    fsm.writeFileSync(f, 'x');
    let calls = 0;
    const inner = (files: string[]) => { calls += files.length; return new Map(files.map((x) => [x, { status: 'Valid', subject: 'CN=A' }])); };
    const look = cachedSigners(dir, inner);
    expect(look([f]).get(f)?.subject).toBe('CN=A');
    look([f]);
    expect(calls).toBe(1);
    fsm.writeFileSync(f, 'changed');
    look([f]);
    expect(calls).toBe(2);
    fsm.rmSync(dir, { recursive: true, force: true });
  });
});
