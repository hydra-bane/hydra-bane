import { createHash } from 'node:crypto';
import type { Program } from './programs.ts';
import type { Signer } from './report.ts';

// Atlas entry format, schema 2 (PLAN.md §7.1, revised 2026-09-26): one JSON file per program in hydra-bane/atlas
// `entries/`. The Atlas states facts, never verdicts: what the program is and why people have it (identification),
// how to find and remove it, and third-party advisories with the versions they cover. What the program does on a
// given PC (root certificates, local servers, services) is measured on that PC by the client (atlas/facts.ts).
// There is no shell-command field by design.

export const SOURCE_KINDS = ['security-research', 'vendor', 'government', 'news', 'regulator', 'package-manifest'] as const;
export const ADVISORY_PUBLISHERS = ['KISA', 'NVD', 'EUVD', 'CISA', 'JVN', 'CERT-FR', 'BSI', 'NCSC', 'vendor', 'other'] as const;

export interface Advisory {
  publisher: (typeof ADVISORY_PUBLISHERS)[number];
  url: string;
  date: string;
  title: string;
  /** CVE ids, when the advisory has them. */
  cve?: string[];
  /**
   * Versions the advisory covers, as published: a range (optional inclusive lower bound `from`, upper bound `up_to`)
   * or a list of individual `versions`. Omitted: the advisory names no versions.
   */
  affected?: { from?: string; up_to?: string; inclusive?: boolean; versions?: string[] };
  /** Listed in CISA's Known Exploited Vulnerabilities catalog. */
  kev?: boolean;
}

export interface AtlasEntry {
  schema: 2;
  id: string;                                   // cc.vendor.product; never changes
  names: string[];
  vendor: { name: string; country?: string };
  /** Neutral, sourced description of what it is and why people have it. No verdicts. */
  context: string;
  tags: { countries: string[]; kind?: string };
  detect: {
    /** Subject patterns (* wildcard) and, when known, exact certificate thumbprints. */
    signers: { subject: string; thumbprints: string[] }[];
    /** Regex on DisplayName plus exact Publisher. At least one signer or uninstall key is required. */
    uninstall_keys: { display_name: string; publisher?: string }[];
    /** Subject substrings of root certificates this program is known to install; presence is measured per PC. */
    root_certs: string[];
  };
  uninstall: {
    command_source: 'msi-product-code' | 'signed-exe';
    msi_product_codes: string[];
    /** For signed-exe: the uninstaller file name, relative to InstallLocation or taken from UninstallString. */
    exe_name?: string;
  };
  residue: 'report-only';
  reversible: 'reinstall-only';
  reinstall_note?: string;
  /** Sources for the identification and the context sentence. */
  sources: { url: string; kind: (typeof SOURCE_KINDS)[number]; date: string; title?: string }[];
  advisories: Advisory[];
  source: 'original' | 'win11debloat' | 'loldrivers';
  vendor_response: { url: string; date: string }[];
  dispute: { status: 'none' | 'open' | 'upheld' | 'rejected'; url?: string };
  verified: boolean;
  verified_by: null | 'bootstrap' | 'maintainers';
  added: string;
  last_reviewed: string;
}

export interface AtlasBundle { schema: 2; bundle_seq: number; created: string; entries: AtlasEntry[] }

const ID = /^[a-z]{2}\.[a-z0-9-]+\.[a-z0-9-]+$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
export const GUID = /^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$/i;
const VERSION = /^\d+(?:[.,]\d+)*$/;
// Our own fields carry no verdicts (PLAN.md §7.2): these words may appear only inside quoted advisory titles.
export const VERDICT_WORDS = /\b(malware|virus|scam|spyware|trojan|adware|pup|junk|bloatware|crapware|vulnerable|insecure|dangerous)\b|사기|악성|취약|위험/i;
const TOP_KEYS = ['schema', 'id', 'names', 'vendor', 'context', 'tags', 'detect', 'uninstall', 'residue', 'reversible', 'reinstall_note', 'sources', 'advisories', 'source', 'vendor_response', 'dispute', 'verified', 'verified_by', 'added', 'last_reviewed'];
const https = (u: unknown) => typeof u === 'string' && /^https:\/\/[^\s]+$/.test(u);

/** Returns problems; an empty list means the entry may be used. The client runs this on every bundle entry. */
export function validateEntry(e: unknown): string[] {
  const p: string[] = [];
  if (!e || typeof e !== 'object' || Array.isArray(e)) return ['entry is not an object'];
  const x = e as Record<string, any>;
  for (const k of Object.keys(x)) if (!TOP_KEYS.includes(k)) p.push(`unexpected field ${k}`);
  if (x.schema !== 2) p.push('schema must be 2');
  if (typeof x.id !== 'string' || !ID.test(x.id)) p.push('id must look like cc.vendor.product');
  if (!Array.isArray(x.names) || !x.names.length || !x.names.every((n: unknown) => typeof n === 'string' && n.length > 0 && n.length <= 120)) p.push('names');
  if (typeof x.vendor?.name !== 'string' || !x.vendor.name) p.push('vendor.name');
  if (typeof x.context !== 'string' || x.context.length < 10 || x.context.length > 400) p.push('context: one neutral sentence (10-400 chars)');
  if (!Array.isArray(x.tags?.countries) || !x.tags.countries.length || !x.tags.countries.every((c: any) => /^[A-Z]{2}$/.test(c))) p.push('tags.countries');
  const signers = x.detect?.signers, keys = x.detect?.uninstall_keys, certs = x.detect?.root_certs;
  if (!Array.isArray(signers) || !Array.isArray(keys) || !Array.isArray(certs)) p.push('detect.signers, detect.uninstall_keys and detect.root_certs must be lists');
  else {
    if (!signers.length && !keys.length) p.push('detect needs a signer or an uninstall key (file names alone are not accepted)');
    for (const s of signers) if (typeof s?.subject !== 'string' || !s.subject || !Array.isArray(s.thumbprints) || !s.thumbprints.every((t: any) => /^[0-9A-F]{40}$/i.test(t))) p.push('detect.signers entry');
    for (const k of keys) {
      if (typeof k?.display_name !== 'string' || !k.display_name) { p.push('detect.uninstall_keys entry'); continue; }
      try { new RegExp(k.display_name, 'i'); } catch { p.push(`bad display_name regex ${k.display_name}`); }
    }
    if (!certs.every((c: any) => typeof c === 'string' && c.length >= 4 && c.length <= 200)) p.push('detect.root_certs entries must be subject substrings of 4-200 chars');
  }
  const u = x.uninstall;
  if (!u || !['msi-product-code', 'signed-exe'].includes(u.command_source)) p.push('uninstall.command_source');
  else {
    if (!Array.isArray(u.msi_product_codes) || !u.msi_product_codes.every((g: any) => GUID.test(g))) p.push('uninstall.msi_product_codes');
    if (u.command_source === 'signed-exe' && (typeof u.exe_name !== 'string' || !/^[\w .()-]+\.exe$/i.test(u.exe_name))) p.push('uninstall.exe_name must be a plain .exe file name');
    if (u.command_source === 'signed-exe' && !(signers ?? []).some((s: any) => s.thumbprints?.length)) p.push('signed-exe needs at least one signer thumbprint');
  }
  if (x.residue !== 'report-only') p.push('residue must be report-only');
  if (x.reversible !== 'reinstall-only') p.push('reversible must be reinstall-only');
  if (!Array.isArray(x.sources) || !x.sources.length || !x.sources.every((v: any) => https(v?.url) && DATE.test(v.date ?? '') && (SOURCE_KINDS as readonly string[]).includes(v.kind))) p.push('sources: at least one https source with a kind and date');
  if (!Array.isArray(x.advisories)) p.push('advisories must be a list');
  else for (const a of x.advisories) {
    if (!(ADVISORY_PUBLISHERS as readonly string[]).includes(a?.publisher) || !https(a.url) || !DATE.test(a.date ?? '') || typeof a.title !== 'string' || !a.title) { p.push('advisory needs publisher, https url, date and title'); continue; }
    if (a.cve !== undefined && (!Array.isArray(a.cve) || !a.cve.every((c: any) => /^CVE-\d{4}-\d{4,}$/.test(c)))) p.push('advisory.cve');
    if (a.affected !== undefined) {
      const f = a.affected, ver = (v: unknown) => typeof v === 'string' && VERSION.test(v);
      const list = Array.isArray(f.versions) && f.versions.length > 0 && f.versions.every(ver);
      const range = ver(f.up_to) && typeof f.inclusive === 'boolean' && (f.from === undefined || ver(f.from));
      if (!(list && f.up_to === undefined && f.from === undefined && f.inclusive === undefined) && !(range && f.versions === undefined)) p.push('advisory.affected: either versions[] or up_to + inclusive (+ optional from), digits and dots');
    }
    if (a.kev !== undefined && typeof a.kev !== 'boolean') p.push('advisory.kev');
  }
  if (!['original', 'win11debloat', 'loldrivers'].includes(x.source)) p.push('source');
  if (!Array.isArray(x.vendor_response)) p.push('vendor_response');
  if (!['none', 'open', 'upheld', 'rejected'].includes(x.dispute?.status)) p.push('dispute.status');
  if (typeof x.verified !== 'boolean' || ![null, 'bootstrap', 'maintainers'].includes(x.verified_by)) p.push('verified/verified_by');
  if (!DATE.test(x.added ?? '') || !DATE.test(x.last_reviewed ?? '')) p.push('added/last_reviewed dates');
  const own = [x.names, x.vendor?.name, x.context, x.reinstall_note, x.tags?.kind].flat().filter((v) => typeof v === 'string').join(' ');
  if (VERDICT_WORDS.test(own)) p.push('verdict words (malware, vulnerable, 취약, 악성…) are not allowed in our own fields; quote an advisory instead');
  return p;
}

/** Compares dotted versions numerically ("4,0,0,0" = "4.0.0.0"); missing parts count as 0. */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.,]/).map((n) => Number.parseInt(n, 10) || 0), pb = b.split(/[.,]/).map((n) => Number.parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

export type Applies = 'applies' | 'not-applicable' | 'unknown';

/** Whether an advisory covers the installed version. No version range, or no readable installed version: unknown. */
export function advisoryApplies(a: Advisory, installed: string | undefined): Applies {
  const f = a.affected;
  if (!f) return 'unknown';
  const v = installed?.match(/\d+(?:[.,]\d+)+/)?.[0] ?? installed?.match(/\d+/)?.[0]; // "AnySign4PC 1.1.2.6" → 1.1.2.6
  if (!v) return 'unknown';
  if (f.versions) return f.versions.some((x) => compareVersions(v, x) === 0) ? 'applies' : 'not-applicable';
  if (f.from !== undefined && compareVersions(v, f.from) < 0) return 'not-applicable';
  const c = compareVersions(v, f.up_to!);
  return c < 0 || (c === 0 && f.inclusive) ? 'applies' : 'not-applicable';
}

/** The published version scope in words, e.g. "from 1.1.4.4 up to and including 1.1.4.6". */
export function describeAffected(f: NonNullable<Advisory['affected']>): string {
  if (f.versions) return `versions ${f.versions.join(', ')}`;
  return `versions ${f.from !== undefined ? `from ${f.from} ` : ''}${f.inclusive ? 'up to and including' : 'before'} ${f.up_to}`;
}

// --- detection helpers ---

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export const subjectMatches = (pattern: string, subject: string) => new RegExp(`^${pattern.split('*').map(escapeRe).join('.*')}$`, 'i').test(subject);

/** DisplayName regex (case-insensitive) and, when the entry names one, the exact Publisher. */
export function keyMatches(e: AtlasEntry, p: Program): boolean {
  return e.detect.uninstall_keys.some((k) => {
    let re: RegExp;
    try { re = new RegExp(k.display_name, 'i'); } catch { return false; }
    return re.test(p.name) && (!k.publisher || (p.publisher ?? '').trim().toLowerCase() === k.publisher.trim().toLowerCase());
  });
}

/** Upper-case thumbprints the entry pins; the only certificates a vendor uninstaller may be signed with. */
export const entryThumbprints = (e: AtlasEntry) => e.detect.signers.flatMap((s) => s.thumbprints.map((t) => t.toUpperCase()));

/** A valid Authenticode signature whose thumbprint is pinned or whose subject matches a pattern. */
export function signerMatches(e: AtlasEntry, s: Signer | undefined): boolean {
  if (s?.status !== 'Valid') return false;
  const tp = s.thumbprint?.toUpperCase();
  return (!!tp && entryThumbprints(e).includes(tp)) || (!!s.subject && e.detect.signers.some((x) => subjectMatches(x.subject, s.subject!)));
}

/** Stable scan item id: the same entry on the same uninstall key always gets the same id. */
export const atlasItemId = (entryId: string, programId: string) => `ATLAS-${createHash('sha1').update(`${entryId}|${programId}`).digest('hex').slice(0, 6)}`;

/** Atlas items are never selected by default and never 'safe' (PLAN.md §7.5). */
export const selectableByDefault = (_e: AtlasEntry) => false;
