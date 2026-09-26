// Atlas entry format (PLAN.md §7.1), stored as one JSON file per entry in hydra-bane/atlas `entries/`.
// JSON instead of the YAML sketched in the plan: no parser dependency, and the same shape is validated
// by the atlas repo CI and again by this client (§7.2). There is no shell-command field by design.

export const CATEGORIES = ['advertising', 'torrent', 'cryptomining', 'bundling', 'marketing', 'evasion', 'poor-industry-reputation', 'vulnerable-software', 'vulnerable-driver'] as const;
export const CRITERIA = ['ms-unwanted:lack-of-choice', 'ms-unwanted:lack-of-control', 'ms-unwanted:installation-and-removal', 'ms-unwanted:advertising'] as const;
export const FLAGS = ['required_by_service', 'root_cert', 'orphan_driver', 'data_collection'] as const;

export interface AtlasEntry {
  schema: 1;
  id: string;                                   // reverse-domain style, e.g. kr.raonsecure.touchen-nxkey; never changes
  names: string[];
  vendor: { name: string; country?: string };
  category: (typeof CATEGORIES)[number][];      // may be empty: listed as "optional to remove" without a label
  criteria_refs: (typeof CRITERIA)[number][];
  tags: { countries: string[]; kind?: string; flags: (typeof FLAGS)[number][] };
  removal_recommendation: 'recommended' | 'optional' | 'not-recommended';
  detect: {
    /** Subject patterns (* wildcard) and, when known, exact certificate thumbprints. */
    signers: { subject: string; thumbprints: string[] }[];
    /** Regex on DisplayName plus exact Publisher. At least one signer or uninstall key is required. */
    uninstall_keys: { display_name: string; publisher?: string }[];
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
  evidence: { url: string; kind: 'security-research' | 'vendor' | 'government' | 'news' | 'regulator'; date: string; title?: string }[];
  source: 'original' | 'win11debloat' | 'loldrivers';
  vendor_response: { url: string; date: string }[];
  dispute: { status: 'none' | 'open' | 'upheld' | 'rejected'; url?: string };
  verified: boolean;
  verified_by: null | 'bootstrap' | 'maintainers';
  added: string;
  last_reviewed: string;
}

export interface AtlasBundle { schema: 1; bundle_seq: number; created: string; entries: AtlasEntry[] }

const ID = /^[a-z]{2}\.[a-z0-9-]+\.[a-z0-9-]+$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const GUID = /^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$/i;
// PLAN.md §7.2 lint: verdict words only inside quotes, never in our own fields.
const VERDICT_WORDS = /\b(malware|virus|scam|spyware|trojan)\b|사기|악성/i;
const TOP_KEYS = ['schema', 'id', 'names', 'vendor', 'category', 'criteria_refs', 'tags', 'removal_recommendation', 'detect', 'uninstall', 'residue', 'reversible', 'reinstall_note', 'evidence', 'source', 'vendor_response', 'dispute', 'verified', 'verified_by', 'added', 'last_reviewed'];

/** Returns problems; an empty list means the entry may be used. The client runs this on every bundle entry. */
export function validateEntry(e: unknown): string[] {
  const p: string[] = [];
  if (!e || typeof e !== 'object' || Array.isArray(e)) return ['entry is not an object'];
  const x = e as Record<string, any>;
  for (const k of Object.keys(x)) if (!TOP_KEYS.includes(k)) p.push(`unexpected field ${k}`);
  if (x.schema !== 1) p.push('schema must be 1');
  if (typeof x.id !== 'string' || !ID.test(x.id)) p.push('id must look like cc.vendor.product');
  if (!Array.isArray(x.names) || !x.names.length || !x.names.every((n: unknown) => typeof n === 'string' && n.length > 0 && n.length <= 120)) p.push('names');
  if (typeof x.vendor?.name !== 'string' || !x.vendor.name) p.push('vendor.name');
  if (!Array.isArray(x.category) || !x.category.every((c: any) => (CATEGORIES as readonly string[]).includes(c))) p.push('category must use Microsoft PUA terms');
  if (!Array.isArray(x.criteria_refs) || !x.criteria_refs.every((c: any) => (CRITERIA as readonly string[]).includes(c))) p.push('criteria_refs');
  if (!Array.isArray(x.tags?.countries) || !x.tags.countries.length || !x.tags.countries.every((c: any) => /^[A-Z]{2}$/.test(c))) p.push('tags.countries');
  if (!Array.isArray(x.tags?.flags) || !x.tags.flags.every((f: any) => (FLAGS as readonly string[]).includes(f))) p.push('tags.flags');
  if (!['recommended', 'optional', 'not-recommended'].includes(x.removal_recommendation)) p.push('removal_recommendation');
  const signers = x.detect?.signers, keys = x.detect?.uninstall_keys;
  if (!Array.isArray(signers) || !Array.isArray(keys)) p.push('detect.signers and detect.uninstall_keys must be lists');
  else {
    if (!signers.length && !keys.length) p.push('detect needs a signer or an uninstall key (file names alone are not accepted)');
    for (const s of signers) if (typeof s?.subject !== 'string' || !s.subject || !Array.isArray(s.thumbprints) || !s.thumbprints.every((t: any) => /^[0-9A-F]{40}$/i.test(t))) p.push('detect.signers entry');
    for (const k of keys) {
      if (typeof k?.display_name !== 'string' || !k.display_name) { p.push('detect.uninstall_keys entry'); continue; }
      try { new RegExp(k.display_name, 'i'); } catch { p.push(`bad display_name regex ${k.display_name}`); }
    }
  }
  const u = x.uninstall;
  if (!u || !['msi-product-code', 'signed-exe'].includes(u.command_source)) p.push('uninstall.command_source');
  else {
    if (!Array.isArray(u.msi_product_codes) || !u.msi_product_codes.every((g: any) => GUID.test(g))) p.push('uninstall.msi_product_codes');
    if (u.command_source === 'signed-exe' && (typeof u.exe_name !== 'string' || !/^[\w .()-]+\.exe$/i.test(u.exe_name))) p.push('uninstall.exe_name must be a plain .exe file name');
    if (u.command_source === 'signed-exe' && !(signers ?? []).some((s: any) => s.thumbprints?.length)) p.push('signed-exe needs at least one signer thumbprint');
  }
  if (x.residue !== 'report-only') p.push('residue must be report-only in v0.2');
  if (x.reversible !== 'reinstall-only') p.push('reversible must be reinstall-only');
  if (!Array.isArray(x.evidence) || !x.evidence.length || !x.evidence.every((v: any) => typeof v?.url === 'string' && /^https:\/\//.test(v.url) && DATE.test(v.date ?? ''))) p.push('evidence: at least one https source with a date');
  if (!['original', 'win11debloat', 'loldrivers'].includes(x.source)) p.push('source');
  if (!Array.isArray(x.vendor_response)) p.push('vendor_response');
  if (!['none', 'open', 'upheld', 'rejected'].includes(x.dispute?.status)) p.push('dispute.status');
  if (typeof x.verified !== 'boolean' || ![null, 'bootstrap', 'maintainers'].includes(x.verified_by)) p.push('verified/verified_by');
  if (!DATE.test(x.added ?? '') || !DATE.test(x.last_reviewed ?? '')) p.push('added/last_reviewed dates');
  const own = [x.names, x.vendor?.name, x.reinstall_note, x.tags?.kind].flat().filter((v) => typeof v === 'string').join(' ');
  if (VERDICT_WORDS.test(own)) p.push('verdict words (malware, scam, 악성, 사기…) are not allowed outside quoted evidence');
  return p;
}

/** Entries with an open dispute are never selected by default (PLAN.md §7.5). */
export const selectableByDefault = (e: AtlasEntry) => e.dispute.status !== 'open' && e.removal_recommendation === 'recommended';
