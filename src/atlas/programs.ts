import crypto from 'node:crypto';
import { regQuery, type RegValue } from '../guard/protected.ts';

// Installed programs from the Uninstall registry keys (read-only). Input for Atlas matching and user reports (PLAN.md §7.7).

const UNINSTALL = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall';
export const UNINSTALL_ROOTS: { hive: 'HKLM' | 'HKCU'; view: '64' | '32'; key: string }[] = [
  { hive: 'HKLM', view: '64', key: `HKLM\\${UNINSTALL}` },
  { hive: 'HKLM', view: '32', key: `HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall` },
  { hive: 'HKCU', view: '64', key: `HKCU\\${UNINSTALL}` },
];

export interface Program {
  id: string;                 // P-<hash6> of hive/view/key name: stable across runs
  name: string;
  publisher?: string | undefined;
  version?: string | undefined;
  hive: 'HKLM' | 'HKCU';
  view: '64' | '32';
  keyName: string;
  installLocation?: string | undefined;
  uninstallString?: string | undefined;
  quietUninstallString?: string | undefined;
  displayIcon?: string | undefined;
  msiProductCode?: string | undefined;
  estimatedBytes?: number | undefined;
  installDate?: string | undefined;
}

export type RegQuery = (key: string, recursive?: boolean) => RegValue[];

const UPDATE_TYPES = /^(update|hotfix|security update|service pack)$/i;

export function listPrograms(query: RegQuery = regQuery): Program[] {
  const out: Program[] = [];
  for (const root of UNINSTALL_ROOTS) {
    const byKey = new Map<string, Map<string, string>>();
    for (const v of query(root.key, true)) {
      const name = v.key.split(/\\Uninstall\\/i)[1]; // reg.exe prints HKEY_LOCAL_MACHINE\..., not HKLM\...
      if (!name || name.includes('\\')) continue; // values of the root itself or of nested subkeys
      if (!byKey.has(name)) byKey.set(name, new Map());
      byKey.get(name)!.set(v.name.toLowerCase(), v.data);
    }
    for (const [keyName, vals] of byKey) {
      const get = (n: string) => vals.get(n.toLowerCase())?.trim() || undefined;
      const name = get('DisplayName');
      if (!name || get('SystemComponent') === '0x1' || get('ParentKeyName') || UPDATE_TYPES.test(get('ReleaseType') ?? '')) continue;
      const kb = get('EstimatedSize');
      out.push({
        id: `P-${crypto.createHash('sha256').update(`${root.hive}|${root.view}|${keyName.toLowerCase()}`).digest('hex').slice(0, 6)}`,
        name, publisher: get('Publisher'), version: get('DisplayVersion'), hive: root.hive, view: root.view, keyName,
        installLocation: get('InstallLocation'), uninstallString: get('UninstallString'), quietUninstallString: get('QuietUninstallString'),
        displayIcon: get('DisplayIcon'),
        msiProductCode: get('WindowsInstaller') === '0x1' && /^\{[0-9a-f-]{36}\}$/i.test(keyName) ? keyName.toUpperCase() : undefined,
        estimatedBytes: kb ? Number.parseInt(kb, 16) * 1024 : undefined,
        installDate: get('InstallDate'),
      });
    }
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}
