import { execFileSync } from 'node:child_process';
import { normalizeWinPath } from './normalize.ts';

// Builds the forbidden set P (PLAN.md §6.3) from this machine: system folders, every user profile,
// every known folder that can be read, and every registered cloud sync root.

const PROFILE_LIST = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList';
const SYNC_ROOTS = 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SyncRootManager';
const SHELL_FOLDERS = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders';
const KNOWN_FOLDER_VALUES = ['Personal', 'Desktop', 'My Pictures', 'My Video', 'My Music', '{374DE290-123F-4565-9164-39C4925E467B}' /* Downloads */];

export interface RegValue { key: string; name: string; type: string; data: string }

export function parseRegQuery(output: string): RegValue[] {
  const values: RegValue[] = [];
  let key = '';
  for (const line of output.split(/\r?\n/)) {
    if (/^HKEY_/.test(line)) { key = line.trim(); continue; }
    const m = /^ {4}(.*?) {4}(REG_\w+) {4}(.*)$/.exec(line);
    if (m) values.push({ key, name: m[1]!, type: m[2]!, data: m[3]! });
  }
  return values;
}

export function regQuery(key: string, recursive = false): RegValue[] {
  try {
    const out = execFileSync('reg.exe', ['query', key, ...(recursive ? ['/s'] : [])], { encoding: 'utf8', windowsHide: true, timeout: 10_000, stdio: ['ignore', 'pipe', 'ignore'] });
    return parseRegQuery(out);
  } catch {
    return [];
  }
}

const expandEnv = (s: string, env: NodeJS.ProcessEnv) => s.replace(/%([^%]+)%/g, (all, name: string) => env[name] ?? all);

export function buildProtectedPaths(env: NodeJS.ProcessEnv = process.env): string[] {
  const raw: string[] = [];
  const add = (p: string | undefined) => { if (p) raw.push(expandEnv(p, env)); };

  for (const v of ['SystemRoot', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432', 'ProgramData', 'PUBLIC']) add(env[v]);
  add(env.SystemDrive && `${env.SystemDrive}\\Users`);
  add(env.SystemDrive && `${env.SystemDrive}\\Recovery`);
  add(env.SystemDrive && `${env.SystemDrive}\\System Volume Information`);

  const profiles = regQuery(PROFILE_LIST, true);
  for (const v of profiles) {
    if (v.name === 'ProfilesDirectory') add(v.data);
    if (v.name === 'ProfileImagePath') add(v.data);
  }

  // Current user's known folders (redirection included). Other users' hives are only readable when loaded:
  // for each loaded SID under HKU we read theirs too.
  const hives = ['HKCU', ...profiles.filter((v) => v.name === 'ProfileImagePath').map((v) => `HKU\\${v.key.split('\\').pop()}`)];
  for (const hive of hives) {
    for (const v of regQuery(`${hive}\\${SHELL_FOLDERS}`)) {
      if (KNOWN_FOLDER_VALUES.includes(v.name)) add(v.data);
    }
  }

  for (const v of regQuery(SYNC_ROOTS, true)) {
    if (/\\UserSyncRoots$/i.test(v.key)) add(v.data);
  }
  add(env.OneDrive);
  add(env.OneDriveConsumer);
  add(env.OneDriveCommercial);

  const out = new Set<string>();
  for (const p of raw) {
    const n = normalizeWinPath(p);
    if (n.ok) out.add(n.path);
  }
  return [...out];
}
