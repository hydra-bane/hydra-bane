import os from 'node:os';
import path from 'node:path';
import type { GuardPolicy } from '../guard/decide.ts';
import { buildProtectedPaths } from '../guard/protected.ts';
import type { RunDeps } from '../atlas/uninstall.ts';

export interface Confirmer {
  /** Ask the human: through the AI agent (--yes after approval) or an interactive terminal (PLAN.md §6.4). */
  confirm(summary: string, planHash: string): Promise<boolean>;
}

export interface Context {
  stateDir: string;      // %LOCALAPPDATA%\hydra-bane
  tempDir: string;       // user %TEMP%
  home: string;          // user profile
  /** Runs a constant tool query (e.g. 'pip cache dir') and returns trimmed stdout, or undefined if the tool is missing. */
  locate: (command: string) => string | undefined;
  roots: string[];       // project roots for build artifacts (--root)
  protectedPaths: string[];
  sid: string;
  now: () => Date;
  confirmer: Confirmer;
  /** Runs an external tool; injectable so tests never touch real caches. */
  run: (file: string, args: string[]) => { status: number | null; stderr: string };
  /** Where to quarantine an item from this path. Defaults to <drive>:\.hydra-bane-quarantine\<SID>. Tests override it. */
  quarantineBaseFor?: (target: string) => string;
  /** Whether a process image (e.g. chrome.exe) is running. Defaults to tasklist; tests override it. */
  isRunning?: (exe: string) => boolean;
  /** Overrides for the vendor-uninstaller path (program list, signer lookup, spawn); tests only. */
  uninstallDeps?: Partial<Omit<RunDeps, 'bundle'>>;
}

export const defaultRoots = (home = os.homedir()) => ['source', 'dev', 'projects', 'repos'].map((d) => path.join(home, d));

export function policyFor(ctx: Pick<Context, 'protectedPaths'>, allow: string[]): GuardPolicy {
  return { protectedPaths: ctx.protectedPaths, allowRoots: { disk: allow, atlas: [], purge: [] } };
}

export const defaultProtected = () => buildProtectedPaths();
