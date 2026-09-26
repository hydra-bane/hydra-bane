import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { Context } from '../../src/core/context.ts';

/** Fresh test folder on HYDRA_BANE_TEST_VOLUME (the CI VHDX, e.g. X:\) when set, else in os.tmpdir(). */
export function testRoot(prefix: string): string {
  const vol = process.env.HYDRA_BANE_TEST_VOLUME;
  const parent = vol ? path.join(vol, 'hb-tests') : os.tmpdir();
  fs.mkdirSync(parent, { recursive: true });
  return fs.realpathSync.native(fs.mkdtempSync(path.join(parent, prefix)));
}

/** Sandbox context shared by the crash test and its child process, so both see the same ledger and quarantine. */
export const crashCtx = (root: string): Context => ({
  stateDir: path.join(root, 'state'),
  tempDir: path.join(root, 'temp'),
  home: path.join(root, 'home'),
  locate: () => undefined,
  roots: [path.join(root, 'work')],
  protectedPaths: [path.join(root, 'protected')],
  sid: 'S-1-5-21-crash',
  now: () => new Date(),
  confirmer: { confirm: async () => true },
  run: () => ({ status: 0, stderr: '' }),
  quarantineBaseFor: () => path.join(root, 'quarantine'),
  isRunning: () => false,
});
