// Child process for test/crash.test.ts: `node crash-child.ts apply|undo <root> <planId|tx>`.
// The parent sets HYDRA_BANE_TEST_KILL_AT so this process dies (exit 137) at the chosen point.
import { apply, undo } from '../../src/core/apply.ts';
import { crashCtx } from './crash-ctx.ts';

const [mode, root, id] = process.argv.slice(2);
const ctx = crashCtx(root!);
const r = mode === 'undo' ? await undo(ctx, id!) : await apply(ctx, id!);
process.stdout.write(JSON.stringify(r));
