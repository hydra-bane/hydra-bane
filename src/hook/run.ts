import { runHook } from './guard-hook.ts';

process.exitCode = await runHook();
