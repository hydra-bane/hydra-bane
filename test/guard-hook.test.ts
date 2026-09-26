import { Readable } from 'node:stream';
import { describe, expect, it, vi } from 'vitest';
import { judge, runHook } from '../src/hook/guard-hook.ts';

// Command corpus with expected verdicts (PLAN.md §6.10). Extend this list whenever a bypass is found.
const CASES: Array<[string, 'ask' | 'deny' | 'allow']> = [
  ['hydra-bane apply lx3k9a2b', 'ask'],
  ['npx -y hydra-bane@0.1.0 apply lx3k9a2b --yes', 'ask'],
  ['hydra-bane undo lx3k9a2b --yes', 'ask'],
  ['hydra-bane scan --json', 'allow'],
  ['hydra-bane plan --select C1,T1', 'allow'],

  [`rm -rf "$(cygpath -u 'C:\\')" 2>/dev/null`, 'deny'], // anthropics/claude-code#95426
  ['rm -rf /c/', 'deny'],
  ['rm -rf ~', 'deny'],
  ['rm -rf /', 'deny'],
  ['rm -rf $HOME/projects', 'deny'],
  ['rd /s /q C:\\', 'deny'],
  ['rmdir /s /q %USERPROFILE%', 'deny'],
  ['del /s /q C:\\Users\\alice', 'deny'],
  ['Remove-Item -Recurse -Force C:\\Users\\alice\\Documents', 'deny'],
  ['ri -r -fo $env:USERPROFILE\\Desktop', 'deny'],
  ['powershell -EncodedCommand ZABlAGwAIAAtAHIA', 'ask'],
  ['pwsh.exe -NoProfile -enc ZABlAGwA', 'ask'],
  ['robocopy C:\\empty C:\\Users\\alice /MIR', 'deny'],
  ['Remove-Item -Recurse "C:\\Program Files\\App"', 'deny'],

  ['rm -rf node_modules', 'allow'],
  ['rm -rf ./dist build', 'allow'],
  ['Remove-Item -Recurse -Force .\\target', 'allow'],
  ['git status', 'allow'],
  ['ls C:\\', 'allow'],
];

describe('guard hook', () => {
  it.each(CASES)('%s -> %s', (cmd, expected) => {
    expect(judge(cmd)?.decision ?? 'allow').toBe(expected);
  });

  it('speaks the PreToolUse protocol', async () => {
    const write = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    await runHook(Readable.from([JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'rm -rf /c/' } })]));
    const out = JSON.parse(String(write.mock.calls[0]?.[0]));
    write.mockRestore();
    expect(out.hookSpecificOutput).toMatchObject({ hookEventName: 'PreToolUse', permissionDecision: 'deny' });
  });

  it('stays silent for unrelated or unparseable input', async () => {
    const write = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    await runHook(Readable.from(['not json']));
    await runHook(Readable.from([JSON.stringify({ tool_name: 'Read', tool_input: { file_path: 'x' } })]));
    expect(write).not.toHaveBeenCalled();
    write.mockRestore();
  });
});
