// PLAN.md §6.10: best-effort PreToolUse guard for agent shells. It is a nudge, not the safety boundary:
// it forces a human prompt for hydra-bane apply/undo/purge and blocks common recursive deletes aimed at
// drive roots, profile/known folders, or paths the hook cannot see because they are computed at runtime.

import { describeAction } from './describe.ts';

export type Verdict = { decision: 'ask' | 'deny'; reason: string } | undefined;

// Only an actual invocation counts: at the start of a command segment, optionally via npx or a path.
// Mentions inside quoted text or heredoc bodies (commit messages, docs) must not trigger a prompt.
const HB_MUTATING = /(?:^|[;&|\n(]\s*)(?:npx\s+(?:-y\s+)?)?(?:[^\s;&|]*[\\/])?hydra-bane(?:@[\w.-]+)?(?:\.cmd|\.ps1)?\s+(apply|undo|purge)\b(?:\s+([a-z0-9]+))?/i;
// Sending a report publishes data about this PC, so it gets the same prompt (PLAN.md §7.7).
const HB_REPORT_SUBMIT = /(?:^|[;&|\n(]\s*)(?:npx\s+(?:-y\s+)?)?(?:[^\s;&|]*[\\/])?hydra-bane(?:@[\w.-]+)?(?:\.cmd|\.ps1)?\s+(report)\s+([\w-]+)\b[^;&|\n]*\s--submit\b/i;

/** Remove heredoc bodies and quoted strings so only the command structure is inspected. */
export function commandSkeleton(command: string): string {
  let s = command.replace(/<<-?\s*['"]?(\w+)['"]?[^\n]*\n[\s\S]*?\n\s*\1\s*(?:\n|$)/g, '\n');
  s = s.replace(/'[^']*'/g, "''").replace(/"(?:[^"\\]|\\.)*"/g, '""');
  return s.trim();
}
const NESTED_SHELL = /\b(?:bash|sh|zsh|dash|cmd|powershell|pwsh|node|python3?|wsl)(?:\.exe)?\b[^|;&]*\s(?:-c|\/c|\/k|-command|-e|--eval)\b/i;
const OPAQUE =/\b(?:powershell|pwsh)(?:\.exe)?\b[^|;&]*\s-e(?:nc(?:odedcommand)?)?\s/i; // payload the hook cannot read

const RECURSIVE_DELETE = [
  /\brm\s+(?:-[a-z]*r[a-z]*|--recursive)\b/i,           // rm -r / -rf / -fr / --recursive
  /\b(?:rd|rmdir)\s+(?:\/[sq]\s*)*\/s\b/i,               // rd /s, rmdir /s /q
  /\bdel\s+(?:\/[a-z]\s*)*\/s\b/i,                       // del /s
  /\b(?:remove-item|ri|rm|del|erase|rd|rmdir)\b[^|;&]*\s-r(?:ecurse)?\b/i, // PowerShell Remove-Item -Recurse and aliases
  /\brobocopy\b[^|;&]*\s\/mir\b/i,
  /\bgit\s+clean\s+-[a-z]*[fdx][a-z]*/i,
  /\bshutil\.rmtree\b|\.rm(?:dir)?(?:Sync)?\s*\([^)]*recursive/i,    // python shutil, node fs.rm/rmdir(…, {recursive})
];

// Targets whose resolution the hook cannot trust, or that are always catastrophic.
const DANGEROUS_TARGET = [
  /\$\(|`/,                                  // command substitution (anthropics/claude-code#95426)
  /%[a-z_]+%|\$env:|\$\{?[a-z_]+\}?/i,        // variables expanded at runtime
  /process\.env\.|os\.homedir\(\)|expanduser\(|Path\.home\(\)|os\.environ/i, // same, from inside node/python one-liners
  /-enc(?:odedcommand)?\b/i,
  /(?:^|[\s"'])(?:[a-z]:[\\/]?|\/[a-z]\/?|\/mnt\/[a-z]\/?|\/cygdrive\/[a-z]\/?|~[\\/]?|\/)(?=$|[\s"'])/i, // drive/home roots
  /[\\/]users[\\/][^\\/\s"']+[\\/]?(?=$|[\s"'])/i,                                                // a whole profile
  /[\\/](?:documents|desktop|pictures|videos|music|onedrive[^\\/\s"']*)[\\/]?(?=$|[\s"'])/i,       // known folders
  /[\\/]windows(?:[\\/]system32)?[\\/]?(?=$|[\s"'])|program files/i,
];

export function judge(command: string, describe: (action: string, id: string | undefined) => string = describeAction): Verdict {
  const m = HB_MUTATING.exec(commandSkeleton(command)) ?? HB_REPORT_SUBMIT.exec(commandSkeleton(command));
  if (m) {
    let what: string;
    try { what = describe(m[1]!, m[2]); } catch { what = `Hydra-bane ${m[1]} ${m[2] ?? ''}`; }
    return { decision: 'ask', reason: `${what}\nApprove only if this is what you want.` };
  }
  if (OPAQUE.test(command)) {
    return { decision: 'ask', reason: 'This PowerShell command is encoded, so its contents cannot be checked. Ask the user before running it.' };
  }
  // The delete verb must be an actual command, not text inside quotes (echo, JSON, commit messages),
  // unless the quotes are themselves executed by a nested shell (bash -c "...", cmd /c "...").
  // Targets are still read from the raw command, because a quoted path is still the path being deleted.
  const skeleton = commandSkeleton(command);
  const verbScope = NESTED_SHELL.test(skeleton) ? command : skeleton;
  if (RECURSIVE_DELETE.some((r) => r.test(verbScope)) && DANGEROUS_TARGET.some((r) => r.test(command))) {
    return {
      decision: 'deny',
      reason: 'Blocked by Hydra-bane: recursive delete of a drive root, profile, system or known folder, or of a path computed at runtime. Use `hydra-bane scan` and `hydra-bane plan` instead, which show the resolved paths and can be undone.',
    };
  }
  return undefined;
}

/** Claude Code / Codex PreToolUse hook protocol: JSON on stdin, JSON decision on stdout. */
export async function runHook(stdin: NodeJS.ReadableStream = process.stdin): Promise<number> {
  let raw = '';
  for await (const chunk of stdin) raw += chunk;
  let command = '';
  try {
    const input = JSON.parse(raw) as { tool_input?: { command?: unknown } };
    command = typeof input.tool_input?.command === 'string' ? input.tool_input.command : '';
  } catch {
    return 0; // not a shell call we understand; do not block unrelated tools
  }
  let v: Verdict;
  try {
    v = judge(command);
  } catch {
    v = { decision: 'deny', reason: 'Hydra-bane guard failed to evaluate this command; blocking to be safe.' }; // fail closed
  }
  if (v) process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: v.decision, permissionDecisionReason: v.reason } }));
  return 0;
}
