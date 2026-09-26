// PLAN.md §6.10: best-effort PreToolUse guard for agent shells. It is a nudge, not the safety boundary:
// it forces a human prompt for hydra-bane apply/undo/purge and blocks common recursive deletes aimed at
// drive roots, profile/known folders, or paths the hook cannot see because they are computed at runtime.

export type Verdict = { decision: 'ask' | 'deny'; reason: string } | undefined;

const HB_MUTATING = /\bhydra-bane(?:@[\w.-]+)?(?:\.cmd|\.ps1)?\s+(apply|undo|purge)\b/i;
const OPAQUE = /\b(?:powershell|pwsh)(?:\.exe)?\b[^|;&]*\s-e(?:nc(?:odedcommand)?)?\s/i; // payload the hook cannot read

const RECURSIVE_DELETE = [
  /\brm\s+(?:-[a-z]*r[a-z]*|--recursive)\b/i,           // rm -r / -rf / -fr / --recursive
  /\b(?:rd|rmdir)\s+(?:\/[sq]\s*)*\/s\b/i,               // rd /s, rmdir /s /q
  /\bdel\s+(?:\/[a-z]\s*)*\/s\b/i,                       // del /s
  /\b(?:remove-item|ri|rm|del|erase|rd|rmdir)\b[^|;&]*\s-r(?:ecurse)?\b/i, // PowerShell Remove-Item -Recurse and aliases
  /\brobocopy\b[^|;&]*\s\/mir\b/i,
  /\bgit\s+clean\s+-[a-z]*[fdx][a-z]*/i,
  /\bshutil\.rmtree\b|\bfs\.rm(?:Sync)?\s*\([^)]*recursive/i,
];

// Targets whose resolution the hook cannot trust, or that are always catastrophic.
const DANGEROUS_TARGET = [
  /\$\(|`/,                                  // command substitution (anthropics/claude-code#95426)
  /%[a-z_]+%|\$env:|\$\{?[a-z_]+\}?/i,        // variables expanded at runtime
  /-enc(?:odedcommand)?\b/i,
  /(?:^|[\s"'])(?:[a-z]:[\\/]?|\/[a-z]\/?|\/mnt\/[a-z]\/?|\/cygdrive\/[a-z]\/?|~[\\/]?|\/)(?=$|[\s"'])/i, // drive/home roots
  /[\\/]users[\\/][^\\/\s"']+[\\/]?(?=$|[\s"'])/i,                                                // a whole profile
  /[\\/](?:documents|desktop|pictures|videos|music|onedrive[^\\/\s"']*)[\\/]?(?=$|[\s"'])/i,       // known folders
  /[\\/]windows(?:[\\/]system32)?[\\/]?(?=$|[\s"'])|program files/i,
];

export function judge(command: string): Verdict {
  if (HB_MUTATING.test(command)) {
    return { decision: 'ask', reason: 'Hydra-bane changes files. Show the user the plan summary and let them approve this command.' };
  }
  if (OPAQUE.test(command)) {
    return { decision: 'ask', reason: 'This PowerShell command is encoded, so its contents cannot be checked. Ask the user before running it.' };
  }
  if (RECURSIVE_DELETE.some((r) => r.test(command)) && DANGEROUS_TARGET.some((r) => r.test(command))) {
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
