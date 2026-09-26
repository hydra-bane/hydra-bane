import { isDriveRoot, isSameOrDescendant, normalizeWinPath, type NormalizeError } from './normalize.ts';

// PLAN.md §6.3: three capabilities, one forbidden set P that overrides all of them.
export type Capability = 'disk' | 'atlas' | 'purge';

export interface GuardPolicy {
  /** Forbidden set P. Already normalized absolute paths. */
  protectedPaths: readonly string[];
  /** Allowed roots per capability. Targets must be the root itself or inside it. */
  allowRoots: Readonly<Record<Capability, readonly string[]>>;
}

export type DenyCode =
  | NormalizeError
  | 'DRIVE_ROOT'
  | 'PROTECTED_OR_ANCESTOR'
  | 'SENSITIVE_SEGMENT'
  | 'NOT_ALLOWLISTED';

export type Decision =
  | { allowed: true; path: string; root: string }
  | { allowed: false; code: DenyCode; detail: string };

const SENSITIVE_SEGMENTS = new Set(['.git', '.ssh', '.gnupg']);

const deny = (code: DenyCode, detail: string): Decision => ({ allowed: false, code, detail });

function touchesProtected(target: string, protectedPaths: readonly string[]): string | undefined {
  // Deny the protected path itself and every ancestor of it. Descendants are handled by the allowlist.
  return protectedPaths.find((p) => isSameOrDescendant(p, target));
}

export function decide(rawTarget: string, capability: Capability, policy: GuardPolicy): Decision {
  const n = normalizeWinPath(rawTarget);
  if (!n.ok) return deny(n.code, rawTarget);
  const target = n.path;

  if (isDriveRoot(target)) return deny('DRIVE_ROOT', target);

  const hit = touchesProtected(target, policy.protectedPaths);
  if (hit) return deny('PROTECTED_OR_ANCESTOR', `${target} contains or equals protected ${hit}`);

  const segment = target.split('\\').find((s) => SENSITIVE_SEGMENTS.has(s.toLowerCase()));
  if (segment) return deny('SENSITIVE_SEGMENT', `${target} is inside ${segment}`);

  // An allow root that itself touches P (bad catalog entry or hostile Atlas data) is ignored.
  const root = policy.allowRoots[capability]
    .map((r) => normalizeWinPath(r))
    .flatMap((r) => (r.ok ? [r.path] : []))
    .filter((r) => !isDriveRoot(r) && !touchesProtected(r, policy.protectedPaths))
    .find((r) => isSameOrDescendant(target, r));
  if (!root) return deny('NOT_ALLOWLISTED', target);

  return { allowed: true, path: target, root };
}
