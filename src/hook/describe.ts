import fs from 'node:fs';
import path from 'node:path';
import { planHash, type Plan } from '../core/plan.ts';
import { Ledger } from '../ledger/ledger.ts';

// Text for the approval prompt: exactly what a hydra-bane apply/undo/purge is about to do,
// read from the sealed plan or the ledger, so the human approves specifics, not a generic warning.

const gb = (b: number) => (b >= 2 ** 30 ? `${(b / 2 ** 30).toFixed(2)} GB` : `${(b / 2 ** 20).toFixed(0)} MB`);
const MAX_LINES = 12;

export const defaultStateDir = () => path.join(process.env.LOCALAPPDATA ?? '', 'hydra-bane');

export function describeAction(action: string, id: string | undefined, stateDir = defaultStateDir()): string {
  const a = action.toLowerCase();
  if (a === 'purge') return 'Hydra-bane will PERMANENTLY delete expired quarantined items. This cannot be undone.';
  if (!id) return `Hydra-bane ${a} without an id; it will fail without changing anything.`;

  if (a === 'apply') {
    let plan: Plan;
    try { plan = JSON.parse(fs.readFileSync(path.join(stateDir, 'plans', `${id}.json`), 'utf8')) as Plan; } catch {
      return `Plan ${id} was not found; the command will fail without changing anything.`;
    }
    const { hash, ...body } = plan;
    const lines = [`Hydra-bane will apply plan ${id} (${hash.slice(0, 8)}):`];
    if (planHash(body) !== hash) lines.push('WARNING: this plan was edited after it was made; hydra-bane will refuse it.');
    for (const i of plan.items) {
      const what = i.op === 'tool_cmd' && i.command ? `runs "${[i.command.file, ...i.command.args].join(' ')}" on ${i.targets[0]} (re-downloadable, not undoable)`
        : i.op === 'delete_cache' ? `deletes ${i.targets[0]} (re-downloadable, not undoable)`
        : i.op === 'purge_quarantine' ? `PERMANENTLY deletes quarantined files in ${i.targets[0]} (undo window is over; cannot be undone)`
        : `moves ${i.targets.length === 1 ? i.targets[0] : `${i.targets.length} entries in ${path.dirname(i.targets[0]!)}`} to quarantine (undoable)`;
      lines.push(`- ${i.id} ${gb(i.bytes)}: ${what}`);
    }
    const total = plan.items.reduce((s, i) => s + i.bytes, 0);
    const undoable = plan.items.some((i) => i.op === 'quarantine');
    lines.push(`Total up to ${gb(total)}.${undoable ? ` Undo quarantined items with: hydra-bane undo ${id}` : ' Nothing here can be undone; caches are re-downloaded when needed.'}`);
    return clip(lines);
  }

  if (a === 'undo') {
    const done = new Ledger(path.join(stateDir, 'ledger')).records()
      .filter((r) => r.tx === id && r.type === 'done' && (r.data as { stored?: string }).stored)
      .map((r) => r.data as { target: string; bytes?: number });
    if (!done.length) return `Transaction ${id} has no quarantined items; the command will fail without changing anything.`;
    const bytes = done.reduce((s, d) => s + (d.bytes ?? 0), 0);
    return clip([`Hydra-bane will restore ${done.length} item(s), ${gb(bytes)}, from quarantine to their original folders:`, ...done.map((d) => `- ${d.target}`)]);
  }
  return `Hydra-bane ${a} ${id}`;
}

function clip(lines: string[]): string {
  return lines.length <= MAX_LINES ? lines.join('\n') : [...lines.slice(0, MAX_LINES - 1), `... and ${lines.length - MAX_LINES + 1} more`].join('\n');
}
