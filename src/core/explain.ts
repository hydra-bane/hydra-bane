import type { Category, ScanItem } from './scan.ts';
import { ADMIN_TEXT } from './admin-text.ts';
import { CACHE_TEXT_V02 } from './caches-text.ts';
import { ATLAS_TEXT } from '../atlas/atlas-text.ts';

// PLAN.md §5.2 `explain <item-id>`: plain-language reasons an agent can relay to the user.

export type ExplainText = { what: string; why: string; after: string };

const BASE: Partial<Record<Category, ExplainText>> = {
  temp: { what: 'Files in your user Temp folder that nobody has modified for over 24 hours.', why: 'Programs write scratch files here and often forget to remove them.', after: 'They are moved to quarantine, not deleted. You can undo for 7 days.' },
  'npm-cache': { what: 'Packages npm downloaded before.', why: 'npm keeps every downloaded package; projects do not need the cache to run.', after: 'npm downloads packages again the next time a project needs them.' },
  'pnpm-store': { what: 'Packages in the pnpm store that no project references any more.', why: '`pnpm store prune` removes only unreferenced packages; projects in use keep theirs.', after: 'Nothing to reinstall for current projects. Old projects re-download on next install.' },
  'pip-cache': { what: 'Python wheels and downloads pip cached.', why: 'pip keeps downloads to speed up future installs.', after: 'pip downloads them again when needed.' },
  'uv-cache': { what: 'Unused entries in the uv cache.', why: '`uv cache prune` removes entries no environment uses.', after: 'uv re-downloads anything it needs later.' },
  'cargo-registry': { what: 'Downloaded crates and git checkouts in ~/.cargo.', why: 'Rust keeps every crate version it ever fetched. Installed tools in ~/.cargo/bin are not touched.', after: 'cargo downloads crates again on the next build.' },
  'browser-cache': { what: 'The web cache folders of this browser (Cache, Code Cache, GPUCache or cache2).', why: 'Browsers store copies of web pages and scripts. Cookies, saved passwords, history, bookmarks and site storage are in other files and are not touched.', after: 'Pages load a little slower the first time as the browser refills the cache. The browser must be closed.' },
  'shader-cache': { what: 'Compiled GPU shaders stored by the graphics driver.', why: 'Drivers keep shaders from every game and app ever run.', after: 'They are rebuilt automatically; the first launch of a game may stutter briefly.' },
  'crash-dumps': { what: 'Memory dumps written when applications crashed.', why: 'Only useful if a developer asked you to send them.', after: 'They are moved to quarantine, not deleted. You can undo for 7 days.' },
  node_modules: { what: 'Installed dependencies of a project nobody has touched for 30+ days.', why: 'The folder is ignored by git and can be recreated from the lockfile next to it.', after: 'Moved to quarantine (undo for 7 days). Run your package manager install to rebuild it.' },
  target: { what: 'Rust build output of a project nobody has touched for 30+ days.', why: 'Ignored by git; `cargo build` recreates it from source.', after: 'Moved to quarantine (undo for 7 days). The next build takes longer.' },
  quarantine: { what: 'Items Hydra-bane quarantined more than 7 days ago.', why: 'Quarantined files still use disk space until they are purged.', after: 'PERMANENT. They are deleted and cannot be restored.' },
};

const TEXT: Partial<Record<Category, ExplainText>> = { ...BASE, ...CACHE_TEXT_V02, ...ADMIN_TEXT, ...ATLAS_TEXT };

export function explain(item: ScanItem) {
  const t = TEXT[item.category] ?? { what: item.title, why: item.instructions ?? '', after: '' };
  return {
    id: item.id,
    title: item.title,
    what: t.what,
    why_safe: t.why,
    what_happens: item.instructions && t.why !== item.instructions ? `${t.after} ${item.instructions}`.trim() : t.after,
    how: item.op === 'uninstall' && item.uninstall ? `runs the vendor uninstaller "${[item.uninstall.file, ...item.uninstall.args].join(' ')}"` : item.op === 'report_only' ? 'reports only; Hydra-bane changes nothing' : item.op === 'tool_cmd' && item.command ? `runs "${[item.command.file, ...item.command.args].join(' ')}"` : item.op === 'quarantine' ? 'moves to quarantine' : 'deletes the folder',
    reversible: item.reversible,
    bytes: item.bytes,
    targets: item.targets.slice(0, 20),
    ...(item.requiresClosed ? { requires_closed: item.requiresClosed } : {}),
  };
}
