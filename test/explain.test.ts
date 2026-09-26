import { describe, expect, it } from 'vitest';
import { explain } from '../src/core/explain.ts';
import type { ScanItem } from '../src/core/scan.ts';

describe('explain', () => {
  it('gives plain-language reasons and the exact action', () => {
    const item: ScanItem = { id: 'PIP', category: 'pip-cache', title: 'pip cache', op: 'tool_cmd', targets: ['C:\\x\\pip'], allowRoot: 'C:\\x\\pip', command: { file: 'pip', args: ['cache', 'purge'] }, bytes: 10, files: 1, risk: 'safe', reversible: 'redownload' };
    expect(explain(item)).toMatchObject({ id: 'PIP', how: 'runs "pip cache purge"', reversible: 'redownload', what: expect.any(String), why_safe: expect.any(String), what_happens: expect.stringContaining('downloads') });
  });

  it('says a quarantine purge is permanent', () => {
    const item: ScanItem = { id: 'Q-abc', category: 'quarantine', title: 'q', op: 'purge_quarantine', targets: ['C:\\q\\abc'], allowRoot: 'C:\\q', bytes: 1, files: 1, risk: 'caution', reversible: 'none' };
    expect(explain(item).what_happens).toMatch(/PERMANENT/);
  });
});
