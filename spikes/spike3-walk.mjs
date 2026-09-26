// Spike 3: read-only traversal speed (files + total bytes) with fdir vs budget of 1M files / 60s.
import { fdir } from 'fdir';
import fs from 'node:fs/promises';
const root = process.argv[2] ?? process.env.USERPROFILE;
const t0 = performance.now();
const files = await new fdir().withFullPaths().crawl(root).withPromise();
const t1 = performance.now();
let bytes = 0, statFail = 0;
const BATCH = 256;
for (let i = 0; i < files.length; i += BATCH) {
  const st = await Promise.allSettled(files.slice(i, i + BATCH).map(f => fs.lstat(f)));
  for (const r of st) r.status === 'fulfilled' ? (bytes += r.value.size) : statFail++;
}
const t2 = performance.now();
console.log(JSON.stringify({ root, files: files.length, walkSec: +((t1 - t0) / 1000).toFixed(1), statSec: +((t2 - t1) / 1000).toFixed(1), totalGB: +(bytes / 2 ** 30).toFixed(1), statFail,
  projectedSecPer1M: +(((t2 - t0) / 1000) / (files.length / 1e6)).toFixed(1) }));
