# AGENTS.md

Instructions for coding agents (Codex, Gemini CLI, Cursor, Claude Code and others). There are two parts: using Hydra-bane to clean up a user's PC, and editing this repository.

## Part 1: cleaning up a Windows PC with hydra-bane

Clean up **only** through the `hydra-bane` CLI (`npx hydra-bane@<version> ...` if it is not on PATH). Always pass `--json` and read the JSON envelope `{schema_version, command, ok, data, warnings, error?, hints?}`. Never parse the human text.

### The loop

1. **Scan (read-only).** `hydra-bane scan --json` (add `--root <dir>` for project folders the user names). Tell the user what was found in plain words: largest items first, sizes in GB, and what happens to each (`reversible`: `redownload` = cache, `move-back` = quarantined and undoable, `none` = permanent).
2. **Let the user choose.** If they ask what an item is, run `hydra-bane explain <id> --json` and relay `what`, `why_safe` and `what_happens`. Suggest `safe` items, explain `caution` items. Do not choose for them.
3. **Plan (read-only).** `hydra-bane plan --select <id,id> --json` returns a `plan_id`. The plan is sealed and expires in 24 hours.
4. **Ask before applying.** Run `hydra-bane apply <plan_id> --json` **without** `--yes`. It changes nothing, exits with code `3` and returns `CONFIRMATION_REQUIRED` with `data.summary`. Show that summary to the user and ask "Apply this plan?". Only after the user explicitly approves in this conversation, run `hydra-bane apply <plan_id> --yes --json`.
5. **Report.** How much was freed now, how much was quarantined, what was skipped and why, and the receipt id: "You can undo this with `hydra-bane undo <tx>`".

Undo works the same way: ask first, then `hydra-bane undo <tx> --yes --json`. `STORED_MISSING` usually means antivirus removed the item from quarantine.

### Hard rules

- **Never pass `--yes` without an explicit approval from the user in this conversation**, even in auto-approve, full-auto or YOLO modes. Your host may not stop you; this rule does.
- **Exit code `3` means "ask the user".** Show the summary and wait. Exit `2` means the guard refused the path: do not rephrase the command to get around it. Exit `4` means partial success: report the skipped items.
- **No improvised recursive deletes.** Do not use `rm -rf`, `Remove-Item -Recurse`, `rd /s`, `del /s` or scripts that do the same for cleanup. If something is not covered by `scan`, tell the user instead of deleting it yourself.
- `scan`, `plan`, `explain`, `analyze`, `programs` and `ledger` change nothing on the PC (`plan` only writes a plan file). `apply`, `undo` and `report --submit` do, and each needs the user's yes.
- Quarantine older than 7 days shows up in `scan` as `Q-xxxxxxxx`. Purging it is **permanent**; say so before asking. Nothing is purged automatically.

### Unwanted programs: report to the Atlas (ask once)

When the user wants to get rid of a program they never asked for:

1. `hydra-bane programs --json` and find it by name.
2. Unless `hydra-bane report <id> --json` shows `data.previous` (already reported or declined), offer **once** to report it, and show `data.report` in full: that is exactly what would be posted publicly.
3. Only if the user says yes: `hydra-bane report <id> --submit --yes --json`. If `data.via` is `"link"`, give the user `data.url`. If they decline: `hydra-bane report <id> --no`.

Never send a report without the user's choice, and never edit the report to add details.

### Star prompt (once)

If an `apply` result contains `"hints": {"star_prompt": true}`, you may ask once whether the user wants to star the project, then run `hydra-bane star --yes` or `hydra-bane star --no`. Never star without the user's choice.

## Part 2: editing this repository

- Windows 10/11, Node.js 22.18 or newer. TypeScript runs directly through Node's type stripping; keep to erasable syntax (`erasableSyntaxOnly`).
- Before you say a change is done, run both and make sure they pass:
  ```
  npx vitest run
  npx tsc --noEmit
  ```
- Tests must never touch real caches or the real user profile: build a `Context` pointing at a temp folder (see `test/flow.test.ts`).
- Anything that deletes, moves or runs a cleanup command must go through the guard (`src/guard`) and write to the ledger before acting. Do not add a code path that bypasses either.
- `PLAN.md`, `HANDOFF.md` and `docs/` are local-only (gitignored). Do not reference them from shipped files and do not try to commit them. Shipped media goes in `assets/`.
- The demo GIF is recorded against a throwaway sandbox profile: `node scripts/demo/record.ts` then `node scripts/demo/render.mjs` (needs Playwright and ffmpeg). Never record against a real profile.
- Keep `README.md` and `README.ko.md` in step when you change user-facing behavior.
