---
name: hydra-bane
description: Safely free disk space and clean up a Windows PC. Use whenever the user asks to clean up, free space, clear caches, delete node_modules/build folders, or when you are about to delete files or folders recursively. Never use rm -rf, Remove-Item -Recurse, rd /s or del /s for cleanup; use hydra-bane, which shows exact paths, asks the user, quarantines instead of deleting, and can undo.
license: Apache-2.0
---

# Hydra-bane: safe cleanup for Windows

You clean up this PC **only** through the `hydra-bane` CLI. It is on PATH while this plugin is enabled.
Always pass `--json` and read the JSON; never parse the human text.

## The loop

1. **Scan (read-only).**
   `hydra-bane scan --json` (add `--root <dir>` for project folders the user names).
   Each item has `id`, `title`, `bytes`, `risk`, `reversible` (`redownload` = cache, `move-back` = quarantined, undoable).
   Tell the user what you found in plain words: largest items first, sizes in GB, and what happens to each.

2. **Let the user choose.** Ask which items to clean. Suggest the `safe` items; explain `caution` items
   (for example, old `node_modules` need `npm install` again later). Do not choose for them.

3. **Plan (read-only).**
   `hydra-bane plan --select <id,id> --json` → returns `plan_id`. A plan is sealed and expires in 24h.

4. **Ask before applying.** Run `hydra-bane apply <plan_id> --json` **without** `--yes` first. It changes nothing and
   returns `CONFIRMATION_REQUIRED` with `data.summary`. Show that summary to the user and ask with your question tool
   (for example AskUserQuestion): "Apply this plan?" with "Apply" / "Cancel".
   Only after the user explicitly picks Apply, run `hydra-bane apply <plan_id> --yes --json`.
   Never add `--yes` on your own judgment, even in auto-approve mode.

5. **Report.** Say how much was freed now, how much was quarantined, which items were skipped and why,
   and the receipt id: "You can undo this with `hydra-bane undo <tx>`".

## Undo

When the user wants something back: ask first, then `hydra-bane undo <tx> --yes --json`. Report items that could not
be restored (`STORED_MISSING` usually means antivirus removed it from quarantine).

## Exploring space

`hydra-bane analyze <dir> --json` lists the largest children of a folder (read-only). Use it to answer
"what is using my disk?". To free what you find, go back to scan/plan; do not delete it directly.

## Star prompt (once)

If an `apply` result contains `"hints": {"star_prompt": true}`, ask the user **once**:
"Hydra-bane freed <freed_bytes in GB>. If it helped, would you like to star it on GitHub?" with
"Star on GitHub" / "No thanks". Then run `hydra-bane star --yes` or `hydra-bane star --no`.
Both record the answer, so it is never asked again. Never star without the user's choice.

## Hard rules

- No recursive deletes outside hydra-bane. If a cleanup need is not covered by `scan`, tell the user instead of
  improvising a delete command.
- Never pass `--yes` without an explicit approval in this conversation.
- Exit code 3 means "ask the user"; exit code 4 means partial success (report the skipped items).
- If the plugin's guard blocks a command, do not try to rephrase it to get around the block.
