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

2. **Let the user choose.** When the user asks what an item is, run `hydra-bane explain <id> --json` and relay
   `what`, `why_safe` and `what_happens`. Browser items need the browser closed (`requires_closed`).
   Ask which items to clean. Suggest the `safe` items; explain `caution` items
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

## Reclaiming quarantined space

Quarantined items keep using disk space until purged. After the 7-day undo window, `scan` lists each old
quarantine as a `Q-xxxxxxxx` item (`reversible: "none"`). Purging it goes through the same plan → ask → apply loop.
Say clearly that it is **permanent** and cannot be undone. Nothing is ever purged automatically.

## Administrator items

Items with `needsAdmin: true` (Windows Update downloads, component store, hibernation file, system Temp…) are
skipped by `apply` with code `NEEDS_ADMIN`. They are permanent; say so. After the user approves, run
`hydra-bane apply-admin <plan_id> --yes --json`: Windows shows an administrator prompt, and only Hydra-bane's
admin-only helper runs them. If it answers `NO_HELPER`, ask the user first, then run `hydra-bane admin-install --yes`
(also an administrator prompt; it verifies the files against the npm registry). Never suggest turning off
hibernation unless the user wants the space: it also disables Fast Startup.

## After a crash

If apply or undo was interrupted, `hydra-bane recover --json` finishes the receipt from what is actually on disk.
apply and undo also run it automatically.

## Exploring space

`hydra-bane analyze <dir> --json` lists the largest children of a folder (read-only). Use it to answer
"what is using my disk?". To free what you find, go back to scan/plan; do not delete it directly.

## Unwanted programs (Atlas)

`hydra-bane atlas status --json` tells whether the signed Atlas catalog is installed. If not, and the user wants
unwanted programs found, run `hydra-bane atlas update --json` (downloads and verifies the signed bundle).
The first Atlas scan checks code signatures and can take about 30 seconds; later scans are fast.

`hydra-bane scan --only atlas --json` lists catalog programs found on this PC (category `atlas`). They are never
`safe`: explain each with `explain <id>` (what it is, the public source, whether a bank or public site may ask to
reinstall it). Items with `op: "uninstall"` go through the same plan → ask → apply loop: apply runs the vendor's own
signed uninstaller (Windows may show its administrator prompt and the vendor's window). Items with
`op: "report_only"` cannot be removed safely by Hydra-bane: give the user `instructions`.

## Unwanted programs not in the Atlas: report (ask once)

When the user wants to get rid of a program they did not want (bundled, adware, "how did this get here?"):

1. `hydra-bane programs --json` and find it by name. If it is not an Atlas item, removal is not automated: point
   the user to Settings > Apps > Installed apps, and do not improvise uninstall or delete commands.
2. Unless `hydra-bane report <id> --json` shows `data.previous` (already reported or declined), offer **once**:
   "Want to report this program to the Hydra-bane Atlas so others can spot it? This is exactly what would be
   posted publicly:" followed by `data.report` in full. Ask with "Report it" / "Don't report". The user may add a
   one-line note on how it got installed (`--note "<text>"`).
3. Only after the user picks Report: `hydra-bane report <id> --submit --yes --json`. If `data.via` is `"link"`,
   give the user `data.url` to open (it needs a GitHub account). If they decline: `hydra-bane report <id> --no`.

Never send a report without the user's choice in this conversation, and never edit the report to add details.

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
