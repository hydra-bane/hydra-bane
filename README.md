# Hydra-bane

**Let your AI agent clean up Windows. Nothing changes until you approve, and what it moves can be put back.**

A disk cleanup CLI and Claude Code plugin for Windows 10/11. Your agent scans, drafts a sealed plan, shows you exactly what it will touch, and waits for your yes. Every change leaves a receipt.

[![npm](https://img.shields.io/npm/v/hydra-bane?style=flat-square)](https://www.npmjs.com/package/hydra-bane)
[![CI](https://img.shields.io/github/actions/workflow/status/hydra-bane/hydra-bane/ci.yml?branch=main&style=flat-square&label=CI%20(Windows))](https://github.com/hydra-bane/hydra-bane/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](https://github.com/hydra-bane/hydra-bane/blob/main/LICENSE)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D4?style=flat-square)

> [!NOTE]
> **v0.1: disk cleanup only.** The per-country bundled-software catalog (Atlas) and threat evidence checks are on the [roadmap](#roadmap), not in this release.

## Quick start

Requires Windows 10/11 and Node.js 22.18 or newer. No admin rights needed.

```powershell
npx hydra-bane scan        # read-only: shows what could be reclaimed, changes nothing
```

**Claude Code plugin** (skill + approval hook). Send these as two separate prompts:

```
/plugin marketplace add hydra-bane/hydra-bane
```
```
/plugin install hydra-bane@hydra-bane
```

Then ask: *"Free up some disk space with hydra-bane."*

## What a scan looks like

Real output from a developer PC:

```
> hydra-bane scan
Found 9.82 GB reclaimable. Nothing was changed.
  TEMP                 0.27 GB  Temp files older than 24h (477 entries)
  NPM                  0.35 GB  npm cache
  PNPM                 0.49 GB  pnpm store (prune removes unreferenced packages: up to this size)
  UV                   7.82 GB  uv cache (prune removes unused entries: up to this size)
  BROWSER-CHROME       0.73 GB  Chrome cache (cookies, logins and history are not touched)
  SHADER-NVIDIA-DX     0.09 GB  GPU shader cache NVIDIA\DXCache (rebuilt by games; first launch may stutter)
  DUMPS                0.05 GB  Application crash dumps (10 file(s); keep them if a developer asked for them)

Next: hydra-bane plan --select <ids>   (or --all-safe)
```

And the approval you see before anything runs, even in Claude Code's bypass-permissions mode:

```
Hydra-bane will apply plan mui6uyrt780161d8 (8b6e44b8):
- PIP 70 MB: runs "pip cache purge" on c:\users\you\appdata\local\pip\cache (re-downloadable, not undoable)
```

## How it works

```
scan  ->  plan  ->  you approve  ->  apply  ->  receipt  ->  undo (7 days)
```

1. **`scan`** finds candidates and changes nothing.
2. **`plan --select TEMP,NPM`** seals your choice: hashed, bound to your user and PC, valid for 24 hours. It cannot grow after you read it.
3. **`apply <plan-id>`** refuses to run without confirmation. Your agent shows you the plan and asks; in a terminal you get a y/N prompt. Scripts must pass `--yes`.
4. Each change is written to a hash-chained receipt ledger **before** it happens.
5. **`undo <tx>`** puts quarantined items back. After 7 days, old quarantine shows up in `scan` as `Q-…` so you can choose to empty it. Nothing is purged automatically.

## What it cleans

| Target | What happens | Can you get it back? |
|---|---|---|
| Temp files older than 24h | Moved to quarantine | Yes, `undo` for 7 days |
| Application crash dumps | Moved to quarantine | Yes, `undo` for 7 days |
| `node_modules` / Rust `target` untouched 30+ days and git-ignored, under `~/source`, `~/dev`, `~/projects`, `~/repos` or any `--root <dir>` | Moved to quarantine | Yes, `undo` for 7 days |
| npm, pnpm, pip, uv caches | The tool's own command (`npm cache clean --force`, `pnpm store prune`, `pip cache purge`, `uv cache prune`) | Re-downloaded when needed |
| Cargo registry and git checkouts | Deleted | Re-downloaded when needed |
| Chrome, Edge, Brave, Firefox caches | Only the cache folders are deleted. Refused while the browser is running | Rebuilt by the browser |
| GPU shader caches | Deleted | Rebuilt by games |

Not sure about an item? `hydra-bane explain <id>` says why it is safe and what happens afterwards.

## Report unwanted programs

Found something on your PC you never asked for? When you ask your agent to get rid of it, Hydra-bane offers to report it to the [Atlas](https://github.com/hydra-bane/atlas), a per-country catalog of bundled and hard-to-remove software. You see exactly what would be posted first: name, publisher, code signer, file hash and `%VAR%`-relative paths. It never includes your user name, PC name or real paths, and nothing is sent unless you say yes. A bot collects reports into one candidate pull request per program for maintainers to review.

## Why not just let my agent `rm -rf`?

Your agent can already delete files. The problem is that nobody knows what it deleted until it is gone.

| | Agent improvising cleanup | Hydra-bane |
|---|---|---|
| What gets touched | Whatever the composed command matches | A list with sizes that you read first |
| Scope creep | The next command can reach further | The plan is sealed; a change means a new plan |
| Who says yes | The agent, especially in auto-approve mode | You, through a prompt that names every item |
| Mistakes | Permanent | User files are quarantined, not deleted |
| Record | Scrollback, if you kept it | A tamper-evident receipt per change |

## Safety model

- **Path guard.** Drive roots, your profile and known folders (Desktop, Documents, OneDrive…) are refused, and so is any folder that contains them. Paths through `.git`, `.ssh` or `.gnupg` are refused too. Ambiguous paths (`/c/…`, `..`, UNC, 8.3 short names, alternate data streams) and junction redirects are rejected. Tested with 10,000 randomized paths.
- **Quarantine, not delete.** Items are moved whole on the same volume into a folder with inheritance cut off and execution denied. Restores never overwrite, and tampering is detected with SHA-256 (files up to 256 MB).
- **Approval hook.** The Claude Code plugin makes Claude Code ask you before any `hydra-bane apply` or `undo`, and the prompt lists what will happen. It also blocks recursive deletes of drives and profiles from any command. Verified in bypass-permissions mode on Claude Code 2.1.283.
- **Receipts.** A hash-chained ledger that shows edits, deletions and reordering. `hydra-bane ledger` verifies it.

### Limitations

- Without the plugin (Codex, Gemini CLI, Cursor, or plain shell), an agent in auto-approve mode could pass `--yes` itself. Keep approvals on for `hydra-bane apply`.
- Caches emptied by their own tools cannot be undone. They are re-downloaded on demand.
- pnpm and uv sizes are upper bounds; prune usually frees less. Hard links are not deduplicated yet.
- Antivirus software may remove files from quarantine. `undo` reports these as `STORED_MISSING`.
- It is not an antivirus and does not claim to find malware.

## For agents

Every command accepts `--json` and returns `{schema_version, command, ok, data, warnings, error?, hints?}`. Item IDs are stable across runs (`TEMP`, `NPM`, `NM-3f2a1c`…). Exit codes: `0` ok, `1` error, `2` refused by the guard, `3` needs human confirmation, `4` partial success. Never pass `--yes` without an explicit approval from the user in the conversation.

## Commands

| Command | Does | Changes anything? |
|---|---|---|
| `scan [--only <categories>] [--root <dir>]` | Find reclaimable space | No |
| `plan --select <ids>` / `--all-safe` | Seal a plan | No (writes a plan file) |
| `apply <plan-id> [--yes]` | Apply after confirmation | Yes |
| `undo <tx> [--yes]` | Restore a transaction | Yes |
| `explain <id>` | Why an item is safe to clean | No |
| `analyze [dir]` | Browse what uses space (arrow keys) | No |
| `ledger` | Verify and list receipts | No |
| `programs` | List installed programs | No |
| `report <program-id>` | Preview an Atlas report of an unwanted program; `--submit` posts it after you approve | Only with `--submit` |

## Roadmap

- **v0.2 Atlas**: a community-maintained, per-country catalog of bundled and hard-to-remove software, starting with Korea and the US. Data under CC BY-SA 4.0.
- Admin-level cleanup (Windows Update leftovers, WinSxS through DISM), MCP server, demo recordings.
- Later: evidence-based persistence and signature checks.

## Support

If Hydra-bane saved you some disk space or a bad afternoon, a star helps other Windows users find it. Issues and ideas for the Atlas are welcome.

## License

Code: [Apache-2.0](https://github.com/hydra-bane/hydra-bane/blob/main/LICENSE). Name use: [TRADEMARK.md](https://github.com/hydra-bane/hydra-bane/blob/main/TRADEMARK.md). Security issues: [SECURITY.md](https://github.com/hydra-bane/hydra-bane/blob/main/SECURITY.md).
Inspired by [Mole](https://github.com/tw93/Mole) for macOS; not affiliated with it.
