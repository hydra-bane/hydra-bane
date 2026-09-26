# Hydra-bane

> Cut it. Burn it. It won't grow back.

**Status: pre-alpha, not usable yet.** Nothing here is safe to run on your machine.

Hydra-bane is a Windows cleanup and hygiene CLI built for AI coding agents (Claude Code, Codex, Gemini CLI, Cursor) and the humans who supervise them.

- **Disk**: reclaim space from caches, build artifacts, and virtual disks.
- **Atlas**: a community-maintained, per-country catalog of bundled and hard-to-remove software.
- **Threat**: evidence-based persistence and signature checks. It is not an antivirus.

It makes one promise: **nothing on your PC changes until you approve a sealed plan, and every change leaves a receipt you can undo.** Your AI agent shows you the plan and asks before applying it. With the Claude Code plugin installed, its guard hook makes Claude Code ask you before any `hydra-bane apply` runs, even in bypass-permissions mode (verified on Claude Code 2.1.283). Without the plugin, an agent in auto-approve mode could approve on its own.

- Feasibility spikes (Win32 via koffi, Windows Hello availability, traversal speed): [spikes/](spikes/)
- License: code [Apache-2.0](LICENSE). The Atlas data will ship separately under CC BY-SA 4.0. Name usage: [TRADEMARK.md](TRADEMARK.md).
- Inspired by [Mole](https://github.com/tw93/Mole). This project is not affiliated with it.
