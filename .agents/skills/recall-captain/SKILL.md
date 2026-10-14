---
name: recall-captain
description: >-
  Agent-only retrieval of the Captain's own guidance from the Firstmate second brain.
  Load before writing worker instructions that need the Captain's own words on a topic, and after a model switch or in a new session when a Captain preference, rule, or past decision is not already in the injected startup memory.
  Fetches scoped matches from the raw Captain-message archive (bin/fm-captain-log.sh search), the curated memory files, and captain-held decisions, without re-injecting the whole archive.
user-invocable: false
metadata:
  internal: true
---

# recall-captain

The raw Captain-message archive is never injected at session start, so what the Captain said on a given topic is reached on demand, not carried in every prompt.
Use this skill to pull only the relevant teachings into the current turn.

This skill does not own any memory contract.
Curation, tiers, and decay stay owned by the [`stow` skill](../stow/SKILL.md); external authoritative stores stay owned by the memory-layering contract in [`docs/configuration.md`](../../../docs/configuration.md).
Recall only reads; it never curates, re-tiers, or declares a tier.

## When to recall

- Before writing a worker brief whose `## Captain's intent` needs the Captain's own standing guidance on the subject, so the worker receives it instead of relying on Firstmate's memory of chat.
- After a model switch or at the start of a new session, when a Captain preference, rule, or decision the turn depends on is not in the injected `data/captain.md` / `data/learnings.md`.
- When a current turn cites "what the Captain said" about a topic and the as-said wording matters.

## How to recall

1. Search the raw as-said archive for the topic:
   `bin/fm-captain-log.sh search <regex>` (add `--limit <n>` to widen the bounded output).
   Each result carries its UTC time, role, source chat/topic, and event id, which is the provenance to cite.
2. Read the curated current view with a scoped grep of `data/captain.md` and `data/learnings.md` for the same topic.
3. Check open and past decisions the Captain owns through the backlog and `bin/fm-captain-hold.sh`.

## How to use what you recall

- Quote or paraphrase only the matches that bear on the current topic; never paste the whole archive into a brief or a reply.
- Carry the provenance so a later reader can find the source: the curated entry's `(src: ...)` pointer, or the raw archive event id.
- When a recalled raw message contradicts a curated entry, treat the curated view as the current intent and the archive as the as-said history; a genuine conflict is a curation question for `/stow`, not something this skill resolves.
- Recall is read-only: a correction, a new durable fact, or a redaction request goes to its owner (`/stow`, or `bin/fm-captain-log.sh redact` for a Captain-directed scrub), never into an edit made from here.
