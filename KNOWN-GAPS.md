# KNOWN GAPS

This document is intentionally blunt. These are current security gaps in The Moat + OpenClaw plugin integration.

## Evasion techniques that bypass Layer 1 regex

Layer 1 regex catches straightforward attacks, but can be bypassed by representation tricks and multi-step payload delivery.

- Homoglyphs (Cyrillic/Greek lookalikes) — **44-76%** evasion rate in research
- Emoji smuggling — **100%** evasion rate against commercial guardrails
- Unicode tag characters — **90%** evasion rate
- Payload splitting (attack spread across multiple benign-looking chunks)
- Bidirectional text manipulation — **78-99%** evasion rate
- Base64/encoding tricks (LLM decodes but regex doesn't see)
- Diacritics ("ïgnörë prëvïöüs ïnstrüctïöns")
- Mathematical Unicode symbols
- Fullwidth characters
- Case/whitespace/newline manipulation (partial coverage exists)

**Important:** Layer 2 LLM classifier catches **some** of these, but not reliably all.

## 🔴 BREAKING: Agent can disable its own safety controls

**The entity being protected has administrative control over the protection mechanism.**

If the AI agent has access to its platform's config and restart mechanisms (e.g., OpenClaw's `gateway config.apply` + `gateway restart`), a prompt injection attack doesn't need to sneak past The Moat — it can simply instruct the agent to:

1. Remove The Moat plugin from the platform config
2. Restart the platform — all scanning stops
3. Deliver the real payload unscanned

**This is not a Moat bug — it's an architectural reality.** Any agent-side security plugin is fundamentally bypassable when the agent has config/restart access. The Moat still defends against unsophisticated or accidental injection, but it is **not a hard security boundary** until the platform enforces that safety plugins cannot be removed by the agent.

**Mitigations:**
- Install The Moat where the agent cannot read/modify/stop it (see QUICKSTART.md)
- Platform-level locked config sections (agent cannot modify safety hooks) — requires upstream support
- Restrict agent's access to config/restart tools via platform policy

**Status:** Unsolved at the platform level. Operators must enforce separation of privilege manually.

---

## Architectural gaps

- No outbound scanning — if injection succeeds, nothing prevents data exfiltration
- No output analysis — doesn't check if agent responses show signs of compromise
- Inbound channel messages: warn-only, cannot hard-block (OpenClaw hook limitation)
- Images/multimedia: text-only scanning, no OCR, no steganography detection
- Text rendered as images on webpages: invisible to scanner
- Multi-turn/multi-message attacks: each piece looks clean individually
- Context window overflow: flooding with benign content to push system prompt out
- Memory poisoning: injecting into persistent files (SOUL.md, MEMORY.md etc)
- Sub-agents inherit no protection unless explicitly configured
- Internal tool calls are unscanned (by design — trusted zone)
- No behavioral monitoring (scans content, not behavior patterns)
- Warning history is in-memory only, resets on restart
- URL policy matching is exact hostname only (no wildcard/glob)

## What IS covered well

- Naive/direct injection phrases
- Format marker injection tokens
- Zero-width character detection
- Credential/key pattern detection
- Basic exfiltration attempt phrases
- LLM classifier catches some subtle/novel attacks (when enabled)

## Planned mitigations (roadmap)

- Unicode NFKC normalization before scanning (kills homoglyphs, diacritics, fullwidth)
- Emoji smuggling detection
- Output scanning (check agent responses for compromise indicators)
- Content length limits
- Outbound filtering (v2)
- Behavioral monitoring (v2)
- Sub-agent protection propagation
- Wildcard URL matching
- OCR for image content

## Research references

- OWASP LLM Top 10 2025: LLM01 Prompt Injection
- CrowdStrike/Pangea: 185+ named injection techniques, 300k+ analyzed prompts
- Mindgard research: emoji smuggling 100% evasion, Unicode tags 90%
- Palo Alto: persistent memory as 4th attack vector element
