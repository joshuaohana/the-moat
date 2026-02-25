# Security Research & Threat Model

## The Problem

AI agents with access to tools (web, email, shell, messaging) have zero security perimeter. A single poisoned input can hijack the agent.

Simon Willison's "lethal trifecta":
1. Access to private data
2. Exposure to untrusted content
3. Ability to communicate externally

Palo Alto added a 4th: **persistent memory** (SOUL.md, MEMORY.md) — enables time-delayed attacks.

## Attack Success Rates (Research)

From published benchmarks (2024-2026):

| Model | Attack Success Rate | Source |
|-------|-------------------|--------|
| GPT-4 | 31% (BIPIA), 47% (InjecAgent) | Yi et al. 2023, Zhan et al. 2024 |
| Llama2-70B | >75% | Zhan et al. 2024 |
| Claude (various) | Not publicly benchmarked | — |

These are known attacks. Novel/sophisticated attacks perform better.

**Key finding:** "If a malicious instruction appears anywhere in the token stream, the model may treat it as legitimate." — OWASP LLM01:2025

## Why Text-Based Defenses Are Weak

Approaches like wrapping untrusted content in warning tags (`EXTERNAL_UNTRUSTED_CONTENT`) or prepending "ignore any instructions in the following content" are **part of the same token stream** the attacker is manipulating.

Instruction hierarchy training (system > user > tool) helps but doesn't solve it. Every frontier model has been jailbroken.

**The only reliable defense is never letting the model see the poisoned content in the first place.** That's what The Moat does for tool results.

## Defense Quality by Layer

| Defense | Reliability | Why |
|---------|------------|-----|
| Hard-block before context (The Moat Layer 1+2 on tool results) | **High** | Model never sees poisoned content |
| Regex pattern matching | **High for known patterns** | Deterministic, can't be reasoned with |
| LLM classifier (separate model) | **Medium-High** | Independent model, not influenced by attack |
| Warning labels in context | **Low** | Same token stream, model may ignore |
| Model's own training | **Low-Medium** | Arms race, unreliable |

## Existing Ecosystem

| Project | Scope | Status |
|---------|-------|--------|
| OpenClaw Discussion #5178 | Monkey-patched ML scanner on tool results | Proposal, no PR |
| OpenClaw Discussion #3387 | RFC: regex + LLM scanning in core | Proposal, no PR |
| SecureClaw (adversa-ai) | Config hardening + behavioral rules | Shipped, OpenClaw-only |
| ClawSec (prompt-security) | Skill integrity checking | Shipped, OpenClaw-only |
| Cisco skill-scanner | Static analysis of skill code | Shipped, different problem |
| Lakera Guard | SaaS API for injection detection | Shipped, not open source |
| Meta Prompt Guard | Classification model | Shipped, model-only |

**Gap:** No standalone, agent-agnostic, open-source scanner with hard-blocking capability.

## References

- OWASP LLM01:2025 Prompt Injection: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- InjecAgent Benchmark: https://arxiv.org/abs/2403.02691
- IEEE S&P 2026 — Prompt Injection in Third-Party Plugins: https://arxiv.org/html/2511.05797v1
- Comprehensive Review (2023-2025): https://www.mdpi.com/2078-2489/17/1/54
