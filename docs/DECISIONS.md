# Design Decisions

Decisions made during development, with reasoning.

## v1 Scope

### Bridges (not "trusted list")
Config uses `bridges:` to define trusted sources. The metaphor: you choose which bridges to lower across The Moat. Everything not on a bridge gets scanned at the wall. More memorable than `perimeter.trusted`.

### OpenClaw Plugin in v1 (not v2)
Originally planned for v2, but since we're dogfooding on OpenClaw anyway, it makes sense to ship the native plugin alongside the HTTP proxy in v1. Two integration paths, same engine:
- **OpenClaw plugin** — hooks into tool pipeline, scans before context window. What we use.
- **HTTP proxy** — agent-agnostic, works with anything. What everyone else uses.

The plugin is a thin wrapper that calls the same Pattern Engine. Not a separate codebase.

### Python (not Rust/Go)
Every AI agent framework is Python. `pip install` is universal in this ecosystem. Proxy libraries are mature (mitmproxy). Performance-sensitive paths (Layer 1 regex) are already fast in Python (<1ms). Can optimize hot paths later if needed.

### Inbound-Only for v1
v1 scans any incoming content (web pages, messages, API responses, file contents) before it reaches the agent. Outbound filtering (credential leak prevention, domain allowlists) is v2. Ship the simplest valuable thing first.

### Layer 1 Only for v1
Pattern Engine (deterministic regex + heuristics) is the only scanning layer in v1. LLM classifier (Layer 2) and policy engine (Layer 3) are v2. The Pattern Engine alone catches the vast majority of known attacks, runs in <1ms, and cannot be prompt-injected.

### Community Pattern Rules
Attack signatures ship as updatable JSON rule files, like antivirus definitions. Community contributes new patterns, maintainers review, users pull updates with `moat rules update`. The rule library is never "done" — it grows continuously via PRs.
