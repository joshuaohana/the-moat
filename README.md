# 🏰 The Moat

**The firewall for AI agents.** Works with anything. Install in 5 minutes.

---

AI agents have access to your files, shell, email, messaging, and APIs — with **zero security perimeter**. A single poisoned webpage or crafty message can hijack an agent into exfiltrating data, sending messages as you, or executing arbitrary commands.

The Moat sits between your agent and the outside world. It scans all inbound content before it reaches the agent's brain, blocks known attacks, and logs everything.

## How It Works

```
                    ┌──────────────────────┐
  [Web, Email,      │     🏰 THE MOAT      │      [Your AI Agent]
   Messages,   ───→ │                      │ ───→  Safe, scanned
   APIs]            │  Scan → Decide → Log │       content only
                    └──────────────────────┘
```

The Moat only activates at the **trust boundary** — where the outside world meets your agent. Internal operations (reading own files, owner chatting with agent) pass through untouched. Zero overhead on normal use.

## Quick Start

```bash
pip install the-moat
moat init          # generates moat.yaml with secure defaults
moat start         # proxy running on localhost:9999
```

Then point your agent's HTTP traffic through the proxy:

```bash
export HTTP_PROXY=http://localhost:9999
export HTTPS_PROXY=http://localhost:9999
```

That's it. Every inbound response is now scanned before your agent sees it.

### OpenClaw (Native Plugin)

For [OpenClaw](https://github.com/openclaw/openclaw) users, The Moat hooks directly into the tool pipeline — no proxy needed:

```json
{
  "moat": true
}
```

Same engine, tighter integration. Content is scanned before it hits the model's context window.

## What It Catches

- **Prompt injection** — "ignore previous instructions", role-play steering, DAN-style jailbreaks
- **Hidden text** — zero-width characters, white-on-white CSS, encoded instructions invisible to humans
- **Credential traps** — API keys or tokens planted in content to trick agents into using them
- **Obfuscated payloads** — base64-encoded instructions, Unicode tricks

## Configuration

`moat.yaml` defines your trust boundary using **bridges** — trusted sources that cross freely into the castle. Everything else hits the wall.

```yaml
bridges:
  - "owner:*"          # your direct chat with the agent
  - "workspace:*"      # agent's own files

always_scan:
  - "web:*"            # all web content
  - "message:*"        # messages from unknown senders

inbound:
  on_suspect: quarantine   # quarantine | block | sanitize | pass
  strip_hidden_text: true
  strip_zero_width: true

logging:
  format: json
  level: info
```

## CLI

| Command | Description |
|---------|-------------|
| `moat init` | Interactive setup, generates `moat.yaml` |
| `moat start` | Start the proxy |
| `moat stop` | Stop the proxy |
| `moat status` | Health check |
| `moat log` | View recent scan decisions |
| `moat rules update` | Pull latest community pattern rules |

## Architecture

**Layer 1: Pattern Engine** — Deterministic regex + heuristic scanning. Runs in <1ms. Cannot be prompt-injected because it's not an LLM. Ships with a curated library of known attack signatures, updated like antivirus definitions.

The agent can't talk itself out of The Moat. It runs as infrastructure, not as a prompt.

## Roadmap

- **v1 (current):** Inbound content scanning — Pattern Engine + HTTP proxy + OpenClaw plugin + audit logging
- **v2:** Outbound filtering, policy engine (domain allowlists, action policies), LLM classifier layer
- **v3:** Agent networking — standardized inbox, discovery protocol, mutual trust verification
- **v4:** Memory integrity monitoring, adaptive pattern evolution, multi-agent trust zones

## Philosophy

1. **Agent-agnostic.** Works with any framework. No vendor lock-in.
2. **Defense in depth.** Multiple layers. An attacker must beat all of them.
3. **Can't be prompt-injected.** Runs as infrastructure, not as a prompt.
4. **Zero overhead on trusted traffic.** Only activates at the perimeter.
5. **Secure defaults.** The floor is high. Users can loosen, but never below safe.
6. **Open source.** MIT license. Community-contributed pattern rules.

## Contributing

Pattern rule contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add new detection signatures.

## License

MIT — see [LICENSE](LICENSE)

---

*"The castle wall doesn't negotiate with the people trying to get through it."* 🏰

Built by [Ohana Industries](https://ohanaindustries.com)
