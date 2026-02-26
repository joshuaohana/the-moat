# 🏰 The Moat

**Transparent proxy firewall for AI agents.**

The Moat sits in front of outbound HTTP traffic, scans response bodies, and enforces ALLOW / SANITIZE / BLOCK decisions before content reaches the agent.

## Architecture (v1)

The primary architecture is OS-enforced transparent proxying:

1. Agent makes outbound HTTP/HTTPS request.
2. `iptables` redirects agent traffic to The Moat proxy.
3. The Moat:
   - HTTP: fetches upstream response, scans body via local engine, returns ALLOW/SANITIZE/BLOCK result.
   - HTTPS CONNECT: tunnels bytes (no MITM in v1), logs destination host:port.
4. Agent receives scanned/sanitized/blocked result.

```
Agent traffic -> iptables redirect -> The Moat proxy -> Internet
                             ^
                             | scan + policy + audit logs
```

## Quick start

See [QUICKSTART.md](QUICKSTART.md).

## How decisions work

- **ALLOW**: pass response unchanged.
- **SANITIZE**: return redacted body (e.g. `[REDACTED:injection]`).
- **BLOCK**: return explicit block page with reason/categories.

## Why transparent mode

No agent-side code changes are required. The enforcement point is the OS network layer (iptables), which prevents bypass when configured correctly.

## API mode

The `/scan` API still exists and can be started with:

```bash
moat start
```

Run both API and proxy:

```bash
moat start --both
```

## OpenClaw

OpenClaw integration now focuses on transparent proxy enforcement (see `docs/openclaw.md`).

The old plugin path remains in `openclaw-plugin/` but is deferred/future work.

## ⚠️ Install as the human, not the agent

The Moat must be installed and managed by the **human operator**, not by the AI agent it protects. If the agent can modify the proxy, iptables rules, or systemd service, a prompt injection could disable scanning entirely. See [QUICKSTART.md](QUICKSTART.md) for setup details.

## Known gaps

See [KNOWN-GAPS.md](KNOWN-GAPS.md) for the full list. The most significant:

- **HTTPS response bodies are not scanned in v1** — CONNECT is tunneled, destination logged only
- **Inbound messages** (chat/webhooks) don't traverse the proxy
- **Local file reads** bypass the proxy entirely

## Roadmap

### v1 (current) — Transparent HTTP Proxy
- ✅ HTTP response body scanning (Pattern Engine + optional LLM Classifier)
- ✅ iptables-enforced transparent proxy (agent cannot bypass)
- ✅ HTTPS destination logging (host:port audit trail)
- ✅ `/scan` API for direct integration
- ✅ CLI (`moat start --proxy`, `moat scan`, `moat proxy-test`)
- ✅ Audit logging (JSON, all requests)
- ✅ Tri-state verdicts: ALLOW / SANITIZE / BLOCK

### v2 — HTTPS Inspection + Outbound Protection
- HTTPS MITM scanning with local CA (opt-in, for controlled environments)
- Outbound request body scanning (data exfiltration detection)
- Domain allowlist/blocklist enforcement
- Unicode NFKC normalization (kills homoglyphs, diacritics, fullwidth evasion)
- OpenClaw plugin revival (defense-in-depth for non-HTTP sources)
- Web dashboard for audit log review

### v3 — Behavioral Monitoring + Agent Networking
- Behavioral anomaly detection (unusual destinations, access patterns, privilege escalation)
- Multi-agent trust zones
- Standardized agent inbox / discovery protocol
- Memory integrity monitoring (detect tampering with agent persistent files)
- Adaptive pattern evolution (auto-learn from new attack signatures)

### v4 — Ecosystem
- Community pattern rule contributions
- Plugin ecosystem for custom scanning logic
- Multi-agent deployment orchestration
- OCR scanning for image-based injection attacks

## Philosophy

1. **Infrastructure, not a plugin.** The security boundary is the OS network layer, not agent configuration.
2. **Defense in depth.** Pattern engine + LLM classifier. Proxy + optional plugin hooks.
3. **Can't be disabled by the thing it protects.** Root-owned service, root-owned iptables rules.
4. **Honest about gaps.** See [KNOWN-GAPS.md](KNOWN-GAPS.md). No security theater.
5. **Open source.** MIT license. Community contributions welcome.

## Contributing

Pattern rule contributions welcome! See the `rules/` directory for the current pattern set.

## License

MIT — © Joshua Ohana
