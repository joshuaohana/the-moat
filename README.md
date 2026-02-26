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

## Known gaps

See [KNOWN-GAPS.md](KNOWN-GAPS.md).

## License

MIT
