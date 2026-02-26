# OpenClaw Integration via Transparent Proxy

The Moat integrates with OpenClaw by enforcing outbound HTTP/HTTPS through a local transparent proxy.

## Key point

**No OpenClaw configuration changes are required** for proxy-mode protection.

Enforcement is done at the OS layer (iptables redirect for the agent user), so OpenClaw tool traffic is routed through The Moat automatically.

## What OpenClaw traffic is covered

Typical outbound HTTP/HTTPS from OpenClaw tools is covered, including:

- `web_fetch`
- `web_search`
- browser HTTP(S) fetch/navigation traffic
- `exec` commands that use network clients (`curl`, `wget`, package managers, etc.)
- SDK/library traffic in scripts that use normal TCP HTTP stacks

## How to deploy with OpenClaw

1. Start The Moat proxy (`moat start --proxy`).
2. Add iptables redirect rules for the OpenClaw agent OS user.
3. Verify with `moat proxy-test` and a real OpenClaw tool call.

## Limitations in OpenClaw context

- HTTPS body scanning is not available in v1 (CONNECT tunnel only).
- Non-HTTP protocols are not scanned.
- Binary payloads are passed through.

## Future: Plugin Mode (deferred)

The repository still includes `openclaw-plugin/` and hook-based documentation as a future path.

Potential hook points (future/deferred):

- `tool_result_persist`
- `before_tool_call`
- `before_prompt_build`
- `message_received`

Proxy mode is the primary supported architecture today.
