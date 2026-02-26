# KNOWN GAPS (Proxy Architecture)

The Moat now runs as a **transparent HTTP forward proxy**. This file documents what is and is not covered in v1.

## Critical gaps

### 1. HTTPS response body inspection is not available in v1

This is the most significant gap. The proxy handles `CONNECT` and tunnels bytes — it logs destination `host:port` but does not decrypt or scan traffic. Since the vast majority of real-world traffic is HTTPS (GitHub API, Twitter/X API, most websites), **most response content passes through unscanned in v1.**

v2 plan: optional MITM mode with a local CA certificate for controlled environments. The agent's trust store would include the Moat CA, allowing the proxy to decrypt, scan, and re-encrypt HTTPS traffic.

### 2. Inbound messages are not covered

Matrix, Telegram, Slack, and other inbound chat/webhook messages arrive on local listeners — they are not outbound HTTP and do not traverse the proxy. A crafted message in a group chat (if external users are added) would reach the agent unscanned.

Mitigation: The OpenClaw plugin (`openclaw-plugin/`) can scan inbound messages via the `message_received` hook, but this is currently deferred. The plugin is also agent-removable (see gap #8), so it's not a hard boundary.

### 3. Local file reads are not proxied

`file://` paths and direct disk reads do not traverse the network proxy. If a malicious file lands on disk (via git clone, file sync, shared folders, etc.), the agent reads it unscanned.

Mitigation: The OpenClaw plugin's `tool_result_persist` hook could scan file read results, but this is deferred.

## Moderate gaps

### 4. Non-HTTP traffic is out of scope

Raw TCP, UDP, or protocols on non-HTTP ports are not scanned. Most agent traffic is HTTP/HTTPS, but custom protocols would bypass the proxy.

### 5. WebSocket is only partially covered

The initial HTTP upgrade request is proxied and scanned. After upgrade, bidirectional frames pass through uninspected.

### 6. Binary payloads are passed through unscanned

Images, video, archives, PDFs, and other binary content are forwarded unchanged. Text rendered as images (screenshots of instructions, OCR-bait) would bypass scanning entirely.

### 7. Responses over max scan size are passed through

If body exceeds configured `proxy.max_scan_body_bytes`, Moat skips scanning and logs a warning. An attacker could pad a payload to exceed the limit.

### 8. OpenClaw plugin is agent-removable (deferred)

The OpenClaw plugin (`openclaw-plugin/`) provides richer integration (tool result scanning, inbound message observation, warning injection). However, if loaded as an OpenClaw plugin, an agent with `gateway config.apply` access can remove it. The plugin is useful as a defense-in-depth layer but **is not a hard security boundary.** The proxy + iptables is the hard boundary.

### 9. Pattern engine evasion

Layer 1 regex catches straightforward attacks but can be bypassed by:
- Homoglyphs (Cyrillic/Greek lookalikes)
- Emoji smuggling
- Unicode tag characters
- Payload splitting across multiple requests
- Bidirectional text manipulation
- Base64/encoding tricks
- Diacritics, mathematical Unicode, fullwidth characters

Layer 2 LLM classifier catches some of these but not reliably all. Both layers only run on HTTP (not HTTPS) traffic in v1.

### 10. No outbound data exfiltration detection

If an injection succeeds, nothing prevents the agent from sending sensitive data outbound. The proxy scans *inbound* responses but does not inspect *outbound* request bodies or URLs for data leakage.

### 11. No behavioral monitoring

The Moat scans content, not behavior patterns. It cannot detect if an agent is acting anomalously (e.g., suddenly making requests to unusual domains, accessing files it normally doesn't, or escalating its own permissions).

## What IS covered well

- ✅ HTTP response body scanning (regex + optional LLM classifier)
- ✅ Full audit trail of all outbound connections (HTTP and HTTPS destinations)
- ✅ iptables enforcement — agent cannot bypass proxy
- ✅ Agent cannot disable the proxy (root-owned service + iptables rules)
- ✅ Zero-width character detection and stripping
- ✅ Naive/direct injection phrase detection
- ✅ Format marker injection token detection
- ✅ Credential/key pattern detection

## Security boundary note

**iptables enforcement is the security boundary; the proxy is the scanning layer.**

If outbound traffic is not forced through The Moat (for example, no iptables redirect), an agent can bypass scanning by talking directly to the internet. Always use iptables (or equivalent OS-level enforcement) in production.
