# KNOWN GAPS (Proxy Architecture)

The Moat now runs as a **transparent HTTP forward proxy**. This file documents what is and is not covered in v1.

## Current gaps

1. **HTTPS response body inspection is not available in v1**
   - The proxy handles `CONNECT` and tunnels bytes.
   - It logs destination `host:port` but does not decrypt traffic.
   - v2 plan: optional MITM mode with local CA for controlled environments.

2. **Non-HTTP traffic is out of scope**
   - Raw TCP or protocols on non-HTTP ports are not scanned.

3. **WebSocket is only partially covered**
   - Initial HTTP upgrade request is proxied/scanned.
   - After upgrade, bidirectional frames pass through uninspected.

4. **Local file reads are not proxied**
   - `file://` and direct disk reads do not traverse the network proxy.

5. **Inbound chat/webhook delivery is not outbound HTTP**
   - Matrix/Telegram inbound messages arriving on local listeners are not covered by outbound proxying.

6. **Binary payloads are passed through unscanned**
   - Images, video, archives, and other binary content are forwarded unchanged.

7. **Responses over max scan size are passed through**
   - If body exceeds configured `proxy.max_scan_body_bytes`, Moat skips scanning and logs a warning.

## Security boundary note

**iptables enforcement is the security boundary; the proxy is the scanning layer.**

If outbound traffic is not forced through The Moat (for example, no iptables redirect), an agent can bypass scanning by talking directly to the internet.
