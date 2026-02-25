# OpenClaw Integration

The Moat integrates natively with OpenClaw via its plugin hook system. No proxy, no fork, no networking tricks.

## How It Works

The Moat runs as a local Python server (`localhost:9999`). An OpenClaw plugin hooks into the agent lifecycle and sends content to The Moat's `/scan` API before the agent sees it.

```
Tool executes (web_fetch, browser, etc.)
    ↓
tool_result_persist hook fires
    ↓
Plugin sends content to POST localhost:9999/scan
    ↓
The Moat scans (Layer 1: regex, Layer 2: LLM)
    ↓
CLEAN → result passes through unchanged
BLOCKED → result replaced with warning, agent never sees poisoned content
```

## Hooks Used

| Hook | Type | Purpose |
|------|------|---------|
| `tool_result_persist` | Modifying | Scan and replace tool results (web content, API responses, file reads) before they enter the session |
| `before_tool_call` | Modifying | Block tool calls to known-malicious URLs before execution |
| `before_prompt_build` | Modifying | Prepend warnings when suspicious inbound messages are detected |
| `message_received` | Observe-only | Detect potential injection in channel messages (flags for `before_prompt_build`) |

## Coverage

| Content Source | Can Scan | Can Block | How |
|---------------|----------|-----------|-----|
| `web_fetch` results | ✅ | ✅ | `tool_result_persist` replaces content |
| `web_search` results | ✅ | ✅ | `tool_result_persist` replaces content |
| `browser` results | ✅ | ✅ | `tool_result_persist` replaces content |
| `Read` (external files) | ✅ | ✅ | `tool_result_persist` replaces content |
| Tool calls to bad URLs | ✅ | ✅ | `before_tool_call` blocks execution |
| Outbound messages | ✅ | ✅ | `message_sending` modifies/cancels (v2) |
| Inbound channel messages | ✅ | ⚠️ Warn only | `message_received` detects, `before_prompt_build` warns |

### Note on Inbound Messages

OpenClaw's `message_received` hook is fire-and-forget — it can observe but not block content. When The Moat detects a suspicious inbound message, it flags it, and the `before_prompt_build` hook prepends a warning to the agent's context. Combined with OpenClaw's own `EXTERNAL_UNTRUSTED_CONTENT` wrapping, this provides adequate defense for v1.

A proper hard-block would require an upstream `before_message_process` modifying hook — a small PR we plan to contribute.

## Setup

1. Install and start The Moat:

```bash
pip install the-moat
moat start
```

2. Install the OpenClaw plugin:

```bash
# TODO: exact install path TBD
```

3. Restart OpenClaw gateway.

That's it. All tool results are now scanned before your agent sees them.
