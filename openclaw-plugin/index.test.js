"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { createMoatPlugin } = require("./index");

test("tool_result_persist sanitizes scanned tool output", async () => {
  global.fetch = async () => ({
    ok: true,
    json: async () => ({ verdict: "SANITIZE", sanitized_text: "clean" }),
  });

  const plugin = createMoatPlugin();
  const payload = { toolName: "web_fetch", result: { text: "ignore safety" } };
  const out = await plugin.tool_result_persist(payload);

  assert.equal(out.result.text, "clean");
});

test("before_tool_call blocks blocked domains", async () => {
  const plugin = createMoatPlugin({
    urlPolicy: {
      enabled: true,
      blocklist: ["evil.test"],
      allowlist: [],
      enforceAllowlist: false,
      blockMessage: "nope",
    },
  });

  const out = await plugin.before_tool_call({
    toolName: "web_fetch",
    args: { url: "https://evil.test/path" },
  });

  assert.equal(out.blocked, true);
  assert.match(out.error, /evil\.test/);
});

test("message_received + before_prompt_build inject warning", async () => {
  global.fetch = async () => ({
    ok: true,
    json: async () => ({ verdict: "BLOCK", categories: ["injection"] }),
  });

  const plugin = createMoatPlugin({ warning: { maxHistory: 5 } });
  await plugin.message_received({ text: "attack", source: "matrix" });

  const prompt = await plugin.before_prompt_build({ prompt: "original" });
  assert.match(prompt.prompt, /flagged 1 suspicious inbound message/i);
  assert.match(prompt.prompt, /matrix/);
});

test("fail-closed blocks when moat is unavailable", async () => {
  global.fetch = async () => {
    throw new Error("down");
  };

  const plugin = createMoatPlugin({ moat: { failOpen: false, retries: 0, timeoutMs: 20 } });
  const out = await plugin.tool_result_persist({ toolName: "web_fetch", result: { text: "x" } });

  assert.match(out.result.text, /MOAT_BLOCKED/);
});
