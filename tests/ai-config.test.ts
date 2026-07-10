import { describe, expect, it } from "vitest";
import {
  DEFAULT_OPENAI_MODEL,
  DEFAULT_OPENAI_REASONING_EFFORT,
  loadAiConfig,
} from "../src/config/ai.js";

describe("OpenAI configuration", () => {
  it("uses the frontier model with high reasoning by default", () => {
    expect(loadAiConfig({ OPENAI_API_KEY: "test-key" })).toEqual({
      apiKey: "test-key",
      model: DEFAULT_OPENAI_MODEL,
      timeoutMs: 180_000,
      reasoningEffort: DEFAULT_OPENAI_REASONING_EFFORT,
    });
    expect(DEFAULT_OPENAI_MODEL).toBe("gpt-5.5");
    expect(DEFAULT_OPENAI_REASONING_EFFORT).toBe("high");
  });

  it("requires an API key without exposing configured values", () => {
    expect(() => loadAiConfig({ OPENAI_MODEL: "gpt-5.4-mini" })).toThrow(
      "OPENAI_API_KEY",
    );
  });
});
