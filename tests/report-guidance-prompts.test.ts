import { describe, expect, it } from "vitest";
import {
  ACTIVE_REPORT_GUIDANCE_PROMPT,
  ACTIVE_REPORT_GUIDANCE_PROMPT_NAME,
  REPORT_GUIDANCE_PROMPTS,
} from "../src/ai/report-guidance-prompts.js";

describe("report guidance guardrails", () => {
  it("uses the administrator coverage prompt", () => {
    expect(ACTIVE_REPORT_GUIDANCE_PROMPT_NAME).toBe(
      "administrator_coverage_v1",
    );
    expect(ACTIVE_REPORT_GUIDANCE_PROMPT).toBe(
      REPORT_GUIDANCE_PROMPTS.administrator_coverage_v1,
    );
  });

  it("requires exact, separate, human-readable actions", () => {
    expect(ACTIVE_REPORT_GUIDANCE_PROMPT).toContain(
      "Never invent a finding, actionId",
    );
    expect(ACTIVE_REPORT_GUIDANCE_PROMPT).toContain(
      "Treat every actionId as a separate recommendation",
    );
    expect(ACTIVE_REPORT_GUIDANCE_PROMPT).toContain(
      "Produce one recommendation for every distinct action",
    );
    expect(ACTIVE_REPORT_GUIDANCE_PROMPT).toContain(
      "Translate internal configuration terms into administrator language",
    );
  });
});
