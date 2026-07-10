import { describe, expect, it } from "vitest";
import type { AiFindingAnalysis } from "../src/ai/provider.js";
import {
  formatAiAnalysis,
  formatFindingForReview,
} from "../src/findings/review-formatter.js";
import type { NormalizedCheckmateFinding } from "../src/findings/types.js";

const finding: NormalizedCheckmateFinding = {
  id: "finding-1",
  validatorId: "checkManagementAPIUserAccess",
  title: "Management API user access",
  status: "failed",
  description: "Access is unrestricted.",
  evidence: { field: "management_api_user_access_allowed" },
  raw: {},
};

const analysis: AiFindingAnalysis = {
  whatItMeans: ["Access is currently unrestricted."],
  whyItMatters: ["Unapproved applications may request access."],
  questions: [
    {
      id: "approved-applications",
      prompt: "Which applications should be approved?",
      inputType: "multi_select",
      options: [],
    },
  ],
  remediationConsiderations: ["Restrict access."],
};

describe("review formatting", () => {
  it("omits validator IDs and evidence from the interactive finding display", () => {
    const output = formatFindingForReview(finding, 1, 1);
    expect(output).not.toContain("Validator:");
    expect(output).not.toContain("Evidence:");
    expect(output).toContain("Title: Management API user access");
  });

  it("shows explanations only when requested", () => {
    expect(formatAiAnalysis(analysis)).not.toContain("What it means:");
    expect(formatAiAnalysis(analysis)).not.toContain("Why it matters:");
    expect(formatAiAnalysis(analysis, true)).toContain("What it means:");
    expect(formatAiAnalysis(analysis, true)).toContain("Why it matters:");
  });
});
