import { describe, expect, it, vi } from "vitest";
import {
  OpenAiProvider,
  type AnalysisRequest,
  type FollowUpRequest,
  type ReportTriageRequest,
} from "../src/ai/openai-provider.js";
import type { NormalizedCheckmateFinding } from "../src/findings/types.js";

const finding: NormalizedCheckmateFinding = {
  id: "finding-1",
  title: "Password policy",
  status: "failed",
  description: "Minimum length is 8.",
  raw: { shouldNotBeSent: true },
};

const validAnalysis = {
  whatItMeans: [
    "The reported password minimum is below the CheckMate recommendation.",
  ],
  whyItMatters: ["Shorter passwords can be easier to guess."],
  questions: [
    {
      id: "increase-possible",
      prompt: "Can the minimum length be increased?",
      inputType: "single_select" as const,
      options: [
        { value: "yes", label: "Yes" },
        { value: "no", label: "No" },
      ],
    },
  ],
  remediationConsiderations: ["Use the minimum length stated by CheckMate."],
};

const STANDARD_EXPECTED_OPTIONS = [
  { value: "yes", label: "Yes" },
  { value: "no", label: "No" },
  { value: "not_applicable", label: "Not applicable" },
  { value: "needs_investigation", label: "Needs investigation" },
];

describe("OpenAI provider", () => {
  it("requests a structured analysis using the configured interactive model", async () => {
    let captured: AnalysisRequest | undefined;
    const requester = vi.fn((request: AnalysisRequest) => {
      captured = request;
      return Promise.resolve(validAnalysis);
    });
    const provider = new OpenAiProvider({
      apiKey: "api-key",
      model: "gpt-5.4-mini",
      timeoutMs: 1_000,
      requester,
    });

    await expect(provider.analyseFinding(finding)).resolves.toEqual(
      validAnalysis,
    );
    expect(captured?.model).toBe("gpt-5.4-mini");
    expect(captured?.finding).not.toHaveProperty("raw");
  });

  it("rejects invalid structured output", async () => {
    const provider = new OpenAiProvider({
      apiKey: "api-key",
      model: "gpt-5.4-mini",
      timeoutMs: 1_000,
      requester: () => Promise.resolve({ explanation: "wrong shape" }),
    });
    await expect(provider.analyseFinding(finding)).rejects.toThrow(
      "invalid finding analysis",
    );
  });

  it("redacts known secrets echoed by a response", async () => {
    const provider = new OpenAiProvider({
      apiKey: "api-key",
      model: "gpt-5.4-mini",
      timeoutMs: 1_000,
      sensitiveValues: ["known-secret"],
      requester: () =>
        Promise.resolve({
          ...validAnalysis,
          whatItMeans: ["Never echo known-secret."],
        }),
    });
    const analysis = await provider.analyseFinding(finding);
    expect(analysis.whatItMeans[0]).toBe("Never echo [REDACTED].");
  });

  it("normalizes ungrounded AI choices instead of aborting the review", async () => {
    const provider = new OpenAiProvider({
      apiKey: "api-key",
      model: "gpt-5.4-mini",
      timeoutMs: 1_000,
      requester: () =>
        Promise.resolve({
          ...validAnalysis,
          questions: [
            {
              id: "applications",
              prompt: "Which applications should be approved?",
              inputType: "multi_select",
              options: [
                { value: "invented-client", label: "Invented application" },
              ],
            },
          ],
        }),
    });

    const analysis = await provider.analyseFinding(finding);
    expect(analysis.questions[0]).toMatchObject({
      inputType: "single_select",
      options: STANDARD_EXPECTED_OPTIONS,
    });
  });

  it("allows direct advice without forcing a question", async () => {
    const provider = new OpenAiProvider({
      apiKey: "api-key",
      model: "gpt-5.4-mini",
      timeoutMs: 1_000,
      requester: () =>
        Promise.resolve({
          ...validAnalysis,
          questions: [],
          remediationConsiderations: ["Enforce the reported secure setting."],
        }),
    });

    const analysis = await provider.analyseFinding(finding);
    expect(analysis.questions).toEqual([]);
    expect(analysis.remediationConsiderations[0]).toBe(
      "Enforce the reported secure setting.",
    );
  });

  it("answers a grounded follow-up question with short bullets", async () => {
    let captured: FollowUpRequest | undefined;
    const provider = new OpenAiProvider({
      apiKey: "api-key",
      model: "gpt-5.4-mini",
      timeoutMs: 1_000,
      requester: () => Promise.resolve(validAnalysis),
      followUpRequester: (request) => {
        captured = request;
        return Promise.resolve({
          answer: ["Check application compatibility before increasing it."],
        });
      },
    });

    await expect(
      provider.answerQuestion(
        finding,
        validAnalysis,
        "What could this change break?",
      ),
    ).resolves.toEqual([
      "Check application compatibility before increasing it.",
    ]);
    expect(captured?.question).toBe("What could this change break?");
    expect(captured?.finding).not.toHaveProperty("raw");
  });

  it("triages the complete report and drops invented or duplicate IDs", async () => {
    let captured: ReportTriageRequest | undefined;
    const provider = new OpenAiProvider({
      apiKey: "api-key",
      model: "gpt-5.4-mini",
      timeoutMs: 1_000,
      requester: () => Promise.resolve(validAnalysis),
      triageRequester: (request) => {
        captured = request;
        return Promise.resolve({
          selectedFindings: [
            {
              findingId: "finding-1",
              actionId: "action-1",
              recommendationTitle: "Strengthen the password policy",
              whatItMeans: ["The password setting is below the report target."],
              suggestedChanges: ["Use the password setting in the report."],
              reason: ["This is a direct scalar change."],
            },
            {
              findingId: "invented-id",
              actionId: "action-invented",
              recommendationTitle: "Invented recommendation",
              whatItMeans: ["Invented."],
              suggestedChanges: ["Invented."],
              reason: ["Invented."],
            },
            {
              findingId: "finding-1",
              actionId: "action-1",
              recommendationTitle: "Duplicate recommendation",
              whatItMeans: ["Duplicate."],
              suggestedChanges: ["Duplicate."],
              reason: ["Duplicate."],
            },
          ],
        });
      },
    });

    const selected = await provider.triageFindings([finding]);
    expect(selected).toHaveLength(1);
    expect(selected[0]?.findingId).toBe("finding-1");
    expect(selected[0]?.actionId).toBe("action-1");
    expect(captured?.findings).toHaveLength(1);
    expect(captured?.findings[0]).not.toHaveProperty("raw");
  });
});
