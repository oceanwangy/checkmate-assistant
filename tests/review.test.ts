import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AiProvider } from "../src/ai/provider.js";
import { executeReview } from "../src/commands/review.js";
import type { ReviewPrompt } from "../src/remediation/review-prompt.js";
import { reviewSessionSchema } from "../src/remediation/review-schema.js";

describe("review command", () => {
  afterEach(() => vi.restoreAllMocks());

  it("removes app-by-app questions from the Management API finding", async () => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    const directory = await mkdtemp(
      path.join(os.tmpdir(), "checkmate-review-"),
    );
    const reportPath = path.join(directory, "report.json");
    const outputDirectory = path.join(directory, "plans");
    await writeFile(
      reportPath,
      JSON.stringify([
        {
          finding_name: "checkManagementAPIUserAccess",
          finding_title: "Management API user access",
          status: "red",
          severity: "High",
          name: "Auth0 Management API",
          message:
            "Management API user access is not restricted to approved applications.",
          recommendation: "Restrict access to approved applications.",
        },
      ]),
    );

    const provider: AiProvider = {
      analyseFinding: vi.fn().mockResolvedValue({
        whatItMeans: [
          "Management API access is unrestricted. Never show do-not-store.",
        ],
        whyItMatters: ["Any application can request a user token."],
        questions: [
          {
            id: "approved-applications",
            prompt: "Which applications should be approved?",
            inputType: "text",
            options: [],
          },
        ],
        remediationConsiderations: [
          "Restrict access to approved applications.",
        ],
      }),
    };
    const closePrompt = vi.fn();
    const askFindingQuestion = vi.fn();
    const prompt: ReviewPrompt = {
      askFindingQuestion,
      selectDecision: vi.fn().mockResolvedValue("approved"),
      askRationale: vi
        .fn()
        .mockResolvedValue("Approved for the development tenant."),
      close: closePrompt,
    };
    const now = () => new Date("2026-07-10T10:00:00.000Z");

    const result = await executeReview(
      { report: reportPath, status: "failed", limit: 1 },
      {
        provider,
        prompt,
        model: "gpt-5.4-mini",
        outputDirectory,
        now,
        env: {
          AUTH0CHECKMATE_DEV_DOMAIN: "tenant.auth0.com",
          AUTH0CHECKMATE_DEV_CLIENT_ID: "checkmate-client",
          AUTH0CHECKMATE_DEV_CLIENT_SECRET: "do-not-store",
        },
      },
    );

    expect(result).toBeDefined();
    const stored = JSON.parse(
      await readFile(result!.outputPath, "utf8"),
    ) as unknown;
    const session = reviewSessionSchema.parse(stored);
    expect(session.review.model).toBe("gpt-5.4-mini");
    expect(session.decisions[0]).toMatchObject({
      checkmateValidatorId: "checkManagementAPIUserAccess",
      checkmateTitle: "Management API user access",
      decision: {
        status: "approved",
        rationale: "Approved for the development tenant.",
      },
    });
    expect(session.decisions[0]?.answers).toEqual([]);
    expect(askFindingQuestion).not.toHaveBeenCalled();
    expect(JSON.stringify(session)).not.toContain("do-not-store");
    expect(closePrompt).toHaveBeenCalledOnce();
  });
});
