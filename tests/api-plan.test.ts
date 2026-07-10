import { mkdtemp, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { parse } from "yaml";
import { describe, expect, it } from "vitest";
import { buildApiPlan, apiPlanSchema } from "../src/remediation/api-plan.js";
import {
  createApiPlanOutputPath,
  writeApiPlan,
} from "../src/remediation/api-plan-writer.js";
import type { ReviewSession } from "../src/remediation/review-schema.js";

const analysis = {
  whatItMeans: ["The current setting needs improvement."],
  whyItMatters: ["The proposed setting reduces risk."],
  questions: [],
  remediationConsiderations: ["Apply the proposed setting."],
};

function session(): ReviewSession {
  return {
    schemaVersion: 1,
    report: { sourceReport: "/reports/tenant-report.json" },
    review: {
      model: "gpt-test",
      startedAt: "2026-07-10T10:00:00.000Z",
      lastUpdatedAt: "2026-07-10T10:05:00.000Z",
      completedAt: "2026-07-10T10:05:00.000Z",
    },
    decisions: [
      {
        checkmateFindingId: "password-policy",
        checkmateTitle: "Password policy",
        checkmateStatus: "failed",
        analysis,
        answers: [],
        actionableChangeId: "action-policy",
        actionableChanges: [
          {
            resourceType: "connection",
            resourceId: "con_database",
            resourceName: "Username-Password-Authentication",
            configPath: "options.passwordPolicy",
            currentValue: "fair",
            targetValue: "good",
          },
        ],
        decision: {
          status: "approved",
          rationale: "Accept the stronger policy.",
          decidedAt: "2026-07-10T10:03:00.000Z",
        },
      },
      {
        checkmateFindingId: "password-history",
        checkmateTitle: "Password history",
        checkmateStatus: "failed",
        analysis,
        answers: [],
        actionableChangeId: "action-history",
        actionableChanges: [
          {
            resourceType: "connection",
            resourceId: "con_database",
            resourceName: "Username-Password-Authentication",
            configPath: "options.password_history.enable",
            currentValue: false,
            targetValue: true,
          },
        ],
        decision: {
          status: "approved",
          rationale: "Prevent password reuse.",
          decidedAt: "2026-07-10T10:04:00.000Z",
        },
      },
      {
        checkmateFindingId: "passkey",
        checkmateTitle: "Passkeys",
        checkmateStatus: "failed",
        analysis,
        answers: [],
        actionableChangeId: "action-passkey",
        actionableChanges: [
          {
            resourceType: "connection",
            resourceId: "con_database",
            resourceName: "Username-Password-Authentication",
            configPath: "options.authentication_methods.passkey.enabled",
            currentValue: false,
            targetValue: true,
          },
        ],
        decision: {
          status: "accepted_risk",
          rationale: "Remain unchanged.",
          decidedAt: "2026-07-10T10:05:00.000Z",
        },
      },
    ],
  };
}

describe("Auth0 API plan", () => {
  it("groups approved changes and excludes unchanged decisions", () => {
    const plan = buildApiPlan(session(), "dev", "2026-07-10T10:06:00.000Z");

    expect(plan.calls).toHaveLength(1);
    expect(plan.calls[0]).toMatchObject({
      method: "PATCH",
      endpoint: "/api/v2/connections/con_database",
      bodyStrategy: "merge_live_connection_options",
      actionIds: ["action-policy", "action-history"],
      preconditions: [
        { path: "options.passwordPolicy", expectedValue: "fair" },
        {
          path: "options.password_history.enable",
          expectedValue: false,
        },
      ],
      body: {
        options: {
          passwordPolicy: "good",
          password_history: { enable: true },
        },
      },
    });
    expect(plan.unchangedActionIds).toEqual(["action-passkey"]);
  });

  it("writes a validated .yml file", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-plan-"));
    const outputPath = createApiPlanOutputPath(
      path.join(directory, "review.json"),
    );
    const plan = buildApiPlan(session(), "dev", "2026-07-10T10:06:00.000Z");

    await writeApiPlan(outputPath, plan);

    expect(outputPath).toMatch(/\.api-plan\.yml$/);
    expect(
      apiPlanSchema.parse(parse(await readFile(outputPath, "utf8"))),
    ).toEqual(plan);
  });
});
