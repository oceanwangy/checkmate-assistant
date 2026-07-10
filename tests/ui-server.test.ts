import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { AiProvider } from "../src/ai/provider.js";
import type { ApiExecutionResult } from "../src/auth0/api-plan-executor.js";
import type { NormalizedCheckmateFinding } from "../src/findings/types.js";
import type { ScanMetadata } from "../src/checkmate/types.js";
import type { ActionableChange } from "../src/remediation/actionable-change.js";
import { buildActionCandidates } from "../src/remediation/action-candidates.js";
import { apiPlanSchema } from "../src/remediation/api-plan.js";
import { createApiPlanOutputPath } from "../src/remediation/api-plan-writer.js";
import { reviewSessionSchema } from "../src/remediation/review-schema.js";
import { startUiServer } from "../src/ui/server.js";
import { parse } from "yaml";

describe("local review UI", () => {
  it("shows only AI-selected findings and saves a validated decision", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-ui-"));
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
          message: "Management API user access is open to every application.",
          recommendation: "Restrict access to approved applications.",
          evidence: { private_field: "must-not-reach-browser" },
        },
        {
          finding_name: "checkPasswordPolicy",
          finding_title: "Databases - Password Policy",
          status: "red",
          severity: "Moderate",
          name: "Username-Password-Authentication",
          message: "The password policy is below the required level.",
          recommendation: "Use a good password policy.",
        },
        {
          finding_name: "checkPasswordPolicy",
          finding_title: "Databases - Password Policy",
          status: "red",
          severity: "Moderate",
          field: "secondary_setting",
          message: "A second row describes the same password validator.",
          recommendation: "Use a good password policy.",
        },
      ]),
    );
    const triageFindings = vi.fn(
      (
        findings: readonly NormalizedCheckmateFinding[],
        configuration: ReadonlyMap<
          string,
          readonly ActionableChange[]
        > = new Map(),
      ) => {
        if (findings.length === 0) return Promise.resolve([]);
        return Promise.resolve(
          buildActionCandidates(configuration).map((candidate) => ({
            findingId: candidate.findingId,
            actionId: candidate.actionId,
            recommendationTitle: candidate.change.configPath.includes(
              "password_history",
            )
              ? "Enable password history"
              : "Set a strong password policy",
            whatItMeans: ["The password policy is below the required level."],
            suggestedChanges: [
              candidate.change.configPath.includes("password_history")
                ? "Prevent users from reusing recent passwords."
                : "Set the password policy to good.",
            ],
            reason: ["This is a direct enum change."],
          })),
        );
      },
    );
    const provider: AiProvider = {
      analyseFinding: vi.fn().mockRejectedValue(new Error("not called")),
      triageFindings,
    };
    const configurationLoader = vi.fn(
      (findings: readonly NormalizedCheckmateFinding[]) => {
        const action: ActionableChange = {
          resourceType: "connection",
          resourceId: "con_database",
          resourceName: "Username-Password-Authentication",
          configPath: "options.passwordPolicy",
          currentValue: "fair",
          targetValue: "good",
        };
        const historyAction: ActionableChange = {
          resourceType: "connection",
          resourceId: "con_database",
          resourceName: "Username-Password-Authentication",
          configPath: "options.password_history.enable",
          currentValue: false,
          targetValue: true,
        };
        return Promise.resolve(
          new Map(
            findings
              .filter(
                (finding) => finding.validatorId === "checkPasswordPolicy",
              )
              .map((finding): [string, ActionableChange[]] => [
                finding.id,
                [action, historyAction],
              ]),
          ),
        );
      },
    );
    const planExecutor = vi.fn((): Promise<ApiExecutionResult> =>
      Promise.resolve({
        status: "succeeded",
        startedAt: "2026-07-10T10:01:00.000Z",
        completedAt: "2026-07-10T10:01:01.000Z",
        profile: "dev",
        calls: [
          {
            id: "api-call-1",
            endpoint: "/api/v2/connections/con_database",
            status: "applied",
            correlationId: "checkmate-test",
          },
        ],
      }),
    );
    const running = await startUiServer(
      {
        report: reportPath,
        status: "failed",
        port: 0,
        outputDirectory,
      },
      {
        provider,
        model: "gpt-5.4-mini",
        env: {
          AUTH0CHECKMATE_DEV_DOMAIN: "tenant.auth0.com",
          AUTH0CHECKMATE_DEV_CLIENT_ID: "inventory-client",
          AUTH0CHECKMATE_DEV_CLIENT_SECRET: "never-return-this-secret",
        },
        now: () => new Date("2026-07-10T10:00:00.000Z"),
        configurationLoader,
        planExecutor,
      },
    );

    try {
      const root = await fetch(running.url);
      expect(root.status).toBe(200);
      expect(root.headers.get("content-security-policy")).toContain(
        "default-src 'self'",
      );
      const cookie = root.headers.get("set-cookie")?.split(";")[0];
      expect(cookie).toMatch(/^checkmate_session=/);
      const stateResponse = await fetch(`${running.url}/api/state`, {
        headers: { cookie: cookie! },
      });
      const initialText = await stateResponse.text();
      expect(initialText).not.toContain("checkManagementAPIUserAccess");
      expect(initialText).not.toContain("must-not-reach-browser");
      expect(initialText).not.toContain("never-return-this-secret");
      const initial = JSON.parse(initialText) as {
        triaged: boolean;
        reportFindingCount: number;
        findings: unknown[];
      };
      expect(initial).toMatchObject({
        triaged: false,
        reportFindingCount: 3,
        findings: [],
      });

      const triageResponse = await fetch(`${running.url}/api/triage`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: "{}",
      });
      expect(triageResponse.status).toBe(200);
      const triaged = (await triageResponse.json()) as {
        triaged: boolean;
        findings: Array<{
          key: string;
          title: string;
          analysis: { remediationConsiderations: string[] };
          actionableChanges: Array<{
            configPath: string;
            currentValue: string;
            targetValue: string;
          }>;
        }>;
      };
      expect(triaged.triaged).toBe(true);
      expect(triaged.findings).toHaveLength(2);
      expect(triaged.findings[0]).toMatchObject({
        title: "Set a strong password policy",
        analysis: {
          remediationConsiderations: ["Set the password policy to good."],
        },
        actionableChanges: [
          {
            configPath: "options.passwordPolicy",
            currentValue: "fair",
            targetValue: "good",
          },
        ],
      });
      expect(JSON.stringify(triaged)).not.toContain(
        "Management API user access",
      );
      expect(triageFindings).toHaveBeenCalledOnce();
      const findingKey = triaged.findings[0]!.key;

      const saveResponse = await fetch(`${running.url}/api/decision`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          findingKey,
          status: "accepted_risk",
          rationale: "The current access is temporarily accepted.",
        }),
      });
      expect(saveResponse.status).toBe(200);
      const stored = reviewSessionSchema.parse(
        JSON.parse(await readFile(running.outputPath, "utf8")) as unknown,
      );
      expect(stored.decisions[0]?.answers).toEqual([]);
      expect(stored.decisions[0]?.decision.status).toBe("accepted_risk");
      expect(stored.decisions[0]?.actionableChangeId).toBe(findingKey);
      expect(stored.decisions[0]?.actionableChanges?.[0]).toMatchObject({
        configPath: "options.passwordPolicy",
        currentValue: "fair",
        targetValue: "good",
      });
      expect(stored.review.completedAt).toBeUndefined();

      const earlySubmitResponse = await fetch(`${running.url}/api/submit`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: "{}",
      });
      expect(earlySubmitResponse.status).toBe(400);

      const secondSaveResponse = await fetch(`${running.url}/api/decision`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          findingKey: triaged.findings[1]!.key,
          status: "approved",
          rationale: "Accept the second independent action.",
        }),
      });
      expect(secondSaveResponse.status).toBe(200);
      const completed = reviewSessionSchema.parse(
        JSON.parse(await readFile(running.outputPath, "utf8")) as unknown,
      );
      expect(completed.decisions).toHaveLength(2);
      expect(completed.decisions[1]?.actionableChangeId).toBe(
        triaged.findings[1]!.key,
      );
      expect(completed.review.completedAt).toBeTruthy();

      const submitResponse = await fetch(`${running.url}/api/submit`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: "{}",
      });
      expect(submitResponse.status).toBe(200);
      const submitted = (await submitResponse.json()) as {
        created: boolean;
        state: {
          submissionReady: boolean;
          submitted: boolean;
          yamlFile: string;
        };
      };
      expect(submitted).toMatchObject({
        created: true,
        state: {
          submissionReady: true,
          submitted: true,
        },
      });
      expect(submitted.state.yamlFile).toMatch(/\.api-plan\.yml$/);
      const apiPlan = apiPlanSchema.parse(
        parse(
          await readFile(createApiPlanOutputPath(running.outputPath), "utf8"),
        ),
      );
      expect(apiPlan.calls).toHaveLength(1);
      expect(apiPlan.calls[0]).toMatchObject({
        method: "PATCH",
        endpoint: "/api/v2/connections/con_database",
        actionIds: [triaged.findings[1]!.key],
        body: {
          options: { password_history: { enable: true } },
        },
      });
      expect(apiPlan.unchangedActionIds).toEqual([findingKey]);

      const executeResponse = await fetch(`${running.url}/api/execute`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: JSON.stringify({ confirmed: true }),
      });
      expect(executeResponse.status).toBe(200);
      const executed = (await executeResponse.json()) as {
        executed: boolean;
        state: {
          canExecute: boolean;
          execution: ApiExecutionResult;
        };
      };
      expect(executed).toMatchObject({
        executed: true,
        state: {
          canExecute: false,
          execution: { status: "succeeded" },
        },
      });
      expect(planExecutor).toHaveBeenCalledOnce();
      const executionRecord = reviewSessionSchema.parse(
        JSON.parse(await readFile(running.outputPath, "utf8")) as unknown,
      );
      expect(executionRecord.execution).toMatchObject({
        status: "succeeded",
        profile: "dev",
        calls: [{ status: "applied" }],
      });
      expect(executionRecord.execution?.planFile).toMatch(/\.api-plan\.yml$/);
    } finally {
      await running.close();
    }
  });

  it("starts without a report and runs CheckMate from the UI", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-ui-"));
    const reportPath = path.join(directory, "generated-report.json");
    const outputDirectory = path.join(directory, "plans");
    const scanExecutor = vi.fn(async () => {
      await writeFile(
        reportPath,
        JSON.stringify([
          {
            finding_name: "checkPasswordPolicy",
            finding_title: "Databases - Password Policy",
            status: "red",
            name: "Username-Password-Authentication",
            message: "The password policy is below the required level.",
          },
        ]),
      );
      return {
        profile: "dev",
        targetDomain: "tenant.auth0.com",
        startedAt: "2026-07-10T10:00:00.000Z",
        finishedAt: "2026-07-10T10:00:01.000Z",
        exitCode: 0,
        reportPath,
      } satisfies ScanMetadata;
    });
    const provider: AiProvider = {
      analyseFinding: vi.fn().mockRejectedValue(new Error("not called")),
      triageFindings: vi.fn(
        (
          _findings: readonly NormalizedCheckmateFinding[],
          configuration: ReadonlyMap<
            string,
            readonly ActionableChange[]
          > = new Map(),
        ) =>
          Promise.resolve(
            buildActionCandidates(configuration).map((candidate) => ({
              findingId: candidate.findingId,
              actionId: candidate.actionId,
              recommendationTitle: "Set a strong password policy",
              whatItMeans: ["The password policy needs improvement."],
              suggestedChanges: ["Set the password policy to Good."],
              reason: ["This improves password strength."],
            })),
          ),
      ),
    };
    const configurationLoader = vi.fn(
      (findings: readonly NormalizedCheckmateFinding[]) =>
        Promise.resolve(
          new Map([
            [
              findings[0]!.id,
              [
                {
                  resourceType: "connection" as const,
                  resourceId: "con_database",
                  resourceName: "Username-Password-Authentication",
                  configPath: "options.passwordPolicy",
                  currentValue: "fair",
                  targetValue: "good",
                },
              ],
            ],
          ]),
        ),
    );
    const running = await startUiServer(
      { status: "failed", port: 0, outputDirectory },
      {
        provider,
        model: "test-model",
        env: {
          AUTH0CHECKMATE_DEV_DOMAIN: "tenant.auth0.com",
          AUTH0CHECKMATE_DEV_CLIENT_ID: "scan-client",
          AUTH0CHECKMATE_DEV_CLIENT_SECRET: "scan-secret",
        },
        scanExecutor,
        configurationLoader,
        now: () => new Date("2026-07-10T10:00:02.000Z"),
      },
    );

    try {
      const root = await fetch(running.url);
      const cookie = root.headers.get("set-cookie")?.split(";")[0];
      const initial = (await fetch(`${running.url}/api/state`, {
        headers: { cookie: cookie! },
      }).then((response) => response.json())) as {
        hasReport: boolean;
        availableProfiles: string[];
      };
      expect(initial).toMatchObject({
        hasReport: false,
        availableProfiles: ["dev"],
      });
      expect(running.outputPath).toBe("");

      const scanResponse = await fetch(`${running.url}/api/scan`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: JSON.stringify({ profile: "dev" }),
      });
      expect(scanResponse.status).toBe(200);
      const scanned = (await scanResponse.json()) as {
        scanned: boolean;
        state: {
          hasReport: boolean;
          selectedProfile: string;
          report: { file: string };
        };
      };
      expect(scanned).toMatchObject({
        scanned: true,
        state: {
          hasReport: true,
          selectedProfile: "dev",
          report: { file: "generated-report.json" },
        },
      });
      expect(running.outputPath).toMatch(/generated-report-review-/);
      expect(scanExecutor).toHaveBeenCalledOnce();

      const triageResponse = await fetch(`${running.url}/api/triage`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: "{}",
      });
      expect(triageResponse.status).toBe(200);
      const triaged = (await triageResponse.json()) as {
        triaged: boolean;
        findings: unknown[];
      };
      expect(triaged.triaged).toBe(true);
      expect(triaged.findings).toHaveLength(1);
    } finally {
      await running.close();
    }
  });

  it("rejects state requests without a browser session", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-ui-"));
    const reportPath = path.join(directory, "report.json");
    await writeFile(
      reportPath,
      JSON.stringify([{ title: "Finding", status: "red" }]),
    );
    const provider: AiProvider = {
      analyseFinding: vi.fn().mockRejectedValue(new Error("not called")),
    };
    const running = await startUiServer(
      { report: reportPath, status: "failed", port: 0 },
      { provider, model: "test" },
    );
    try {
      const response = await fetch(`${running.url}/api/state`);
      expect(response.status).toBe(401);
    } finally {
      await running.close();
    }
  });
});
