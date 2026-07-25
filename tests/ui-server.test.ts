import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { AiProvider } from "../src/ai/provider.js";
import type {
  ApiExecutionResult,
  ApiPlanValidationResult,
} from "../src/auth0/api-plan-executor.js";
import type { NormalizedCheckmateFinding } from "../src/findings/types.js";
import type { ScanMetadata } from "../src/checkmate/types.js";
import type { ActionableChange } from "../src/remediation/actionable-change.js";
import { buildActionCandidates } from "../src/remediation/action-candidates.js";
import { apiPlanSchema } from "../src/remediation/api-plan.js";
import { createChangePackagePaths } from "../src/remediation/change-package-writer.js";
import { reviewSessionSchema } from "../src/remediation/review-schema.js";
import type { TerraformValidationResult } from "../src/remediation/terraform-validator.js";
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
      (
        findings: readonly NormalizedCheckmateFinding[],
        config: { profile: "dev" | "prod" },
      ) => {
        const action: ActionableChange = {
          resourceType: "connection",
          resourceId: `con_${config.profile}`,
          resourceName: "Username-Password-Authentication",
          configPath: "options.passwordPolicy",
          currentValue: "fair",
          targetValue: "good",
        };
        const historyAction: ActionableChange = {
          resourceType: "connection",
          resourceId: `con_${config.profile}`,
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
    const apiPlanValidator = vi.fn(
      (plan: { profile: "dev" | "prod" }): Promise<ApiPlanValidationResult> =>
        Promise.resolve({
          valid: true,
          profile: plan.profile,
          validatedAt: "2026-07-10T10:00:00.000Z",
          calls: [],
        }),
    );
    const terraformValidator = vi.fn(
      (terraformFile: string): Promise<TerraformValidationResult> =>
        Promise.resolve({
          valid: true,
          validatedAt: "2026-07-10T10:00:00.000Z",
          terraformFile,
          steps: [
            { command: "fmt", valid: true, message: "formatted" },
            { command: "init", valid: true, message: "initialised" },
            { command: "validate", valid: true, message: "validated" },
          ],
        }),
    );
    const running = await startUiServer(
      {
        report: reportPath,
        profile: "dev",
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
          AUTH0CHECKMATE_PROD_DOMAIN: "prod.auth0.com",
          AUTH0CHECKMATE_PROD_CLIENT_ID: "prod-client",
          AUTH0CHECKMATE_PROD_CLIENT_SECRET: "prod-secret",
        },
        now: () => new Date("2026-07-10T10:00:00.000Z"),
        configurationLoader,
        planExecutor,
        apiPlanValidator,
        terraformValidator,
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
        findingStatus: string;
        reportValidatorCount: number;
        reportFindingCount: number;
        posture: {
          current: { score: number; rating: string };
          projected: { score: number; rating: string };
        };
        findings: unknown[];
      };
      expect(initial).toMatchObject({
        triaged: false,
        findingStatus: "failed",
        reportValidatorCount: 2,
        reportFindingCount: 3,
        findings: [],
      });
      expect(initial.posture.current).toEqual(initial.posture.projected);
      expect(initial.posture.current.score).toBeLessThan(100);

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
        posture: {
          projected: {
            openControls: Array<{
              title: string;
              importance: string;
              guidance: string;
              recommendationAvailable: boolean;
            }>;
          };
        };
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
      expect(JSON.stringify(triaged.findings)).not.toContain(
        "Management API user access",
      );
      expect(triaged.posture.projected.openControls).toContainEqual(
        expect.objectContaining({
          title: "Management API user access",
          importance: "High impact",
          recommendationAvailable: false,
        }),
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
      const savedState = (await saveResponse.json()) as {
        state: {
          posture: {
            current: { score: number };
            projected: { score: number };
          };
          findings: Array<{ key: string; adminNote?: string }>;
        };
      };
      expect(
        savedState.state.findings.find((finding) => finding.key === findingKey)
          ?.adminNote,
      ).toBe("The current access is temporarily accepted.");
      expect(savedState.state.posture.projected.score).toBe(
        savedState.state.posture.current.score,
      );
      const stored = reviewSessionSchema.parse(
        JSON.parse(await readFile(running.outputPath, "utf8")) as unknown,
      );
      expect(stored.decisions[0]?.answers).toEqual([]);
      expect(stored.decisions[0]?.decision.status).toBe("accepted_risk");
      expect(stored.decisions[0]?.decision.rationale).toBe(
        "The current access is temporarily accepted.",
      );
      expect(stored.decisions[0]?.decision.adminNote).toBe(
        "The current access is temporarily accepted.",
      );
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
      const partiallyApproved = (await secondSaveResponse.json()) as {
        state: {
          posture: {
            current: { score: number };
            projected: { score: number };
          };
        };
      };
      expect(partiallyApproved.state.posture.projected.score).toBeGreaterThan(
        partiallyApproved.state.posture.current.score,
      );
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
          changePackage: {
            directory: string;
            dev: {
              apiFile: string;
              terraformFile: string;
              apiPlanSha256: string;
            };
            prod: {
              apiFile: string;
              terraformFile: string;
              apiPlanSha256: string;
            };
          };
        };
      };
      expect(submitted).toMatchObject({
        created: true,
        state: {
          submissionReady: true,
          submitted: true,
        },
      });
      expect(submitted.state.changePackage).toMatchObject({
        dev: { apiFile: "dev/api-plan.yml", terraformFile: "dev/main.tf" },
        prod: {
          apiFile: "prod/api-plan.yml",
          terraformFile: "prod/main.tf",
        },
      });
      expect(submitted.state.changePackage.dev.apiPlanSha256).toMatch(
        /^[a-f0-9]{64}$/,
      );
      const packagePaths = createChangePackagePaths(running.outputPath);
      const apiPlan = apiPlanSchema.parse(
        parse(await readFile(packagePaths.dev.apiPlan, "utf8")),
      );
      expect(apiPlan.calls).toHaveLength(1);
      expect(apiPlan.calls[0]).toMatchObject({
        method: "PATCH",
        endpoint: "/api/v2/connections/con_dev",
        actionIds: [triaged.findings[1]!.key],
        body: {
          options: { password_history: { enable: true } },
        },
      });
      expect(apiPlan.unchangedActionIds).toEqual([findingKey]);
      const productionPlan = apiPlanSchema.parse(
        parse(await readFile(packagePaths.prod.apiPlan, "utf8")),
      );
      expect(productionPlan).toMatchObject({
        profile: "prod",
        calls: [{ endpoint: "/api/v2/connections/con_prod" }],
      });
      expect(await readFile(packagePaths.dev.terraform, "utf8")).toContain(
        'data "auth0_connection"',
      );
      expect(await readFile(packagePaths.prod.terraform, "utf8")).toContain(
        'profile        = "prod"',
      );

      const apiPreview = await fetch(
        `${running.url}/api/artifact?profile=dev&artifact=api`,
        { headers: { cookie: cookie! } },
      );
      expect(apiPreview.status).toBe(200);
      expect(apiPreview.headers.get("content-type")).toContain(
        "application/yaml",
      );
      expect(await apiPreview.text()).toContain("profile: dev");

      const terraformDownload = await fetch(
        `${running.url}/api/artifact?profile=prod&artifact=terraform&download=1`,
        { headers: { cookie: cookie! } },
      );
      expect(terraformDownload.status).toBe(200);
      expect(terraformDownload.headers.get("content-disposition")).toBe(
        'attachment; filename="prod-main.tf"',
      );
      expect(await terraformDownload.text()).toContain(
        'profile        = "prod"',
      );

      const unsupportedArtifact = await fetch(
        `${running.url}/api/artifact?profile=dev&artifact=../report`,
        { headers: { cookie: cookie! } },
      );
      expect(unsupportedArtifact.status).toBe(400);

      const reviewedPlanContent = await readFile(
        packagePaths.dev.apiPlan,
        "utf8",
      );
      await writeFile(
        packagePaths.dev.apiPlan,
        `${reviewedPlanContent}\n# changed after review\n`,
      );
      const changedPlanResponse = await fetch(`${running.url}/api/execute`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: JSON.stringify({ confirmed: true }),
      });
      expect(changedPlanResponse.status).toBe(400);
      expect(await changedPlanResponse.text()).toContain(
        "changed after review",
      );
      expect(planExecutor).not.toHaveBeenCalled();
      await writeFile(packagePaths.dev.apiPlan, reviewedPlanContent);

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
      expect(apiPlanValidator).toHaveBeenCalledTimes(3);
      expect(terraformValidator).toHaveBeenCalledTimes(3);
      const executionRecord = reviewSessionSchema.parse(
        JSON.parse(await readFile(running.outputPath, "utf8")) as unknown,
      );
      expect(executionRecord.execution).toMatchObject({
        status: "succeeded",
        profile: "dev",
        calls: [{ status: "applied" }],
      });
      expect(executionRecord.execution?.planFile).toBe("dev/api-plan.yml");
      expect(executionRecord.execution?.planSha256).toBe(
        submitted.state.changePackage.dev.apiPlanSha256,
      );
    } finally {
      await running.close();
    }
  });

  it("groups deterministic application changes with selectable applications", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-ui-"));
    const reportPath = path.join(directory, "applications.json");
    await writeFile(
      reportPath,
      JSON.stringify([
        {
          finding_name: "checkGrantTypes",
          finding_title: "Application Grant Types",
          status: "red",
          severity: "High",
          name: "App One (client_one12345) (First-Party Application)",
          field: "unexpected_grant_type_for_app_type",
          value: "implicit",
          message: "The Implicit grant type is enabled.",
        },
        {
          finding_name: "checkGrantTypes",
          finding_title: "Application Grant Types",
          status: "red",
          severity: "High",
          name: "App Two (client_two12345) (First-Party Application)",
          field: "unexpected_grant_type_for_app_type",
          value: "implicit",
          message: "The Implicit grant type is enabled.",
        },
      ]),
    );
    const triageFindings = vi.fn().mockResolvedValue([]);
    const provider: AiProvider = {
      analyseFinding: vi.fn().mockRejectedValue(new Error("not called")),
      triageFindings,
    };
    const configurationLoader = vi.fn(
      (findings: readonly NormalizedCheckmateFinding[]) =>
        Promise.resolve(
          new Map(
            findings.map((finding, index): [string, ActionableChange[]] => {
              const suffix = index === 0 ? "one" : "two";
              return [
                finding.id,
                [
                  {
                    resourceType: "client",
                    resourceId: `client_${suffix}12345`,
                    resourceName: index === 0 ? "App One" : "App Two",
                    configPath: "grant_types",
                    currentValue: [
                      "authorization_code",
                      "implicit",
                      "refresh_token",
                    ],
                    targetValue: ["authorization_code", "refresh_token"],
                  },
                ],
              ];
            }),
          ),
        ),
    );
    const running = await startUiServer(
      {
        report: reportPath,
        profile: "dev",
        status: "failed",
        port: 0,
        outputDirectory: directory,
      },
      {
        provider,
        configurationLoader,
        env: {
          AUTH0CHECKMATE_DEV_DOMAIN: "tenant.auth0.com",
          AUTH0CHECKMATE_DEV_CLIENT_ID: "client-id",
          AUTH0CHECKMATE_DEV_CLIENT_SECRET: "client-secret",
        },
        now: () => new Date("2026-07-14T10:00:00.000Z"),
      },
    );

    try {
      const root = await fetch(running.url);
      const cookie = root.headers.get("set-cookie")?.split(";")[0];
      const response = await fetch(`${running.url}/api/triage`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: "{}",
      });
      expect(response.status).toBe(200);
      const state = (await response.json()) as {
        findings: Array<{
          key: string;
          title: string;
          selectionMode: string;
          actionableChanges: Array<{ actionId: string; resourceName: string }>;
        }>;
      };
      expect(state.findings).toHaveLength(1);
      expect(state.findings[0]).toMatchObject({
        key: "applications-remove-implicit",
        title: "Remove the Implicit grant type from",
        selectionMode: "applications",
        actionableChanges: [
          { resourceName: "App One" },
          { resourceName: "App Two" },
        ],
      });
      expect(triageFindings).not.toHaveBeenCalled();

      const selectedActionId =
        state.findings[0]!.actionableChanges[0]!.actionId;
      const save = await fetch(`${running.url}/api/decision`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          findingKey: state.findings[0]!.key,
          status: "approved",
          rationale: "",
          selectedActionIds: [selectedActionId],
        }),
      });
      expect(save.status).toBe(200);
      const stored = reviewSessionSchema.parse(
        JSON.parse(await readFile(running.outputPath, "utf8")) as unknown,
      );
      expect(stored.decisions).toHaveLength(2);
      expect(
        stored.decisions.map((decision) => decision.decision.status),
      ).toEqual(["approved", "accepted_risk"]);
      expect(
        stored.decisions.map((decision) => decision.decision.rationale),
      ).toEqual(["Accepted AI suggestion.", "Remained unchanged."]);
      expect(
        stored.decisions.every(
          (decision) => decision.decision.adminNote === undefined,
        ),
      ).toBe(true);
    } finally {
      await running.close();
    }
  });

  it("groups insecure callback removals by application with selectable URLs", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-ui-"));
    const reportPath = path.join(directory, "callbacks.json");
    await writeFile(
      reportPath,
      JSON.stringify([
        {
          finding_name: "checkAllowedCallbacks",
          finding_title: "Application Allowed Callbacks",
          status: "red",
          severity: "High",
          name: "Assistant0 (client_assistant0) (First-Party Application)",
          field: "insecure_callbacks",
          value: "http://localhost:3000/auth/callback",
          message: "An insecure callback URL is allowed.",
        },
        {
          finding_name: "checkAllowedCallbacks",
          finding_title: "Application Allowed Callbacks",
          status: "red",
          severity: "High",
          name: "Assistant0 (client_assistant0) (First-Party Application)",
          field: "insecure_callbacks",
          value: "http://localhost:4000/auth/callback",
          message: "An insecure callback URL is allowed.",
        },
      ]),
    );
    const triageFindings = vi.fn().mockResolvedValue([]);
    const provider: AiProvider = {
      analyseFinding: vi.fn().mockRejectedValue(new Error("not called")),
      triageFindings,
    };
    const currentCallbacks = [
      "http://localhost:3000/auth/callback",
      "http://localhost:4000/auth/callback",
      "https://assistant.example.com/auth/callback",
    ];
    const configurationLoader = vi.fn(
      (findings: readonly NormalizedCheckmateFinding[]) =>
        Promise.resolve(
          new Map(
            findings.map((finding, index): [string, ActionableChange[]] => [
              finding.id,
              [
                {
                  resourceType: "client",
                  resourceId: "client_assistant0",
                  resourceName: "Assistant0",
                  configPath: "callbacks",
                  currentValue: currentCallbacks,
                  targetValue: currentCallbacks.filter((callback) =>
                    index === 0
                      ? !callback.includes("localhost:3000")
                      : !callback.includes("localhost:4000"),
                  ),
                },
              ],
            ]),
          ),
        ),
    );
    const running = await startUiServer(
      {
        report: reportPath,
        profile: "dev",
        status: "failed",
        port: 0,
        outputDirectory: directory,
      },
      {
        provider,
        configurationLoader,
        env: {
          AUTH0CHECKMATE_DEV_DOMAIN: "tenant.auth0.com",
          AUTH0CHECKMATE_DEV_CLIENT_ID: "client-id",
          AUTH0CHECKMATE_DEV_CLIENT_SECRET: "client-secret",
        },
        now: () => new Date("2026-07-25T10:00:00.000Z"),
      },
    );

    try {
      const root = await fetch(running.url);
      const cookie = root.headers.get("set-cookie")?.split(";")[0];
      const response = await fetch(`${running.url}/api/triage`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: "{}",
      });
      expect(response.status).toBe(200);
      const state = (await response.json()) as {
        findings: Array<{
          key: string;
          title: string;
          selectionMode: string;
          actionableChanges: Array<{
            actionId: string;
            currentValue: string[];
            targetValue: string[];
          }>;
        }>;
      };
      expect(state.findings).toHaveLength(1);
      expect(state.findings[0]).toMatchObject({
        title: "Remove insecure callback URLs from Assistant0",
        selectionMode: "changes",
      });
      expect(state.findings[0]?.actionableChanges).toHaveLength(2);
      expect(triageFindings).not.toHaveBeenCalled();

      const selectedActionId =
        state.findings[0]!.actionableChanges[0]!.actionId;
      const save = await fetch(`${running.url}/api/decision`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          findingKey: state.findings[0]!.key,
          status: "approved",
          rationale: "",
          selectedActionIds: [selectedActionId],
        }),
      });
      expect(save.status).toBe(200);
      const stored = reviewSessionSchema.parse(
        JSON.parse(await readFile(running.outputPath, "utf8")) as unknown,
      );
      expect(stored.decisions).toHaveLength(2);
      expect(
        stored.decisions.map((decision) => decision.decision.status),
      ).toEqual(["approved", "accepted_risk"]);
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
