import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { ApiPlan } from "../src/remediation/api-plan.js";
import { buildTerraformReviewConfiguration } from "../src/remediation/terraform-plan.js";
import {
  validateTerraformConfiguration,
  type TerraformCommandRunner,
} from "../src/remediation/terraform-validator.js";

function plan(): ApiPlan {
  return {
    schemaVersion: 1,
    generatedAt: "2026-07-14T02:00:00.000Z",
    sourceReport: "/private/reports/tenant.json",
    profile: "dev",
    unchangedActionIds: ["action-unchanged"],
    alreadyCompliantActionIds: [],
    calls: [
      {
        id: "api-call-1",
        method: "PATCH",
        endpoint: "/api/v2/connections/con_dev",
        resourceType: "connection",
        resourceId: "con_dev",
        resourceName: "Username-Password-Authentication",
        bodyStrategy: "merge_live_connection_options",
        actionIds: ["action-history"],
        preconditions: [
          {
            path: "options.password_history.enable",
            expectedValue: false,
          },
        ],
        body: { options: { password_history: { enable: true } } },
      },
      {
        id: "api-call-2",
        method: "PATCH",
        endpoint: "/api/v2/clients/client_12345678",
        resourceType: "client",
        resourceId: "client_12345678",
        resourceName: "Test App",
        bodyStrategy: "merge_live_nested_objects",
        actionIds: ["action-implicit"],
        preconditions: [
          {
            path: "grant_types",
            expectedValue: ["authorization_code", "implicit"],
          },
        ],
        body: { grant_types: ["authorization_code"] },
      },
    ],
  };
}

describe("Terraform review output", () => {
  it("uses the official Auth0 provider without declaring partial managed resources", () => {
    const terraform = buildTerraformReviewConfiguration(plan());

    expect(terraform).toContain('source  = "auth0/auth0"');
    expect(terraform).toContain('version = "~> 1.51.0"');
    expect(terraform).toContain('data "auth0_connection"');
    expect(terraform).toContain('data "auth0_client"');
    expect(terraform).toContain('client_id = "client_12345678"');
    expect(terraform).toContain('connection_id        = "con_dev"');
    expect(terraform).toContain('path     = "options.password_history.enable"');
    expect(terraform).toContain("proposed = true");
    expect(terraform).not.toContain('resource "auth0_connection"');
    expect(terraform).not.toContain("/private/reports");
  });

  it("runs fmt, init, and validate as fixed Terraform commands", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-tf-"));
    const terraformFile = path.join(directory, "main.tf");
    await writeFile(terraformFile, buildTerraformReviewConfiguration(plan()));
    const runner = vi.fn<TerraformCommandRunner>().mockResolvedValue({
      exitCode: 0,
      stdout: "Success!",
      stderr: "",
    });

    const result = await validateTerraformConfiguration(terraformFile, {
      runner,
      env: { PATH: process.env.PATH },
      now: () => new Date("2026-07-14T03:00:00.000Z"),
    });

    expect(result.valid).toBe(true);
    expect(result.steps.map((step) => step.command)).toEqual([
      "fmt",
      "init",
      "validate",
    ]);
    expect(runner.mock.calls.map(([request]) => request.args[0])).toEqual([
      "fmt",
      "init",
      "validate",
    ]);
    expect(runner.mock.calls[0]?.[0].env).not.toHaveProperty(
      "AUTH0_CLIENT_SECRET",
    );
  });

  it("stops validation after the first failed command", async () => {
    const runner = vi.fn<TerraformCommandRunner>().mockResolvedValue({
      exitCode: 1,
      stdout: "",
      stderr: "File is not formatted.",
    });

    const result = await validateTerraformConfiguration("/tmp/main.tf", {
      runner,
    });

    expect(result).toMatchObject({
      valid: false,
      error: "File is not formatted.",
    });
    expect(runner).toHaveBeenCalledOnce();
  });
});
