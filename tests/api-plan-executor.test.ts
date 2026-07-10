import { describe, expect, it, vi } from "vitest";
import { executeApiPlan } from "../src/auth0/api-plan-executor.js";
import type { Fetcher } from "../src/auth0/application-inventory.js";
import type { CheckmateConfig } from "../src/config/env.js";
import type { ApiPlan } from "../src/remediation/api-plan.js";

const config: CheckmateConfig = {
  profile: "dev",
  domain: "tenant.auth0.com",
  clientId: "executor-client",
  clientSecret: "executor-secret",
  outputDirectory: "/tmp/reports",
  disablePdfReporting: true,
  timeoutMs: 30_000,
};

function plan(): ApiPlan {
  return {
    schemaVersion: 1,
    generatedAt: "2026-07-10T10:00:00.000Z",
    sourceReport: "/reports/report.json",
    profile: "dev",
    unchangedActionIds: [],
    calls: [
      {
        id: "api-call-1",
        method: "PATCH",
        endpoint: "/api/v2/connections/con_database",
        resourceType: "connection",
        resourceId: "con_database",
        resourceName: "Username-Password-Authentication",
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
      },
    ],
  };
}

function attackPlan(): ApiPlan {
  return {
    schemaVersion: 1,
    generatedAt: "2026-07-10T10:00:00.000Z",
    sourceReport: "/reports/report.json",
    profile: "dev",
    unchangedActionIds: [],
    calls: [
      {
        id: "api-call-1",
        method: "PATCH",
        endpoint: "/api/v2/attack-protection/breached-password-detection",
        resourceType: "attack_protection",
        resourceId: "checkBreachedPassword",
        resourceName: "Breached Password Detection",
        bodyStrategy: "merge_live_nested_objects",
        actionIds: ["action-signup"],
        preconditions: [
          {
            path: "stage.pre-user-registration.shields",
            expectedValue: [],
          },
        ],
        body: {
          stage: { "pre-user-registration": { shields: ["block"] } },
        },
      },
    ],
  };
}

describe("Auth0 API plan executor", () => {
  it("merges planned connection changes into live options and verifies them", async () => {
    const before = {
      id: "con_database",
      name: "Username-Password-Authentication",
      options: {
        passwordPolicy: "fair",
        password_history: { enable: false, size: 5 },
        requires_username: false,
      },
    };
    const after = {
      ...before,
      options: {
        ...before.options,
        passwordPolicy: "good",
        password_history: { enable: true, size: 5 },
      },
    };
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "management-token" })),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify(before)))
      .mockResolvedValueOnce(new Response(JSON.stringify(after)))
      .mockResolvedValueOnce(new Response(JSON.stringify(after)));

    const result = await executeApiPlan(plan(), config, {
      fetcher,
      now: () => new Date("2026-07-10T10:01:00.000Z"),
    });

    expect(result.status).toBe("succeeded");
    expect(result.calls[0]?.status).toBe("applied");
    const tokenRequestBody = fetcher.mock.calls[0]?.[1]?.body;
    expect(typeof tokenRequestBody).toBe("string");
    const tokenBody = JSON.parse(tokenRequestBody as string) as {
      scope: string;
    };
    expect(tokenBody.scope).toContain("update:connections");
    expect(tokenBody.scope).toContain("update:connections_options");
    const patch = fetcher.mock.calls[2];
    expect(patch?.[1]?.method).toBe("PATCH");
    const patchBody = patch?.[1]?.body;
    expect(typeof patchBody).toBe("string");
    expect(JSON.parse(patchBody as string)).toEqual({
      options: {
        passwordPolicy: "good",
        password_history: { enable: true, size: 5 },
        requires_username: false,
      },
    });
    const headers = patch?.[1]?.headers as Record<string, string>;
    expect(headers["x-correlation-id"]).toMatch(/^checkmate-/);
  });

  it("stops without patching when a live value has drifted", async () => {
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "management-token" })),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            id: "con_database",
            options: {
              passwordPolicy: "excellent",
              password_history: { enable: false },
            },
          }),
        ),
      );

    const result = await executeApiPlan(plan(), config, { fetcher });

    expect(result.status).toBe("failed");
    expect(result.error).toContain("changed after the plan was created");
    expect(result.calls[0]?.status).toBe("failed");
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("preserves unselected nested attack-protection settings", async () => {
    const before = {
      enabled: true,
      stage: {
        "pre-user-registration": { shields: [] },
        "pre-change-password": { shields: ["block"] },
      },
    };
    const after = {
      ...before,
      stage: {
        ...before.stage,
        "pre-user-registration": { shields: ["block"] },
      },
    };
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "management-token" })),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify(before)))
      .mockResolvedValueOnce(new Response(JSON.stringify(after)))
      .mockResolvedValueOnce(new Response(JSON.stringify(after)));

    const result = await executeApiPlan(attackPlan(), config, { fetcher });

    expect(result.status).toBe("succeeded");
    const patchBody = fetcher.mock.calls[2]?.[1]?.body;
    expect(typeof patchBody).toBe("string");
    expect(JSON.parse(patchBody as string)).toEqual({
      stage: {
        "pre-user-registration": { shields: ["block"] },
        "pre-change-password": { shields: ["block"] },
      },
    });
  });

  it("rejects production execution", async () => {
    await expect(
      executeApiPlan(
        { ...plan(), profile: "prod" },
        { ...config, profile: "prod" },
      ),
    ).rejects.toThrow("restricted to the dev profile");
  });
});
