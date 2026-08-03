import { describe, expect, it, vi } from "vitest";
import {
  executeApiPlan,
  validateApiPlan,
} from "../src/auth0/api-plan-executor.js";
import type { Fetcher } from "../src/auth0/fetcher.js";
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
    alreadyCompliantActionIds: [],
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
    alreadyCompliantActionIds: [],
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

function clientPlan(): ApiPlan {
  return {
    schemaVersion: 1,
    generatedAt: "2026-07-10T10:00:00.000Z",
    sourceReport: "/reports/report.json",
    profile: "dev",
    unchangedActionIds: [],
    alreadyCompliantActionIds: [],
    calls: [
      {
        id: "api-call-1",
        method: "PATCH",
        endpoint: "/api/v2/clients/client_12345678",
        resourceType: "client",
        resourceId: "client_12345678",
        resourceName: "Test App",
        bodyStrategy: "merge_live_nested_objects",
        actionIds: ["action-alg", "action-cross-origin", "action-implicit"],
        preconditions: [
          { path: "jwt_configuration.alg", expectedValue: "HS256" },
          { path: "cross_origin_authentication", expectedValue: true },
          {
            path: "grant_types",
            expectedValue: ["authorization_code", "implicit", "refresh_token"],
          },
        ],
        body: {
          jwt_configuration: { alg: "RS256" },
          cross_origin_authentication: false,
          grant_types: ["authorization_code", "refresh_token"],
        },
      },
    ],
  };
}

describe("Auth0 API plan executor", () => {
  it("validates live API preconditions without making a PATCH request", async () => {
    const before = {
      id: "con_database",
      options: {
        passwordPolicy: "fair",
        password_history: { enable: false },
      },
    };
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "management-token" })),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify(before)));

    const result = await validateApiPlan(plan(), config, {
      fetcher,
      includeRequestBodies: true,
    });

    expect(result).toMatchObject({
      valid: true,
      profile: "dev",
      calls: [{ status: "ready" }],
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(result.calls[0]?.requestBody).toEqual({
      options: {
        passwordPolicy: "good",
        password_history: { enable: true },
      },
    });
    expect(result.calls[0]?.requestSha256).toMatch(/^[a-f0-9]{64}$/);
    const validationTokenBody = JSON.parse(
      fetcher.mock.calls[0]?.[1]?.body as string,
    ) as { scope: string };
    expect(validationTokenBody.scope).toContain("read:connections");
    expect(validationTokenBody.scope).toContain("update:connections");
    expect(
      fetcher.mock.calls.some(([, request]) => request?.method === "PATCH"),
    ).toBe(false);
  });

  it("rejects API validation when Auth0 reports a missing update scope", async () => {
    const fetcher = vi.fn<Fetcher>().mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: "management-token",
          scope: "read:connections read:connections_options",
        }),
      ),
    );

    await expect(validateApiPlan(plan(), config, { fetcher })).rejects.toThrow(
      "missing required scopes",
    );
    expect(fetcher).toHaveBeenCalledOnce();
  });

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

  it("omits null live connection options when executing an independent change", async () => {
    const minimumLengthPlan: ApiPlan = {
      ...plan(),
      calls: [
        {
          ...plan().calls[0]!,
          actionIds: ["action-minimum-length"],
          preconditions: [
            {
              path: "options.password_complexity_options.min_length",
              expectedValue: 1,
            },
          ],
          body: {
            options: { password_complexity_options: { min_length: 12 } },
          },
        },
      ],
    };
    const before = {
      id: "con_database",
      options: {
        passwordPolicy: null,
        password_complexity_options: { min_length: 1 },
        requires_username: false,
      },
    };
    const after = {
      ...before,
      options: {
        ...before.options,
        password_complexity_options: { min_length: 12 },
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

    const result = await executeApiPlan(minimumLengthPlan, config, { fetcher });

    expect(result.status).toBe("succeeded");
    expect(JSON.parse(fetcher.mock.calls[2]?.[1]?.body as string)).toEqual({
      options: {
        password_complexity_options: { min_length: 12 },
        requires_username: false,
      },
    });
  });

  it("includes Auth0 error details when a PATCH is rejected", async () => {
    const before = {
      id: "con_database",
      options: {
        passwordPolicy: "fair",
        password_history: { enable: false },
      },
    };
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "management-token" })),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify(before)))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ message: "Payload validation failed" }), {
          status: 400,
        }),
      );

    const result = await executeApiPlan(plan(), config, { fetcher });

    expect(result.status).toBe("failed");
    expect(result.error).toContain("status 400: Payload validation failed");
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

  it("stops when the execution request differs from the confirmed preview", async () => {
    const before = {
      id: "con_database",
      options: {
        passwordPolicy: "fair",
        password_history: { enable: false },
      },
    };
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "management-token" })),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify(before)));

    const result = await executeApiPlan(plan(), config, {
      fetcher,
      approvedRequestDigests: { "api-call-1": "0".repeat(64) },
    });

    expect(result.status).toBe("failed");
    expect(result.error).toContain("no longer matches the confirmed preview");
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(
      fetcher.mock.calls.some(([, request]) => request?.method === "PATCH"),
    ).toBe(false);
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

  it("validates and safely merges application-level changes", async () => {
    const before = {
      client_id: "client_12345678",
      name: "Test App",
      jwt_configuration: {
        alg: "HS256",
        lifetime_in_seconds: 36000,
        secret_encoded: false,
      },
      cross_origin_authentication: true,
      grant_types: ["authorization_code", "implicit", "refresh_token"],
    };
    const after = {
      ...before,
      jwt_configuration: {
        ...before.jwt_configuration,
        alg: "RS256",
      },
      cross_origin_authentication: false,
      grant_types: ["authorization_code", "refresh_token"],
    };
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "management-token" })),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify(before)))
      .mockResolvedValueOnce(new Response(JSON.stringify(after)))
      .mockResolvedValueOnce(new Response(JSON.stringify(after)));

    const result = await executeApiPlan(clientPlan(), config, { fetcher });

    expect(result.status).toBe("succeeded");
    const tokenBody = JSON.parse(
      fetcher.mock.calls[0]?.[1]?.body as string,
    ) as {
      scope: string;
    };
    expect(tokenBody.scope).toContain("read:clients");
    expect(tokenBody.scope).toContain("update:clients");
    expect(JSON.parse(fetcher.mock.calls[2]?.[1]?.body as string)).toEqual({
      jwt_configuration: {
        alg: "RS256",
        lifetime_in_seconds: 36000,
        secret_encoded: false,
      },
      cross_origin_authentication: false,
      grant_types: ["authorization_code", "refresh_token"],
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
