import { describe, expect, it, vi } from "vitest";
import { loadActionableConfiguration } from "../src/auth0/configuration-reader.js";
import type { Fetcher } from "../src/auth0/application-inventory.js";
import type { CheckmateConfig } from "../src/config/env.js";
import type { NormalizedCheckmateFinding } from "../src/findings/types.js";

const config: CheckmateConfig = {
  profile: "dev",
  domain: "tenant.auth0.com",
  clientId: "client-id",
  clientSecret: "client-secret",
  outputDirectory: "/tmp",
  disablePdfReporting: true,
  timeoutMs: 30_000,
};

const passwordPolicyFinding: NormalizedCheckmateFinding = {
  id: "password-policy",
  validatorId: "checkPasswordPolicy",
  title: "Databases - Password Policy",
  status: "failed",
  affectedResource: { name: "Username-Password-Authentication" },
  raw: {},
};

describe("Auth0 actionable configuration reader", () => {
  it("reads the live password policy and creates an exact change", async () => {
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "management-token" })),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify([
            {
              id: "con_database",
              name: "Username-Password-Authentication",
              strategy: "auth0",
              options: { passwordPolicy: "fair" },
            },
          ]),
        ),
      );

    const result = await loadActionableConfiguration(
      [passwordPolicyFinding],
      config,
      fetcher,
    );

    expect(result.get("password-policy")).toEqual([
      {
        resourceType: "connection",
        resourceId: "con_database",
        resourceName: "Username-Password-Authentication",
        configPath: "options.passwordPolicy",
        currentValue: "fair",
        targetValue: "good",
      },
    ]);
    const requestBody = fetcher.mock.calls[0]?.[1]?.body;
    expect(typeof requestBody).toBe("string");
    if (typeof requestBody !== "string") {
      throw new Error("Expected a JSON token request body.");
    }
    const tokenBody = JSON.parse(requestBody) as { scope: string };
    expect(tokenBody.scope).toContain("read:connections_options");
  });

  it("does not propose legacy fields for a flexible password policy", async () => {
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "management-token" })),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify([
            {
              id: "con_database",
              name: "Username-Password-Authentication",
              strategy: "auth0",
              options: { password_options: { policy_version: 2 } },
            },
          ]),
        ),
      );

    const result = await loadActionableConfiguration(
      [passwordPolicyFinding],
      config,
      fetcher,
    );
    expect(result.size).toBe(0);
  });

  it("does not treat a brute-force mode difference as an easy toggle", async () => {
    const finding: NormalizedCheckmateFinding = {
      id: "brute-force",
      validatorId: "checkBruteForce",
      title: "Brute Force Protection",
      status: "failed",
      raw: {},
    };
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "management-token" })),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            enabled: true,
            shields: ["block", "user_notification"],
            mode: "count_per_identifier_and_ip",
            allowlist: [],
          }),
        ),
      );

    const result = await loadActionableConfiguration(
      [finding],
      config,
      fetcher,
    );
    expect(result.size).toBe(0);
  });
});
