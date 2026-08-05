import { describe, expect, it } from "vitest";
import { loadChatConfig } from "../apps/checkmate-chat/src/config.js";

const baseEnv: NodeJS.ProcessEnv = {
  OPENAI_API_KEY: "test-key",
  OPENAI_MODEL: "gpt-5.5",
  OPENAI_REASONING_EFFORT: "high",
  CHECKMATE_CHAT_MODEL: "gpt-5.4-mini",
  CHECKMATE_CHAT_REASONING_EFFORT: "low",
  AUTH0CHECKMATE_DEV_DOMAIN: "dev-tenant.auth0.com",
  AUTH0CHECKMATE_DEV_CLIENT_ID: "dev-client",
  AUTH0CHECKMATE_DEV_CLIENT_SECRET: "dev-secret",
  AUTH0CHECKMATE_PROD_DOMAIN: "prod-tenant.auth0.com",
  CHECKMATE_CHAT_DEV_WRITE_DOMAIN: "dev-tenant.auth0.com",
};

describe("chat configuration", () => {
  it("uses the requested OpenAI conversation settings and enables a distinct allowlisted dev tenant", () => {
    const config = loadChatConfig(baseEnv);

    expect(config.model).toBe("gpt-5.5");
    expect(config.reasoningEffort).toBe("high");
    expect(config.devPlanningEnabled).toBe(true);
    expect(config.devRemediationEnabled).toBe(true);
    expect(config.devTenantDomain).toBe("dev-tenant.auth0.com");
    expect(config.scanTargets.dev).toEqual({
      configured: true,
      tenantDomain: "dev-tenant.auth0.com",
    });
    expect(config.scanTargets.prod).toEqual({
      configured: false,
      tenantDomain: "prod-tenant.auth0.com",
    });
  });

  it("uses the explicit chat dev allowlist even when another workflow reuses the domain", () => {
    const config = loadChatConfig({
      ...baseEnv,
      AUTH0CHECKMATE_PROD_DOMAIN: "dev-tenant.auth0.com",
    });

    expect(config.devRemediationEnabled).toBe(true);
    expect(config.devPlanningEnabled).toBe(true);
    expect(config.devRemediationDisabledReason).toBeUndefined();
  });
});
