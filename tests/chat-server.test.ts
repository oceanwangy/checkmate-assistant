import http from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ChatConfig } from "../apps/checkmate-chat/src/config.js";
import type {
  DevRemediationLike,
  PreparedDevPlanState,
} from "../apps/checkmate-chat/src/dev-remediation.js";
import type { McpHubLike } from "../apps/checkmate-chat/src/mcp-hub.js";
import { createChatServer } from "../apps/checkmate-chat/src/server.js";

const servers: http.Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers
      .splice(0)
      .map(
        (server) =>
          new Promise<void>((resolve) => server.close(() => resolve())),
      ),
  );
});

interface TestResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Record<string, unknown>;
}

function request(
  port: number,
  method: "GET" | "POST",
  pathname: string,
  options: {
    cookie?: string;
    csrf?: string;
    body?: Record<string, unknown>;
  } = {},
): Promise<TestResponse> {
  return new Promise((resolve, reject) => {
    const body = options.body ? JSON.stringify(options.body) : undefined;
    const headers: Record<string, string> = { host: "127.0.0.1:4320" };
    if (body) {
      headers["content-type"] = "application/json";
      headers.origin = "http://127.0.0.1:4320";
      headers["content-length"] = String(Buffer.byteLength(body));
    }
    if (options.cookie) headers.cookie = options.cookie;
    if (options.csrf) headers["x-csrf-token"] = options.csrf;
    const outgoing = http.request(
      { host: "127.0.0.1", port, method, path: pathname, headers },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          resolve({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: text ? (JSON.parse(text) as Record<string, unknown>) : {},
          });
        });
      },
    );
    outgoing.on("error", reject);
    if (body) outgoing.write(body);
    outgoing.end();
  });
}

describe("chat dev confirmation workflow", () => {
  it("previews a session-bound dev call and requires exact confirmation", async () => {
    const config: ChatConfig = {
      projectRoot: "/project",
      publicDirectory: "/project/public",
      reportsDirectory: "/project/reports",
      checkmateServerPath: "/project/checkmate.js",
      host: "127.0.0.1",
      port: 4320,
      model: "gpt-5.5",
      reasoningEffort: "high",
      openAiApiKey: "test-key",
      remediationUrl: "http://127.0.0.1:4317",
      auth0Enabled: false,
      auth0Command: process.execPath,
      auth0Arguments: [],
      devTenantDomain: "dev-tenant.auth0.com",
      devPlanningEnabled: true,
      devRemediationEnabled: true,
    };
    const hub: McpHubLike = {
      initialize: () => Promise.resolve(),
      close: () => Promise.resolve(),
      getTools: () => [],
      getStatus: () => ({
        checkmate: { enabled: true, connected: true, readOnly: true },
        auth0: { enabled: false, connected: false, readOnly: true },
      }),
      callTool: () =>
        Promise.resolve({
          server: "checkmate",
          tool: "checkmate_get_report_summary",
          isError: false,
          value: {
            report: {
              reportId: "latest-report.json",
              totalFindings: 1,
              counts: { passed: 0, failed: 1, warning: 0, unknown: 0 },
            },
          },
        }),
    };
    const agent = {
      answer: vi.fn().mockResolvedValue({
        answer: {
          headline: "Remove the implicit grant from GrantMate.",
          sections: [
            {
              title: "Recommended change",
              items: [
                {
                  text: "Remove implicit.",
                  basis: "checkmate_report",
                },
              ],
            },
          ],
          evidenceGaps: ["This internal limitation should not be displayed."],
          suggestedQuestions: [],
          actionConfirmations: [
            {
              question:
                "Would you like me to prepare removal of the Implicit grant for dev?",
              findingIds: ["finding-1"],
            },
          ],
        },
        evidence: {
          report: { reportId: "latest-report.json" },
          findingIds: ["finding-1"],
          tools: [],
        },
      }),
    };
    const prepared: PreparedDevPlanState = {
      plan: { profile: "dev" },
      approvedRequestDigests: { "api-call-1": "a".repeat(64) },
      preview: {
        profile: "dev",
        tenantDomain: "dev-tenant.auth0.com",
        sourceReport: "latest-report.json",
        generatedAt: "2026-07-14T14:00:00.000Z",
        planSha256: "b".repeat(64),
        calls: [
          {
            id: "api-call-1",
            method: "PATCH",
            url: "https://dev-tenant.auth0.com/api/v2/clients/client-1",
            endpoint: "/api/v2/clients/client-1",
            resourceName: "GrantMate",
            status: "ready",
            changes: [],
            body: { grant_types: ["authorization_code"] },
            sensitiveValuesRedacted: false,
          },
        ],
      },
    };
    const execute = vi.fn().mockResolvedValue({
      validation: {
        valid: true,
        validatedAt: "2026-07-14T14:01:00.000Z",
        calls: [],
      },
      execution: {
        status: "succeeded",
        startedAt: "2026-07-14T14:01:01.000Z",
        completedAt: "2026-07-14T14:01:02.000Z",
        profile: "dev",
        calls: [],
      },
    });
    const writeAudit = vi.fn().mockResolvedValue("/audit/plan.json");
    const remediation: DevRemediationLike = {
      prepare: vi.fn().mockResolvedValue(prepared),
      execute,
      writeAudit,
    };
    const server = createChatServer({ config, hub, agent, remediation });
    servers.push(server);
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No address");

    const status = await request(address.port, "GET", "/api/status");
    const cookie = status.headers["set-cookie"]?.[0]?.split(";")[0];
    const csrf = status.body.csrfToken;
    expect(cookie).toBeTruthy();
    expect(typeof csrf).toBe("string");
    if (!cookie || typeof csrf !== "string") {
      throw new Error("The test session was not created.");
    }

    const chat = await request(address.port, "POST", "/api/chat", {
      cookie,
      csrf,
      body: { question: "Harden GrantMate", history: [] },
    });
    expect(chat.status).toBe(200);
    expect(chat.body.answer).not.toHaveProperty("actionConfirmations");
    expect(
      (chat.body.answer as { evidenceGaps: unknown }).evidenceGaps,
    ).toEqual([]);
    const remediationOffer = chat.body.remediation as {
      actions: Array<{ recommendationId: string; question: string }>;
    };
    expect(remediationOffer.actions).toHaveLength(1);
    expect(remediationOffer.actions[0]?.question).toContain(
      "Would you like me",
    );
    const recommendation = remediationOffer.actions[0];
    if (!recommendation) throw new Error("No recommendation was offered");

    const plan = await request(address.port, "POST", "/api/dev-plan", {
      cookie,
      csrf,
      body: { recommendationId: recommendation.recommendationId },
    });
    expect(plan.status).toBe(200);
    const preview = plan.body.plan as {
      planId: string;
      planSha256: string;
      tenantDomain: string;
      executionEnabled: boolean;
    };
    expect(preview.executionEnabled).toBe(true);

    const rejected = await request(address.port, "POST", "/api/dev-execute", {
      cookie,
      csrf,
      body: {
        planId: preview.planId,
        planSha256: preview.planSha256,
        confirmed: true,
        tenantDomain: preview.tenantDomain,
        confirmationText: "NO",
      },
    });
    expect(rejected.status).toBe(400);
    expect(execute).not.toHaveBeenCalled();

    const executed = await request(address.port, "POST", "/api/dev-execute", {
      cookie,
      csrf,
      body: {
        planId: preview.planId,
        planSha256: preview.planSha256,
        confirmed: true,
        tenantDomain: preview.tenantDomain,
        confirmationText: "EXECUTE DEV",
      },
    });
    expect(executed.status).toBe(200);
    expect(executed.body).toMatchObject({
      executed: true,
      profile: "dev",
      tenantDomain: "dev-tenant.auth0.com",
    });
    expect(execute).toHaveBeenCalledOnce();
    expect(writeAudit).toHaveBeenCalledTimes(3);
  });
});
