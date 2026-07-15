import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Fetcher } from "../src/auth0/fetcher.js";
import { loadCheckmateReport } from "../src/checkmate/report-loader.js";
import {
  executeChatDevPlan,
  prepareChatDevPlan,
} from "../src/chat/dev-remediation-service.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("chat dev remediation service", () => {
  it("maps a recommended report finding to an exact validated dev PATCH preview", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "chat-dev-plan-"));
    const reportId = "latest-report.json";
    const reportPath = path.join(directory, reportId);
    await writeFile(
      reportPath,
      JSON.stringify([
        {
          finding_name: "checkGrantTypes",
          finding_title: "Application Grant Types",
          severity: "High",
          name: "GrantMate (prod_client_12345678) (Regular Web App)",
          field: "unexpected_grant_type_for_app_type",
          value: "implicit",
          message: "Unexpected implicit grant type enabled.",
        },
      ]),
    );
    const report = await loadCheckmateReport(reportPath);
    const findingId = report.findings[0]!.id;
    const liveClient = {
      client_id: "dev_client_87654321",
      name: "GrantMate",
      app_type: "regular_web",
      grant_types: ["authorization_code", "implicit", "refresh_token"],
      jwt_configuration: { alg: "RS256", lifetime_in_seconds: 36000 },
    };
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "read-token" })),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify([liveClient])))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "validation-token" })),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify(liveClient)));
    vi.stubGlobal("fetch", fetcher);

    const prepared = await prepareChatDevPlan({
      reportsDirectory: directory,
      reportId,
      findingIds: [findingId],
      env: {
        AUTH0CHECKMATE_DEV_DOMAIN: "dev-tenant.auth0.com",
        AUTH0CHECKMATE_DEV_CLIENT_ID: "dev-m2m-client",
        AUTH0CHECKMATE_DEV_CLIENT_SECRET: "dev-m2m-secret",
        AUTH0CHECKMATE_PROD_DOMAIN: "dev-tenant.auth0.com",
      },
      now: () => new Date("2026-07-14T14:00:00.000Z"),
    });

    expect(prepared.preview).toMatchObject({
      profile: "dev",
      tenantDomain: "dev-tenant.auth0.com",
      sourceReport: reportId,
      calls: [
        {
          method: "PATCH",
          url: "https://dev-tenant.auth0.com/api/v2/clients/dev_client_87654321",
          resourceName: "GrantMate",
          status: "ready",
          body: {
            grant_types: ["authorization_code", "refresh_token"],
          },
          changes: [
            expect.objectContaining({
              findingId,
              description: "Remove the Implicit grant type from GrantMate.",
            }),
          ],
        },
      ],
    });
    expect(prepared.preview.planSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(prepared.approvedRequestDigests["api-call-1"]).toMatch(
      /^[a-f0-9]{64}$/,
    );
    expect(prepared.plan.profile).toBe("dev");
    expect(
      fetcher.mock.calls.some(([, request]) => request?.method === "PATCH"),
    ).toBe(false);
    await expect(
      executeChatDevPlan({
        plan: prepared.plan,
        approvedRequestDigests: prepared.approvedRequestDigests,
        expectedTenantDomain: prepared.preview.tenantDomain,
        env: {
          AUTH0CHECKMATE_DEV_DOMAIN: "dev-tenant.auth0.com",
          AUTH0CHECKMATE_DEV_CLIENT_ID: "dev-m2m-client",
          AUTH0CHECKMATE_DEV_CLIENT_SECRET: "dev-m2m-secret",
          AUTH0CHECKMATE_PROD_DOMAIN: "dev-tenant.auth0.com",
        },
      }),
    ).rejects.toThrow("CHECKMATE_CHAT_DEV_WRITE_DOMAIN");
  });
});
