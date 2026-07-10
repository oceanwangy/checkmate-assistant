import { describe, expect, it, vi } from "vitest";
import {
  listAuth0Applications,
  type Fetcher,
} from "../src/auth0/application-inventory.js";
import type { CheckmateConfig } from "../src/config/env.js";

const config: CheckmateConfig = {
  profile: "dev",
  domain: "tenant.auth0.com",
  clientId: "checkmate-client",
  clientSecret: "never-print-this",
  outputDirectory: "/tmp/reports",
  disablePdfReporting: true,
  timeoutMs: 10_000,
};

describe("Auth0 application inventory", () => {
  it("uses a narrow read-only client listing and returns selectable applications", async () => {
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "management-token" }), {
          status: 200,
        }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify([
            { client_id: "client-b", name: "Beta", app_type: "regular_web" },
            { client_id: "client-a", name: "Alpha", app_type: "spa" },
          ]),
          { status: 200 },
        ),
      );

    await expect(listAuth0Applications(config, fetcher)).resolves.toEqual([
      { clientId: "client-a", name: "Alpha", appType: "spa" },
      { clientId: "client-b", name: "Beta", appType: "regular_web" },
    ]);
    expect(fetcher).toHaveBeenCalledTimes(2);
    const requestBody = fetcher.mock.calls[0]?.[1]?.body;
    expect(typeof requestBody).toBe("string");
    if (typeof requestBody !== "string")
      throw new Error("Expected a JSON request body.");
    const tokenBody = JSON.parse(requestBody) as unknown;
    expect(tokenBody).toMatchObject({ scope: "read:clients" });
    const clientsUrl = String(fetcher.mock.calls[1]?.[0]);
    expect(clientsUrl).toContain("/api/v2/clients");
    expect(clientsUrl).toContain("fields=client_id%2Cname%2Capp_type");
  });

  it("does not expose credentials when Auth0 rejects the request", async () => {
    const fetcher: Fetcher = () =>
      Promise.resolve(new Response("denied", { status: 401 }));
    await expect(listAuth0Applications(config, fetcher)).rejects.not.toThrow(
      "never-print-this",
    );
  });
});
