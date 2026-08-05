import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runChatCheckmateScan } from "../src/chat/checkmate-scan-service.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, {
        recursive: true,
        force: true,
      }),
    ),
  );
});

describe("chat CheckMate scan service", () => {
  it("runs the selected profile and returns a report ID inside the MCP directory", async () => {
    const reportsDirectory = await mkdtemp(
      path.join(tmpdir(), "checkmate-chat-scan-"),
    );
    temporaryDirectories.push(reportsDirectory);
    const reportPath = path.join(reportsDirectory, "dev-report.json");
    const scanExecutor = vi.fn().mockResolvedValue({
      profile: "dev",
      targetDomain: "dev-tenant.auth0.com",
      startedAt: "2026-08-05T09:00:00.000Z",
      finishedAt: "2026-08-05T09:01:00.000Z",
      checkmateVersion: "1.8.3",
      reportPath,
      exitCode: 0,
    });

    const result = await runChatCheckmateScan(
      {
        profile: "dev",
        reportsDirectory,
        env: {
          AUTH0CHECKMATE_DEV_DOMAIN: "dev-tenant.auth0.com",
          AUTH0CHECKMATE_DEV_CLIENT_ID: "dev-client",
          AUTH0CHECKMATE_DEV_CLIENT_SECRET: "dev-secret",
          AUTH0CHECKMATE_FILE_PATH: reportsDirectory,
        },
      },
      { scanExecutor },
    );

    expect(result).toMatchObject({
      profile: "dev",
      tenantDomain: "dev-tenant.auth0.com",
      reportId: "dev-report.json",
      checkmateVersion: "1.8.3",
    });
    expect(scanExecutor).toHaveBeenCalledOnce();
    expect(scanExecutor.mock.calls[0]?.[0]).toEqual({ profile: "dev" });
    expect(scanExecutor.mock.calls[0]?.[1]).toMatchObject({
      env: {
        AUTH0CHECKMATE_DEV_DOMAIN: "dev-tenant.auth0.com",
      },
    });
  });

  it("rejects a report directory that differs from the CheckMate output directory", async () => {
    const reportsDirectory = await mkdtemp(
      path.join(tmpdir(), "checkmate-chat-reports-"),
    );
    const outputDirectory = await mkdtemp(
      path.join(tmpdir(), "checkmate-chat-output-"),
    );
    temporaryDirectories.push(reportsDirectory, outputDirectory);

    await expect(
      runChatCheckmateScan({
        profile: "prod",
        reportsDirectory,
        env: {
          AUTH0CHECKMATE_PROD_DOMAIN: "prod-tenant.auth0.com",
          AUTH0CHECKMATE_PROD_CLIENT_ID: "prod-client",
          AUTH0CHECKMATE_PROD_CLIENT_SECRET: "prod-secret",
          AUTH0CHECKMATE_FILE_PATH: outputDirectory,
        },
      }),
    ).rejects.toThrow(
      "CHECKMATE_REPORTS_DIR and AUTH0CHECKMATE_FILE_PATH must resolve to the same report directory.",
    );
  });
});
