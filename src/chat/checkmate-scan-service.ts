import path from "node:path";
import { executeScan } from "../commands/scan.js";
import { loadCheckmateConfig } from "../config/env.js";
import type { ProfileName } from "../config/profiles.js";

export interface ChatCheckmateScanInput {
  profile: ProfileName;
  reportsDirectory: string;
  env?: NodeJS.ProcessEnv;
}

export interface ChatCheckmateScanResult {
  profile: ProfileName;
  tenantDomain: string;
  reportId: string;
  startedAt: string;
  finishedAt: string;
  checkmateVersion?: string;
}

export interface ChatCheckmateScanDependencies {
  scanExecutor?: typeof executeScan;
}

export async function runChatCheckmateScan(
  input: ChatCheckmateScanInput,
  dependencies: ChatCheckmateScanDependencies = {},
): Promise<ChatCheckmateScanResult> {
  const env = input.env ?? process.env;
  const config = loadCheckmateConfig(input.profile, env);
  const reportsDirectory = path.resolve(input.reportsDirectory);
  if (config.outputDirectory !== reportsDirectory) {
    throw new Error(
      "CHECKMATE_REPORTS_DIR and AUTH0CHECKMATE_FILE_PATH must resolve to the same report directory.",
    );
  }
  const metadata = await (dependencies.scanExecutor ?? executeScan)(
    { profile: input.profile },
    { env },
  );
  const reportPath = path.resolve(metadata.reportPath);
  if (path.dirname(reportPath) !== reportsDirectory) {
    throw new Error(
      "CheckMate created its report outside the configured report directory.",
    );
  }
  const reportId = path.basename(reportPath);
  if (!reportId.toLowerCase().endsWith(".json")) {
    throw new Error("CheckMate did not create a JSON report.");
  }
  return {
    profile: input.profile,
    tenantDomain: config.domain,
    reportId,
    startedAt: metadata.startedAt,
    finishedAt: metadata.finishedAt,
    ...(metadata.checkmateVersion
      ? { checkmateVersion: metadata.checkmateVersion }
      : {}),
  };
}
