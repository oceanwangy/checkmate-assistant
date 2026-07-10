import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { collectSensitiveEnvironmentValues } from "../ai/finding-payload.js";
import { OpenAiProvider } from "../ai/openai-provider.js";
import {
  REPORT_GUIDANCE_PROMPTS,
  type ReportGuidancePromptName,
} from "../ai/report-guidance-prompts.js";
import { loadActionableConfiguration } from "../auth0/configuration-reader.js";
import { loadCheckmateReport } from "../checkmate/report-loader.js";
import { loadAiConfig } from "../config/ai.js";
import { initialiseEnvironment, loadCheckmateConfig } from "../config/env.js";
import { filterFindings } from "../findings/filter.js";

function argument(name: string): string {
  const index = process.argv.indexOf(name);
  const value = index >= 0 ? process.argv[index + 1] : undefined;
  if (!value) throw new Error(`Missing required argument: ${name}`);
  return value;
}

async function main(): Promise<void> {
  initialiseEnvironment();
  const reportPath = argument("--report");
  const profileName = argument("--profile");
  const env = process.env;
  const [report, aiConfig] = await Promise.all([
    loadCheckmateReport(reportPath),
    Promise.resolve(loadAiConfig(env)),
  ]);
  const findings = filterFindings(report.findings, "failed");
  const profile = loadCheckmateConfig(profileName, env);
  const actionableConfiguration = await loadActionableConfiguration(
    findings,
    profile,
  );
  const sensitiveValues = collectSensitiveEnvironmentValues(env);
  const evaluations = [];

  for (const [name, prompt] of Object.entries(REPORT_GUIDANCE_PROMPTS) as Array<
    [ReportGuidancePromptName, string]
  >) {
    const startedAt = new Date();
    const provider = new OpenAiProvider({
      apiKey: aiConfig.apiKey,
      model: aiConfig.model,
      timeoutMs: aiConfig.timeoutMs,
      reasoningEffort: aiConfig.reasoningEffort,
      sensitiveValues,
      triageInstructions: prompt,
    });
    const recommendations = await provider.triageFindings(
      findings,
      actionableConfiguration,
    );
    evaluations.push({
      name,
      prompt,
      recommendationCount: recommendations.length,
      recommendations,
      elapsedMs: Date.now() - startedAt.getTime(),
    });
    console.log(`${name}: ${recommendations.length} recommendations`);
  }

  const outputDirectory = path.resolve("prompt-evaluations");
  await mkdir(outputDirectory, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const outputPath = path.join(
    outputDirectory,
    `report-guidance-${timestamp}.json`,
  );
  await writeFile(
    outputPath,
    `${JSON.stringify(
      {
        schemaVersion: 1,
        model: aiConfig.model,
        reasoningEffort: aiConfig.reasoningEffort,
        report: path.basename(report.sourcePath),
        reportFindingCount: findings.length,
        actionableFindingCount: actionableConfiguration.size,
        evaluations,
      },
      null,
      2,
    )}\n`,
    { encoding: "utf8", mode: 0o600 },
  );
  console.log(`Saved evaluation: ${outputPath}`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : "Evaluation failed.");
  process.exitCode = 1;
});
