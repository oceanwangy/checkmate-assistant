import path from "node:path";
import { InvalidArgumentError, Option, type Command } from "commander";
import type { AiProvider } from "../ai/provider.js";
import { collectSensitiveEnvironmentValues } from "../ai/finding-payload.js";
import { OpenAiProvider } from "../ai/openai-provider.js";
import { loadAiConfig } from "../config/ai.js";
import { loadCheckmateReport } from "../checkmate/report-loader.js";
import {
  filterFindings,
  type FindingStatusFilter,
} from "../findings/filter.js";
import {
  formatAiAnalysis,
  formatFindingForReview,
} from "../findings/review-formatter.js";
import { prioritizeFindings } from "../findings/priority.js";
import {
  createReviewOutputPath,
  writeReviewSession,
} from "../remediation/review-writer.js";
import type {
  ReviewAnswer,
  ReviewSession,
} from "../remediation/review-schema.js";
import {
  ConsoleReviewPrompt,
  type ReviewPrompt,
} from "../remediation/review-prompt.js";
import { planReviewQuestions } from "../remediation/question-planner.js";
import {
  boundedAnswer,
  boundedUserText,
  createReviewEntry,
  redactAnalysis,
} from "../remediation/review-entry.js";
import { displayPath } from "../utils/filesystem.js";

interface ReviewOptions {
  report: string;
  status: FindingStatusFilter;
  limit?: number;
  showExplanation?: boolean;
}

export interface ReviewDependencies {
  provider?: AiProvider;
  prompt?: ReviewPrompt;
  env?: NodeJS.ProcessEnv;
  model?: string;
  outputDirectory?: string;
  now?: () => Date;
}

export interface ReviewResult {
  outputPath: string;
  session: ReviewSession;
}

function positiveInteger(value: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new InvalidArgumentError("Limit must be a positive integer.");
  }
  return parsed;
}

export async function executeReview(
  options: ReviewOptions,
  dependencies: ReviewDependencies = {},
): Promise<ReviewResult | undefined> {
  const env = dependencies.env ?? process.env;
  const sensitiveValues = collectSensitiveEnvironmentValues(env);
  const report = await loadCheckmateReport(options.report);
  const filtered = prioritizeFindings(
    filterFindings(report.findings, options.status),
  );
  const findings = options.limit ? filtered.slice(0, options.limit) : filtered;
  if (findings.length === 0) {
    console.log("No findings matched the selected review status.");
    return undefined;
  }

  let model = dependencies.model;
  let provider = dependencies.provider;
  if (!provider) {
    const config = loadAiConfig(env);
    model = config.model;
    provider = new OpenAiProvider({
      apiKey: config.apiKey,
      model: config.model,
      timeoutMs: config.timeoutMs,
      reasoningEffort: config.reasoningEffort,
      sensitiveValues,
    });
  }
  model ??= "injected-test-provider";

  const now = dependencies.now ?? (() => new Date());
  const startedAt = now();
  const outputPath = createReviewOutputPath(
    report.sourcePath,
    startedAt,
    dependencies.outputDirectory ?? path.resolve("remediation-plans"),
  );
  const session: ReviewSession = {
    schemaVersion: 1,
    report: { sourceReport: report.sourcePath },
    review: {
      model,
      startedAt: startedAt.toISOString(),
      lastUpdatedAt: startedAt.toISOString(),
    },
    decisions: [],
  };
  if (report.tenant) session.report.tenant = report.tenant;
  if (report.generatedAt) session.report.reportTimestamp = report.generatedAt;

  const prompt = dependencies.prompt ?? new ConsoleReviewPrompt();
  console.log(
    `Reviewing ${findings.length} CheckMate finding(s) with ${model}.`,
  );
  console.log(
    "Do not enter secrets, tokens, passwords, or API keys in your answers.",
  );

  try {
    for (const [index, finding] of findings.entries()) {
      console.log(
        `\n${formatFindingForReview(finding, index + 1, findings.length, sensitiveValues)}`,
      );
      console.log("\nAnalysing this finding with OpenAI...");
      const modelAnalysis = redactAnalysis(
        await provider.analyseFinding(finding, { answers: {} }),
        sensitiveValues,
      );
      const analysis = planReviewQuestions(finding, modelAnalysis);
      console.log(
        `\n${formatAiAnalysis(analysis, options.showExplanation ?? false)}`,
      );

      const answers: ReviewAnswer[] = [];
      for (const question of analysis.questions) {
        const answer = await prompt.askFindingQuestion(question);
        answers.push({
          questionId: question.id,
          prompt: question.prompt,
          inputType: question.inputType,
          answer: boundedAnswer(answer, sensitiveValues),
        });
      }
      const decision = await prompt.selectDecision();
      const rationale = boundedUserText(
        await prompt.askRationale(),
        sensitiveValues,
      );
      const decidedAt = now().toISOString();
      session.decisions.push(
        createReviewEntry(
          finding,
          analysis,
          answers,
          decision,
          rationale,
          decidedAt,
          sensitiveValues,
        ),
      );
      session.review.lastUpdatedAt = decidedAt;
      await writeReviewSession(outputPath, session);
      console.log(`Decision saved: ${decision}`);
    }

    const completedAt = now().toISOString();
    session.review.completedAt = completedAt;
    session.review.lastUpdatedAt = completedAt;
    await writeReviewSession(outputPath, session);
    console.log(`\nReview complete. Decisions: ${displayPath(outputPath)}`);
    return { outputPath, session };
  } finally {
    prompt.close();
  }
}

export function registerReviewCommand(program: Command): void {
  program
    .command("review")
    .description("Review CheckMate findings with OpenAI and record decisions")
    .requiredOption("--report <report>", "path to a CheckMate JSON report")
    .addOption(
      new Option("--status <status>", "filter findings before review")
        .choices(["failed", "warning", "passed", "unknown", "all"])
        .default("failed"),
    )
    .option(
      "--limit <number>",
      "review at most this many findings",
      positiveInteger,
    )
    .option(
      "--show-explanation",
      'show the optional "What it means" and "Why it matters" sections',
    )
    .action(async (options: ReviewOptions) => {
      await executeReview(options);
    });
}
