import { randomBytes, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type {
  AiFindingAnalysis,
  AiProvider,
  AiReportTriageItem,
} from "../ai/provider.js";
import { collectSensitiveEnvironmentValues } from "../ai/finding-payload.js";
import { OpenAiProvider } from "../ai/openai-provider.js";
import {
  loadActionableConfiguration,
  type ActionableConfigurationMap,
} from "../auth0/configuration-reader.js";
import {
  executeApiPlan,
  type ApiExecutionResult,
} from "../auth0/api-plan-executor.js";
import { loadCheckmateReport } from "../checkmate/report-loader.js";
import { executeScan } from "../commands/scan.js";
import { loadAiConfig } from "../config/ai.js";
import type { CheckmateConfig } from "../config/env.js";
import { profiles, type ProfileName } from "../config/profiles.js";
import { resolveReviewProfile } from "../config/review-profile.js";
import {
  filterFindings,
  type FindingStatusFilter,
} from "../findings/filter.js";
import type { NormalizedCheckmateFinding } from "../findings/types.js";
import type { ActionableChange } from "../remediation/actionable-change.js";
import { buildActionCandidates } from "../remediation/action-candidates.js";
import { buildApiPlan, type ApiPlan } from "../remediation/api-plan.js";
import {
  createApiPlanOutputPath,
  writeApiPlan,
} from "../remediation/api-plan-writer.js";
import { redactText } from "../security/redaction.js";
import {
  boundedUserText,
  createReviewEntry,
} from "../remediation/review-entry.js";
import type { ReviewSession } from "../remediation/review-schema.js";
import {
  createReviewOutputPath,
  writeReviewSession,
} from "../remediation/review-writer.js";
import { toErrorMessage } from "../utils/errors.js";

const HOST = "127.0.0.1";
const MAX_BODY_BYTES = 1_000_000;
const publicDirectory = fileURLToPath(new URL("./public/", import.meta.url));

const decisionRequestSchema = z
  .object({
    findingKey: z.string().min(1).max(500),
    status: z.enum(["approved", "accepted_risk"]),
    rationale: z.string().trim().min(1).max(4_000),
  })
  .strict();
const submitRequestSchema = z.object({}).strict();
const executeRequestSchema = z.object({ confirmed: z.literal(true) }).strict();
const scanRequestSchema = z
  .object({ profile: z.enum(["dev", "prod"]) })
  .strict();

export interface UiServerOptions {
  report?: string;
  status: FindingStatusFilter;
  port: number;
  profile?: string;
  outputDirectory?: string;
}

export interface UiServerDependencies {
  env?: NodeJS.ProcessEnv;
  provider?: AiProvider;
  model?: string;
  now?: () => Date;
  configurationLoader?: typeof loadActionableConfiguration;
  planExecutor?: typeof executeApiPlan;
  scanExecutor?: typeof executeScan;
}

export interface RunningUiServer {
  url: string;
  outputPath: string;
  close(): Promise<void>;
}

interface CachedFinding {
  finding: NormalizedCheckmateFinding;
}

interface CachedRecommendation {
  key: string;
  actionId: string;
  finding: NormalizedCheckmateFinding;
  title: string;
  analysis: AiFindingAnalysis;
  actionableChange: ActionableChange;
}

function securityHeaders(response: ServerResponse): void {
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  );
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Frame-Options", "DENY");
}

function sendJson(
  response: ServerResponse,
  status: number,
  value: unknown,
): void {
  securityHeaders(response);
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.end(JSON.stringify(value));
}

function sendError(
  response: ServerResponse,
  status: number,
  error: unknown,
): void {
  sendJson(response, status, { error: toErrorMessage(error) });
}

async function readBody(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const data: unknown = chunk;
    if (!(typeof data === "string" || data instanceof Uint8Array)) {
      throw new Error("Request body contains unsupported data.");
    }
    const buffer = Buffer.from(data);
    size += buffer.length;
    if (size > MAX_BODY_BYTES) throw new Error("Request body is too large.");
    chunks.push(buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    throw new Error("Request body must be valid JSON.");
  }
}

function hasSession(request: IncomingMessage, token: Buffer): boolean {
  const cookie = request.headers.cookie ?? "";
  const value = cookie
    .split(";")
    .map((item) => item.trim())
    .find((item) => item.startsWith("checkmate_session="))
    ?.slice("checkmate_session=".length);
  if (!value) return false;
  const candidate = Buffer.from(value, "hex");
  return candidate.length === token.length && timingSafeEqual(candidate, token);
}

function validLocalRequest(request: IncomingMessage): boolean {
  return /^127\.0\.0\.1(?::\d+)?$/.test(request.headers.host ?? "");
}

function validOrigin(request: IncomingMessage): boolean {
  return request.headers.origin === `http://${request.headers.host}`;
}

export async function startUiServer(
  options: UiServerOptions,
  dependencies: UiServerDependencies = {},
): Promise<RunningUiServer> {
  const env = dependencies.env ?? process.env;
  const sensitiveValues = collectSensitiveEnvironmentValues(env);
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
  const token = randomBytes(32);
  let report: Awaited<ReturnType<typeof loadCheckmateReport>> | undefined;
  let findings: NormalizedCheckmateFinding[] = [];
  let cachedFindings: CachedFinding[] = [];
  let profile: CheckmateConfig | undefined;
  let outputPath: string | undefined;
  let session: ReviewSession | undefined;
  let triaged = false;
  let recommendations: CachedRecommendation[] = [];
  const recommendationMap = new Map<string, CachedRecommendation>();
  let triagePromise: Promise<void> | undefined;
  let submittedYamlPath: string | undefined;
  let submittedPlan: ApiPlan | undefined;
  let execution: ApiExecutionResult | undefined;
  let executing = false;
  let scanning = false;

  const availableProfiles = (["dev", "prod"] as const).filter((name) => {
    const definition = profiles[name];
    return Boolean(
      env[definition.domainEnv]?.trim() &&
      env[definition.clientIdEnv]?.trim() &&
      env[definition.clientSecretEnv]?.trim(),
    );
  });

  const initialiseReport = async (
    reportPath: string,
    requestedProfile?: ProfileName,
  ): Promise<void> => {
    const loaded = await loadCheckmateReport(reportPath);
    const selectedFindings = filterFindings(loaded.findings, options.status);
    if (selectedFindings.length === 0) {
      throw new Error("No findings matched the selected status.");
    }
    const startedAt = now();
    const nextOutputPath = createReviewOutputPath(
      loaded.sourcePath,
      startedAt,
      options.outputDirectory ?? path.resolve("remediation-plans"),
    );
    const nextSession: ReviewSession = {
      schemaVersion: 1,
      report: { sourceReport: loaded.sourcePath },
      review: {
        model,
        startedAt: startedAt.toISOString(),
        lastUpdatedAt: startedAt.toISOString(),
      },
      decisions: [],
    };
    if (loaded.tenant) nextSession.report.tenant = loaded.tenant;
    if (loaded.generatedAt) {
      nextSession.report.reportTimestamp = loaded.generatedAt;
    }
    report = loaded;
    findings = selectedFindings;
    cachedFindings = findings.map((finding) => ({ finding }));
    profile = resolveReviewProfile(
      requestedProfile ?? options.profile,
      loaded.sourcePath,
      env,
    );
    outputPath = nextOutputPath;
    session = nextSession;
    triaged = false;
    recommendations = [];
    recommendationMap.clear();
    triagePromise = undefined;
    submittedYamlPath = undefined;
    submittedPlan = undefined;
    execution = undefined;
    executing = false;
  };

  if (options.report) {
    await initialiseReport(
      options.report,
      options.profile as ProfileName | undefined,
    );
  } else if (options.profile) {
    profile = resolveReviewProfile(options.profile, "", env);
  }

  const allDecisionsSaved = (): boolean =>
    Boolean(session) &&
    triaged &&
    recommendations.length > 0 &&
    recommendations.every((recommendation) =>
      session!.decisions.some(
        (decision) => decision.actionableChangeId === recommendation.actionId,
      ),
    );

  const applyTriage = (
    items: readonly AiReportTriageItem[],
    configuration: ActionableConfigurationMap,
  ): void => {
    recommendations = [];
    recommendationMap.clear();
    const actionMap = new Map(
      buildActionCandidates(configuration).map((candidate) => [
        candidate.actionId,
        candidate,
      ]),
    );
    for (const selected of items) {
      const actionCandidate = actionMap.get(selected.actionId);
      if (
        !actionCandidate ||
        actionCandidate.findingId !== selected.findingId
      ) {
        continue;
      }
      const item = cachedFindings.find(
        ({ finding }) => finding.id === selected.findingId,
      );
      if (!item || recommendationMap.has(selected.actionId)) continue;
      const recommendation: CachedRecommendation = {
        key: selected.actionId,
        actionId: selected.actionId,
        finding: item.finding,
        title: selected.recommendationTitle,
        actionableChange: actionCandidate.change,
        analysis: {
          whatItMeans: selected.whatItMeans,
          whyItMatters: selected.reason,
          questions: [],
          remediationConsiderations: selected.suggestedChanges,
        },
      };
      recommendations.push(recommendation);
      recommendationMap.set(recommendation.key, recommendation);
    }
    triaged = true;
  };

  const runTriage = async (): Promise<void> => {
    if (triaged) return;
    if (!report || !session) {
      throw new Error("Run a CheckMate scan or load a report first.");
    }
    if (!provider.triageFindings) {
      throw new Error(
        "Report-level AI triage is unavailable for this provider.",
      );
    }
    if (!profile) {
      throw new Error(
        "A configured Auth0 profile is required to verify live settings. Start the UI with --profile dev or --profile prod.",
      );
    }
    triagePromise ??= (async () => {
      const configuration = await (
        dependencies.configurationLoader ?? loadActionableConfiguration
      )(findings, profile);
      const items = await provider.triageFindings!(findings, configuration);
      applyTriage(items, configuration);
    })();
    try {
      await triagePromise;
    } catch (error) {
      triagePromise = undefined;
      throw error;
    }
  };

  const state = () => ({
    hasReport: Boolean(report),
    scanning,
    availableProfiles,
    ...(profile ? { selectedProfile: profile.profile } : {}),
    ...(report
      ? {
          report: {
            file: path.basename(report.sourcePath),
            ...(report.tenant
              ? { tenant: redactText(report.tenant, sensitiveValues) }
              : {}),
            ...(report.generatedAt ? { generatedAt: report.generatedAt } : {}),
          },
        }
      : {}),
    ...(outputPath ? { outputFile: path.basename(outputPath) } : {}),
    submissionReady: allDecisionsSaved(),
    submitted: Boolean(submittedYamlPath),
    ...(submittedYamlPath
      ? { yamlFile: path.basename(submittedYamlPath) }
      : {}),
    canExecute:
      Boolean(submittedPlan?.calls.length) &&
      profile?.profile === "dev" &&
      execution?.status !== "succeeded",
    executing,
    ...(submittedPlan
      ? {
          plan: {
            profile: submittedPlan.profile,
            generatedAt: submittedPlan.generatedAt,
            calls: submittedPlan.calls,
            unchangedActionIds: submittedPlan.unchangedActionIds,
          },
        }
      : {}),
    ...(execution ? { execution } : {}),
    triaged,
    reportFindingCount: cachedFindings.length,
    progress: {
      completed: session?.decisions.length ?? 0,
      total: recommendations.length,
    },
    findings: recommendations.map((recommendation) => {
      const { finding, analysis } = recommendation;
      const saved = session?.decisions.find(
        (entry) => entry.actionableChangeId === recommendation.actionId,
      );
      return {
        key: recommendation.key,
        title: redactText(recommendation.title, sensitiveValues),
        validatorTitle: redactText(finding.title, sensitiveValues),
        status: finding.status,
        ...(finding.severity
          ? { severity: redactText(finding.severity, sensitiveValues) }
          : {}),
        analysis,
        actionableChanges: [recommendation.actionableChange],
        ...(saved ? { decision: saved.decision.status } : {}),
      };
    }),
  });

  const server = http.createServer((request, response) => {
    void (async () => {
      if (!validLocalRequest(request)) {
        sendError(response, 403, "Only local requests are allowed.");
        return;
      }
      const url = new URL(request.url ?? "/", `http://${request.headers.host}`);

      if (request.method === "GET" && url.pathname === "/") {
        const content = await readFile(
          path.join(publicDirectory, "index.html"),
        );
        securityHeaders(response);
        response.setHeader(
          "Set-Cookie",
          `checkmate_session=${token.toString("hex")}; HttpOnly; SameSite=Strict; Path=/`,
        );
        response.setHeader("Content-Type", "text/html; charset=utf-8");
        response.end(content);
        return;
      }
      if (
        request.method === "GET" &&
        (url.pathname === "/styles.css" || url.pathname === "/app.js")
      ) {
        const filename = url.pathname.slice(1);
        const content = await readFile(path.join(publicDirectory, filename));
        securityHeaders(response);
        response.setHeader(
          "Content-Type",
          filename.endsWith(".css")
            ? "text/css; charset=utf-8"
            : "text/javascript; charset=utf-8",
        );
        response.end(content);
        return;
      }
      if (!hasSession(request, token)) {
        sendError(
          response,
          401,
          "Open the interface from its local URL first.",
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/health") {
        sendJson(response, 200, { ok: true });
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/state") {
        sendJson(response, 200, state());
        return;
      }
      if (request.method === "POST" && !validOrigin(request)) {
        sendError(response, 403, "The request origin is not allowed.");
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/scan") {
        const parsed = scanRequestSchema.parse(await readBody(request));
        if (!availableProfiles.includes(parsed.profile)) {
          throw new Error(
            `The ${parsed.profile} Auth0 profile is not fully configured in .env.`,
          );
        }
        if (scanning) throw new Error("A CheckMate scan is already running.");
        if (executing) {
          throw new Error("Wait for API plan execution to finish first.");
        }
        scanning = true;
        try {
          const metadata = await (dependencies.scanExecutor ?? executeScan)(
            { profile: parsed.profile },
            { env },
          );
          await initialiseReport(metadata.reportPath, parsed.profile);
        } finally {
          scanning = false;
        }
        sendJson(response, 200, { scanned: true, state: state() });
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/triage") {
        await readBody(request);
        await runTriage();
        sendJson(response, 200, state());
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/decision") {
        if (!session || !outputPath) {
          throw new Error("Run a CheckMate scan or load a report first.");
        }
        const parsed = decisionRequestSchema.parse(await readBody(request));
        const recommendation = recommendationMap.get(parsed.findingKey);
        if (!recommendation)
          throw new Error("This action was not selected by AI guidance.");
        const decidedAt = now().toISOString();
        const entry = createReviewEntry(
          recommendation.finding,
          recommendation.analysis,
          [],
          parsed.status,
          boundedUserText(parsed.rationale, sensitiveValues),
          decidedAt,
          sensitiveValues,
          [recommendation.actionableChange],
        );
        entry.actionableChangeId = recommendation.actionId;
        const existingIndex = session.decisions.findIndex(
          (decision) => decision.actionableChangeId === recommendation.actionId,
        );
        if (existingIndex >= 0) session.decisions[existingIndex] = entry;
        else session.decisions.push(entry);
        session.review.lastUpdatedAt = decidedAt;
        if (session.decisions.length === recommendations.length) {
          session.review.completedAt = decidedAt;
        } else {
          delete session.review.completedAt;
        }
        submittedYamlPath = undefined;
        submittedPlan = undefined;
        execution = undefined;
        delete session.execution;
        await writeReviewSession(outputPath, session);
        sendJson(response, 200, { saved: true, state: state() });
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/submit") {
        if (!session || !outputPath) {
          throw new Error("Run a CheckMate scan or load a report first.");
        }
        submitRequestSchema.parse(await readBody(request));
        if (!allDecisionsSaved()) {
          throw new Error(
            "Save a decision for every recommendation before submitting.",
          );
        }
        if (!profile) {
          throw new Error(
            "A configured Auth0 profile is required to create the API plan.",
          );
        }
        const yamlPath = createApiPlanOutputPath(outputPath);
        const plan = buildApiPlan(
          session,
          profile.profile,
          now().toISOString(),
        );
        await writeApiPlan(yamlPath, plan);
        submittedYamlPath = yamlPath;
        submittedPlan = plan;
        execution = undefined;
        delete session.execution;
        sendJson(response, 200, { created: true, state: state() });
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/execute") {
        if (!session || !outputPath) {
          throw new Error("Run a CheckMate scan or load a report first.");
        }
        executeRequestSchema.parse(await readBody(request));
        if (!submittedPlan || !submittedYamlPath) {
          throw new Error("Submit and review an API plan before executing it.");
        }
        if (!profile || profile.profile !== "dev") {
          throw new Error(
            "API execution is restricted to the dev profile. Start the UI with --profile dev.",
          );
        }
        if (executing) {
          throw new Error("This API plan is already being executed.");
        }
        if (execution?.status === "succeeded") {
          throw new Error("This API plan has already been executed.");
        }
        executing = true;
        try {
          try {
            execution = await (dependencies.planExecutor ?? executeApiPlan)(
              submittedPlan,
              profile,
              { now },
            );
          } catch (error) {
            const timestamp = now().toISOString();
            execution = {
              status: "failed",
              startedAt: timestamp,
              completedAt: timestamp,
              profile: "dev",
              calls: [],
              error: redactText(toErrorMessage(error), sensitiveValues),
            };
          }
        } finally {
          executing = false;
        }
        session.execution = {
          planFile: path.basename(submittedYamlPath),
          ...execution,
        };
        session.review.lastUpdatedAt = execution.completedAt;
        await writeReviewSession(outputPath, session);
        sendJson(response, 200, {
          executed: execution.status === "succeeded",
          state: state(),
        });
        return;
      }
      sendError(response, 404, "Not found.");
    })().catch((error: unknown) => sendError(response, 400, error));
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port, HOST, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("Unable to determine UI address.");
  return {
    url: `http://${HOST}:${address.port}`,
    get outputPath() {
      return outputPath ?? "";
    },
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}
