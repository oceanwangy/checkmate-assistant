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
  validateApiPlan,
  type ApiExecutionResult,
  type ApiPlanValidationResult,
} from "../auth0/api-plan-executor.js";
import { loadCheckmateReport } from "../checkmate/report-loader.js";
import { executeScan } from "../commands/scan.js";
import { loadAiConfig } from "../config/ai.js";
import { loadCheckmateConfig, type CheckmateConfig } from "../config/env.js";
import { profiles, type ProfileName } from "../config/profiles.js";
import { resolveReviewProfile } from "../config/review-profile.js";
import {
  filterFindings,
  type FindingStatusFilter,
} from "../findings/filter.js";
import type { NormalizedCheckmateFinding } from "../findings/types.js";
import type { ActionableChange } from "../remediation/actionable-change.js";
import { buildActionCandidates } from "../remediation/action-candidates.js";
import type { ApiPlan } from "../remediation/api-plan.js";
import { readApiPlan, writeApiPlan } from "../remediation/api-plan-writer.js";
import {
  createChangePackagePaths,
  type ChangePackagePaths,
  writeTextArtifact,
} from "../remediation/change-package-writer.js";
import { buildProfileApiPlan } from "../remediation/profile-api-plan.js";
import { buildTerraformReviewConfiguration } from "../remediation/terraform-plan.js";
import {
  validateTerraformConfiguration,
  type TerraformValidationResult,
} from "../remediation/terraform-validator.js";
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
import { evaluatePosture } from "../posture/evaluator.js";
import { POSTURE_REVIEW_GUIDANCE } from "../posture/control-catalog.js";

const HOST = "127.0.0.1";
const MAX_BODY_BYTES = 1_000_000;
const publicDirectory = fileURLToPath(new URL("./public/", import.meta.url));

const decisionRequestSchema = z
  .object({
    findingKey: z.string().min(1).max(500),
    status: z.enum(["approved", "accepted_risk"]),
    rationale: z.string().trim().max(4_000),
    selectedActionIds: z
      .array(z.string().min(1).max(200))
      .max(1_000)
      .optional(),
  })
  .strict();
const submitRequestSchema = z.object({}).strict();
const executeRequestSchema = z.object({ confirmed: z.literal(true) }).strict();
const scanRequestSchema = z
  .object({ profile: z.enum(["dev", "prod"]) })
  .strict();
const artifactRequestSchema = z.object({
  profile: z.enum(["dev", "prod"]),
  artifact: z.enum(["api", "terraform"]),
  download: z.enum(["0", "1"]).optional(),
});

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
  apiPlanValidator?: typeof validateApiPlan;
  terraformValidator?: typeof validateTerraformConfiguration;
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
  title: string;
  analysis: AiFindingAnalysis;
  selectionMode: "single" | "applications" | "changes";
  actions: Array<{
    actionId: string;
    finding: NormalizedCheckmateFinding;
    actionableChange: ActionableChange;
  }>;
}

interface EnvironmentChangePackage {
  plan: ApiPlan;
  apiPlanSha256: string;
  apiValidation: ApiPlanValidationResult;
  terraformValidation: TerraformValidationResult;
}

interface SubmittedChangePackage {
  paths: ChangePackagePaths;
  dev: EnvironmentChangePackage;
  prod: EnvironmentChangePackage;
}

const deterministicApplicationGroups = [
  {
    key: "applications-remove-implicit",
    configPath: "grant_types",
    title: "Remove the Implicit grant type from",
    whatItMeans: [
      "These applications currently allow the Implicit grant type.",
    ],
    suggestion: "Remove the Implicit grant type from selected applications.",
    reason: [
      "This prevents tokens from being returned directly through the browser flow.",
      "Other configured grant types remain unchanged.",
    ],
  },
  {
    key: "applications-use-rs256",
    configPath: "jwt_configuration.alg",
    title: "Set JWT signing to RS256",
    whatItMeans: ["These applications are not using RS256 for JWT signing."],
    suggestion: "Set JWT signing to RS256 for selected applications.",
    reason: [
      "RS256 uses asymmetric signing and keeps verification separate from signing.",
      "Other JWT settings remain unchanged.",
    ],
  },
  {
    key: "applications-disable-cross-origin",
    configPath: "cross_origin_auth",
    title: "Disable cross-origin authentication for",
    whatItMeans: [
      "These applications currently allow cross-origin authentication.",
    ],
    suggestion:
      "Disable cross-origin authentication for selected applications.",
    reason: [
      "This removes an unnecessary browser-based authentication surface.",
      "Cross-origin authentication should be disabled.",
    ],
  },
] as const;

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
  let reportValidatorCount = 0;
  let profile: CheckmateConfig | undefined;
  let outputPath: string | undefined;
  let session: ReviewSession | undefined;
  let triaged = false;
  let recommendations: CachedRecommendation[] = [];
  const recommendationMap = new Map<string, CachedRecommendation>();
  const postureActionIdsByValidator = new Map<string, Set<string>>();
  let triagePromise: Promise<void> | undefined;
  let submittedPackage: SubmittedChangePackage | undefined;
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
    reportValidatorCount = new Set(
      selectedFindings.map((finding) => finding.validatorId ?? finding.id),
    ).size;
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
    postureActionIdsByValidator.clear();
    triagePromise = undefined;
    submittedPackage = undefined;
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
      recommendation.actions.every((action) =>
        session!.decisions.some(
          (decision) => decision.actionableChangeId === action.actionId,
        ),
      ),
    );

  const runApiValidation = async (
    plan: ApiPlan,
    config: CheckmateConfig,
  ): Promise<ApiPlanValidationResult> => {
    try {
      return await (dependencies.apiPlanValidator ?? validateApiPlan)(
        plan,
        config,
        { now },
      );
    } catch (error) {
      return {
        valid: false,
        profile: config.profile,
        validatedAt: now().toISOString(),
        calls: [],
        error: redactText(toErrorMessage(error), sensitiveValues),
      };
    }
  };

  const runTerraformValidation = (
    terraformFile: string,
  ): Promise<TerraformValidationResult> =>
    (dependencies.terraformValidator ?? validateTerraformConfiguration)(
      terraformFile,
      { env, now },
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
    const deterministicActionIds = new Set<string>();
    for (const group of deterministicApplicationGroups) {
      const actions = [...actionMap.values()].flatMap((candidate) => {
        if (
          candidate.change.resourceType !== "client" ||
          candidate.change.configPath !== group.configPath
        ) {
          return [];
        }
        const item = cachedFindings.find(
          ({ finding }) => finding.id === candidate.findingId,
        );
        if (!item) return [];
        deterministicActionIds.add(candidate.actionId);
        return [
          {
            actionId: candidate.actionId,
            finding: item.finding,
            actionableChange: candidate.change,
          },
        ];
      });
      if (actions.length === 0) continue;
      const recommendation: CachedRecommendation = {
        key: group.key,
        title: group.title,
        selectionMode: "applications",
        actions,
        analysis: {
          whatItMeans: [...group.whatItMeans],
          whyItMatters: [...group.reason],
          questions: [],
          remediationConsiderations: [group.suggestion],
        },
      };
      recommendations.push(recommendation);
      recommendationMap.set(recommendation.key, recommendation);
    }
    const callbackActions = [...actionMap.values()].flatMap((candidate) => {
      if (
        candidate.change.resourceType !== "client" ||
        candidate.change.configPath !== "callbacks"
      ) {
        return [];
      }
      const item = cachedFindings.find(
        ({ finding }) => finding.id === candidate.findingId,
      );
      if (!item) return [];
      deterministicActionIds.add(candidate.actionId);
      return [
        {
          actionId: candidate.actionId,
          finding: item.finding,
          actionableChange: candidate.change,
        },
      ];
    });
    const callbacksByClient = new Map<string, typeof callbackActions>();
    for (const action of callbackActions) {
      const resourceId = action.actionableChange.resourceId;
      const grouped = callbacksByClient.get(resourceId) ?? [];
      grouped.push(action);
      callbacksByClient.set(resourceId, grouped);
    }
    for (const actions of callbacksByClient.values()) {
      const first = actions[0];
      if (!first) continue;
      const resourceName = first.actionableChange.resourceName;
      const recommendation: CachedRecommendation = {
        key: `callbacks-${first.actionId}`,
        title: `Remove insecure callback URLs from ${resourceName}`,
        selectionMode: "changes",
        actions,
        analysis: {
          whatItMeans: [
            `${resourceName} allows callback URLs that CheckMate identified as insecure.`,
          ],
          whyItMatters: [
            "Removing development callback URLs reduces the chance of authentication responses being redirected to unintended local endpoints.",
            "All other configured callback URLs remain unchanged.",
          ],
          questions: [],
          remediationConsiderations: [
            `Remove the selected insecure callback URLs from ${resourceName}.`,
          ],
        },
      };
      recommendations.push(recommendation);
      recommendationMap.set(recommendation.key, recommendation);
    }
    for (const selected of items) {
      const actionCandidate = actionMap.get(selected.actionId);
      if (
        !actionCandidate ||
        actionCandidate.findingId !== selected.findingId ||
        deterministicActionIds.has(selected.actionId)
      ) {
        continue;
      }
      const item = cachedFindings.find(
        ({ finding }) => finding.id === selected.findingId,
      );
      if (!item || recommendationMap.has(selected.actionId)) continue;
      const recommendation: CachedRecommendation = {
        key: selected.actionId,
        title: selected.recommendationTitle,
        selectionMode: "single",
        actions: [
          {
            actionId: selected.actionId,
            finding: item.finding,
            actionableChange: actionCandidate.change,
          },
        ],
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
    postureActionIdsByValidator.clear();
    for (const recommendation of recommendations) {
      for (const action of recommendation.actions) {
        const validatorId = action.finding.validatorId;
        if (!validatorId) continue;
        const actionIds =
          postureActionIdsByValidator.get(validatorId) ?? new Set();
        actionIds.add(action.actionId);
        postureActionIdsByValidator.set(validatorId, actionIds);
      }
    }
    triaged = true;
  };

  const runTriage = async (): Promise<void> => {
    if (triaged) return;
    if (!report || !session) {
      throw new Error("Run a CheckMate scan or load a report first.");
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
      const aiConfiguration: ActionableConfigurationMap = new Map(
        [...configuration].flatMap(([findingId, changes]) => {
          const filtered = changes.filter(
            (change) =>
              !(
                change.resourceType === "client" &&
                (change.configPath === "callbacks" ||
                  deterministicApplicationGroups.some(
                    (group) => group.configPath === change.configPath,
                  ))
              ),
          );
          return filtered.length > 0 ? [[findingId, filtered]] : [];
        }),
      );
      if (aiConfiguration.size > 0 && !provider.triageFindings) {
        throw new Error(
          "Report-level AI triage is unavailable for this provider.",
        );
      }
      const items =
        aiConfiguration.size > 0
          ? await provider.triageFindings!(findings, aiConfiguration)
          : [];
      applyTriage(items, configuration);
    })();
    try {
      await triagePromise;
    } catch (error) {
      triagePromise = undefined;
      throw error;
    }
  };

  const state = () => {
    const projectedValidatorProgress = new Map<string, number>();
    for (const [validatorId, actionIds] of postureActionIdsByValidator) {
      const approved = [...actionIds].filter((actionId) =>
        session?.decisions.some(
          (decision) =>
            decision.actionableChangeId === actionId &&
            decision.decision.status === "approved",
        ),
      ).length;
      if (actionIds.size > 0) {
        projectedValidatorProgress.set(validatorId, approved / actionIds.size);
      }
    }
    const posture = report
      ? evaluatePosture(report.findings, { projectedValidatorProgress })
      : undefined;
    const projectedOpenControls = posture
      ? [
          ...posture.projected.openFoundationalControls.map((control) => ({
            ...control,
            importance: "Foundational" as const,
          })),
          ...posture.projected.openHighControls.map((control) => ({
            ...control,
            importance: "High impact" as const,
          })),
        ].map(({ validatorId, title, importance }) => ({
          title,
          importance,
          guidance:
            POSTURE_REVIEW_GUIDANCE[validatorId] ??
            "Review this control against the tenant's technical and business requirements.",
          recommendationAvailable: postureActionIdsByValidator.has(validatorId),
        }))
      : [];
    const publicPosture = posture
      ? {
          modelVersion: posture.modelVersion,
          evidenceBasis: posture.evidenceBasis,
          current: {
            score: posture.current.score,
            rating: posture.current.rating,
            openFoundationalControlCount:
              posture.current.openFoundationalControls.length,
            openHighControlCount: posture.current.openHighControls.length,
          },
          projected: {
            score: posture.projected.score,
            rating: posture.projected.rating,
            openFoundationalControlCount:
              posture.projected.openFoundationalControls.length,
            openHighControlCount: posture.projected.openHighControls.length,
            ...(triaged ? { openControls: projectedOpenControls } : {}),
          },
          delta: posture.delta,
          catalogControlCount: posture.catalogControlCount,
          reportedControlCount: posture.reportedControlCount,
          unscoredValidatorCount: posture.unscoredValidatorIds.length,
        }
      : undefined;
    return {
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
              ...(report.generatedAt
                ? { generatedAt: report.generatedAt }
                : {}),
            },
          }
        : {}),
      ...(outputPath ? { outputFile: path.basename(outputPath) } : {}),
      submissionReady: allDecisionsSaved(),
      submitted: Boolean(submittedPackage),
      canExecute:
        Boolean(submittedPackage?.dev.plan.calls.length) &&
        submittedPackage?.dev.apiValidation.valid === true &&
        submittedPackage?.dev.terraformValidation.valid === true &&
        execution?.status !== "succeeded",
      executing,
      ...(submittedPackage
        ? {
            changePackage: {
              directory: path.basename(submittedPackage.paths.directory),
              dev: {
                apiFile: path.relative(
                  submittedPackage.paths.directory,
                  submittedPackage.paths.dev.apiPlan,
                ),
                terraformFile: path.relative(
                  submittedPackage.paths.directory,
                  submittedPackage.paths.dev.terraform,
                ),
                plan: submittedPackage.dev.plan,
                apiPlanSha256: submittedPackage.dev.apiPlanSha256,
                apiValidation: submittedPackage.dev.apiValidation,
                terraformValidation: submittedPackage.dev.terraformValidation,
              },
              prod: {
                apiFile: path.relative(
                  submittedPackage.paths.directory,
                  submittedPackage.paths.prod.apiPlan,
                ),
                terraformFile: path.relative(
                  submittedPackage.paths.directory,
                  submittedPackage.paths.prod.terraform,
                ),
                plan: submittedPackage.prod.plan,
                apiPlanSha256: submittedPackage.prod.apiPlanSha256,
                apiValidation: submittedPackage.prod.apiValidation,
                terraformValidation: submittedPackage.prod.terraformValidation,
              },
            },
          }
        : {}),
      ...(execution ? { execution } : {}),
      triaged,
      findingStatus: options.status,
      reportValidatorCount,
      reportFindingCount: cachedFindings.length,
      ...(publicPosture ? { posture: publicPosture } : {}),
      progress: {
        completed: recommendations.filter((recommendation) =>
          recommendation.actions.every((action) =>
            session?.decisions.some(
              (decision) => decision.actionableChangeId === action.actionId,
            ),
          ),
        ).length,
        total: recommendations.length,
      },
      findings: recommendations.map((recommendation) => {
        const { analysis } = recommendation;
        const finding = recommendation.actions[0]!.finding;
        const saved = recommendation.actions.flatMap((action) => {
          const entry = session?.decisions.find(
            (decision) => decision.actionableChangeId === action.actionId,
          );
          return entry ? [entry] : [];
        });
        const reviewed = saved.length === recommendation.actions.length;
        const selectedActionIds = saved
          .filter((entry) => entry.decision.status === "approved")
          .flatMap((entry) =>
            entry.actionableChangeId ? [entry.actionableChangeId] : [],
          );
        const decision = reviewed
          ? selectedActionIds.length === 0
            ? "accepted_risk"
            : selectedActionIds.length === recommendation.actions.length
              ? "approved"
              : "mixed"
          : undefined;
        const adminNote =
          saved.find((entry) => entry.decision.status === "approved")?.decision
            .adminNote ?? saved[0]?.decision.adminNote;
        return {
          key: recommendation.key,
          title: redactText(recommendation.title, sensitiveValues),
          validatorTitle: redactText(finding.title, sensitiveValues),
          status: finding.status,
          ...(finding.severity
            ? { severity: redactText(finding.severity, sensitiveValues) }
            : {}),
          analysis,
          selectionMode: recommendation.selectionMode,
          actionableChanges: recommendation.actions.map((action) => ({
            actionId: action.actionId,
            ...action.actionableChange,
          })),
          reviewed,
          selectedActionIds,
          ...(adminNote
            ? { adminNote: redactText(adminNote, sensitiveValues) }
            : {}),
          ...(decision ? { decision } : {}),
        };
      }),
    };
  };

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
      if (request.method === "GET" && url.pathname === "/api/artifact") {
        if (!submittedPackage) {
          throw new Error(
            "Submit the change package before opening its files.",
          );
        }
        const parsed = artifactRequestSchema.parse({
          profile: url.searchParams.get("profile"),
          artifact: url.searchParams.get("artifact"),
          ...(url.searchParams.has("download")
            ? { download: url.searchParams.get("download") }
            : {}),
        });
        const environment = submittedPackage.paths[parsed.profile];
        const artifactPath =
          parsed.artifact === "api"
            ? environment.apiPlan
            : environment.terraform;
        const filename = `${parsed.profile}-${path.basename(artifactPath)}`;
        const content = await readFile(artifactPath);
        securityHeaders(response);
        response.setHeader(
          "Content-Type",
          parsed.artifact === "api"
            ? "application/yaml; charset=utf-8"
            : "text/plain; charset=utf-8",
        );
        if (parsed.download === "1") {
          response.setHeader(
            "Content-Disposition",
            `attachment; filename="${filename}"`,
          );
        }
        response.end(content);
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
          throw new Error("This recommendation is not available.");
        const availableActionIds = new Set(
          recommendation.actions.map((action) => action.actionId),
        );
        const selectedActionIds =
          parsed.status === "approved"
            ? new Set(
                parsed.selectedActionIds ??
                  recommendation.actions.map((action) => action.actionId),
              )
            : new Set<string>();
        if (
          [...selectedActionIds].some(
            (actionId) => !availableActionIds.has(actionId),
          )
        ) {
          throw new Error(
            "The selected option is not part of this recommendation.",
          );
        }
        if (parsed.status === "approved" && selectedActionIds.size === 0) {
          throw new Error("Select at least one option, or remain unchanged.");
        }
        const decidedAt = now().toISOString();
        const adminNote = boundedUserText(
          parsed.rationale,
          sensitiveValues,
        ).trim();
        session.decisions = session.decisions.filter(
          (decision) =>
            !decision.actionableChangeId ||
            !availableActionIds.has(decision.actionableChangeId),
        );
        for (const action of recommendation.actions) {
          const selected = selectedActionIds.has(action.actionId);
          const entry = createReviewEntry(
            action.finding,
            recommendation.analysis,
            [],
            selected ? "approved" : "accepted_risk",
            adminNote ||
              (selected ? "Accepted AI suggestion." : "Remained unchanged."),
            decidedAt,
            sensitiveValues,
            [action.actionableChange],
          );
          if (adminNote) entry.decision.adminNote = adminNote;
          entry.actionableChangeId = action.actionId;
          session.decisions.push(entry);
        }
        session.review.lastUpdatedAt = decidedAt;
        if (allDecisionsSaved()) {
          session.review.completedAt = decidedAt;
        } else {
          delete session.review.completedAt;
        }
        submittedPackage = undefined;
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
        const devConfig = loadCheckmateConfig("dev", env);
        const prodConfig = loadCheckmateConfig("prod", env);
        const configurationLoader =
          dependencies.configurationLoader ?? loadActionableConfiguration;
        const [devConfiguration, prodConfiguration] = await Promise.all([
          configurationLoader(findings, devConfig, undefined, {
            includeCompliant: true,
          }),
          configurationLoader(findings, prodConfig, undefined, {
            includeCompliant: true,
          }),
        ]);
        const generatedAt = now().toISOString();
        const devPlan = buildProfileApiPlan(
          session,
          devConfiguration,
          "dev",
          generatedAt,
        );
        const prodPlan = buildProfileApiPlan(
          session,
          prodConfiguration,
          "prod",
          generatedAt,
        );
        const paths = createChangePackagePaths(outputPath);
        await Promise.all([
          writeApiPlan(paths.dev.apiPlan, devPlan),
          writeApiPlan(paths.prod.apiPlan, prodPlan),
          writeTextArtifact(
            paths.dev.terraform,
            buildTerraformReviewConfiguration(devPlan),
          ),
          writeTextArtifact(
            paths.prod.terraform,
            buildTerraformReviewConfiguration(prodPlan),
          ),
        ]);
        const [devArtifact, prodArtifact] = await Promise.all([
          readApiPlan(paths.dev.apiPlan),
          readApiPlan(paths.prod.apiPlan),
        ]);
        const [
          devApiValidation,
          prodApiValidation,
          devTerraformValidation,
          prodTerraformValidation,
        ] = await Promise.all([
          runApiValidation(devArtifact.plan, devConfig),
          runApiValidation(prodArtifact.plan, prodConfig),
          runTerraformValidation(paths.dev.terraform),
          runTerraformValidation(paths.prod.terraform),
        ]);
        submittedPackage = {
          paths,
          dev: {
            plan: devArtifact.plan,
            apiPlanSha256: devArtifact.sha256,
            apiValidation: devApiValidation,
            terraformValidation: devTerraformValidation,
          },
          prod: {
            plan: prodArtifact.plan,
            apiPlanSha256: prodArtifact.sha256,
            apiValidation: prodApiValidation,
            terraformValidation: prodTerraformValidation,
          },
        };
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
        if (!submittedPackage) {
          throw new Error(
            "Submit and review the change package before executing it.",
          );
        }
        if (executing) {
          throw new Error("This API plan is already being executed.");
        }
        if (execution?.status === "succeeded") {
          throw new Error("This API plan has already been executed.");
        }
        const devConfig = loadCheckmateConfig("dev", env);
        const devArtifact = await readApiPlan(
          submittedPackage.paths.dev.apiPlan,
        );
        if (devArtifact.sha256 !== submittedPackage.dev.apiPlanSha256) {
          throw new Error(
            "Execution stopped because dev/api-plan.yml changed after review. Submit the decisions again to create and validate a new plan.",
          );
        }
        const [apiValidation, terraformValidation] = await Promise.all([
          runApiValidation(devArtifact.plan, devConfig),
          runTerraformValidation(submittedPackage.paths.dev.terraform),
        ]);
        submittedPackage.dev.apiValidation = apiValidation;
        submittedPackage.dev.terraformValidation = terraformValidation;
        if (!apiValidation.valid || !terraformValidation.valid) {
          sendJson(response, 200, { executed: false, state: state() });
          return;
        }
        executing = true;
        try {
          try {
            execution = await (dependencies.planExecutor ?? executeApiPlan)(
              devArtifact.plan,
              devConfig,
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
          planFile: path.relative(
            submittedPackage.paths.directory,
            submittedPackage.paths.dev.apiPlan,
          ),
          planSha256: devArtifact.sha256,
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
