import { createHash, randomUUID } from "node:crypto";
import { z } from "zod";
import type { CheckmateConfig } from "../config/env.js";
import type { ProfileName } from "../config/profiles.js";
import {
  apiPlanSchema,
  type ApiPlan,
  type ApiPlanCall,
} from "../remediation/api-plan.js";
import { AppError, toErrorMessage } from "../utils/errors.js";
import type { Fetcher } from "./fetcher.js";

const tokenSchema = z.object({
  access_token: z.string().min(1),
  scope: z.string().optional(),
});
const recordSchema = z.record(z.unknown());

export interface ApiCallExecution {
  id: string;
  endpoint: string;
  status: "applied" | "already_applied" | "failed";
  correlationId: string;
  error?: string;
}

export interface ApiExecutionResult {
  status: "succeeded" | "failed";
  startedAt: string;
  completedAt: string;
  profile: "dev";
  calls: ApiCallExecution[];
  error?: string;
}

export interface ApiPlanExecutorOptions {
  fetcher?: Fetcher;
  now?: () => Date;
  includeRequestBodies?: boolean;
  approvedRequestDigests?: Readonly<Record<string, string>>;
}

export interface ApiPlanValidationResult {
  valid: boolean;
  profile: ProfileName;
  validatedAt: string;
  calls: Array<{
    id: string;
    endpoint: string;
    method: "PATCH";
    resourceName: string;
    status: "ready" | "already_applied" | "invalid";
    requestBody?: Record<string, unknown>;
    requestSha256?: string;
    error?: string;
  }>;
  error?: string;
}

function tenantBaseUrl(domain: string): string {
  if (!/^[a-zA-Z0-9.-]+\.auth0\.com$/.test(domain)) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      "The selected profile domain is not a valid Auth0 tenant domain.",
    );
  }
  return `https://${domain}`;
}

function record(value: unknown, label: string): Record<string, unknown> {
  const parsed = recordSchema.safeParse(value);
  if (!parsed.success) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `Auth0 returned invalid ${label} configuration.`,
    );
  }
  return parsed.data;
}

async function responseJson(
  response: Response,
  label: string,
): Promise<unknown> {
  if (!response.ok) {
    let detail = "";
    try {
      const text = await response.text();
      if (text) {
        try {
          const parsed = JSON.parse(text) as unknown;
          if (parsed !== null && typeof parsed === "object") {
            const body = parsed as Record<string, unknown>;
            const messages = [
              body.message,
              body.error_description,
              body.error,
            ].filter(
              (value): value is string =>
                typeof value === "string" && value.trim().length > 0,
            );
            detail = [...new Set(messages)].join(" — ");
          }
        } catch {
          detail = text;
        }
      }
    } catch {
      // Retain the status-only error when Auth0 does not return a readable body.
    }
    const safeDetail = detail.replace(/\s+/g, " ").trim().slice(0, 500);
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `${label} failed with status ${response.status}${safeDetail ? `: ${safeDetail}` : ""}.`,
    );
  }
  try {
    return (await response.json()) as unknown;
  } catch (error) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `${label} returned invalid JSON.`,
      { cause: error },
    );
  }
}

function safeSegments(dottedPath: string): string[] {
  const segments = dottedPath.split(".");
  if (
    segments.length === 0 ||
    segments.some(
      (segment) =>
        !/^[a-zA-Z0-9_-]+$/.test(segment) ||
        ["__proto__", "prototype", "constructor"].includes(segment),
    )
  ) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `The API plan contains an unsupported configuration path: ${dottedPath}`,
    );
  }
  return segments;
}

function valueAt(source: unknown, dottedPath: string): unknown {
  let current = source;
  for (const segment of safeSegments(dottedPath)) {
    if (
      current === null ||
      typeof current !== "object" ||
      Array.isArray(current)
    ) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

function sameValue(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function cloneRecord(value: Record<string, unknown>): Record<string, unknown> {
  return structuredClone(value);
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

export function apiRequestSha256(
  method: "PATCH",
  endpoint: string,
  body: Record<string, unknown>,
): string {
  return createHash("sha256")
    .update(`${method}\n${endpoint}\n${canonicalJson(body)}`, "utf8")
    .digest("hex");
}

function mergeRecords(
  target: Record<string, unknown>,
  patch: Record<string, unknown>,
): Record<string, unknown> {
  for (const [key, value] of Object.entries(patch)) {
    safeSegments(key);
    const existing = target[key];
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      const existingRecord =
        existing !== null &&
        typeof existing === "object" &&
        !Array.isArray(existing)
          ? cloneRecord(existing as Record<string, unknown>)
          : {};
      target[key] = mergeRecords(
        existingRecord,
        value as Record<string, unknown>,
      );
    } else {
      target[key] = structuredClone(value);
    }
  }
  return target;
}

function removeNullLiveValues(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(removeNullLiveValues);
  }
  if (value !== null && typeof value === "object") {
    const cleaned: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value)) {
      safeSegments(key);
      if (nested !== null && nested !== undefined) {
        cleaned[key] = removeNullLiveValues(nested);
      }
    }
    return cleaned;
  }
  return value;
}

function assertJsonPayload(value: unknown, path = "body"): void {
  if (
    value === undefined ||
    typeof value === "bigint" ||
    typeof value === "function" ||
    typeof value === "symbol" ||
    (typeof value === "number" && !Number.isFinite(value))
  ) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `The API plan produced an invalid PATCH value at ${path}.`,
    );
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) =>
      assertJsonPayload(item, `${path}[${index}]`),
    );
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) {
      safeSegments(key);
      assertJsonPayload(nested, `${path}.${key}`);
    }
  }
}

function targetValue(call: ApiPlanCall, path: string): unknown {
  const target = valueAt(call.body, path);
  if (target === undefined) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `The API plan is missing a target value for ${path}.`,
    );
  }
  return target;
}

function classifyLiveState(
  call: ApiPlanCall,
  live: Record<string, unknown>,
): "target" | "safe_to_apply" {
  let allTargets = true;
  for (const precondition of call.preconditions) {
    const current = valueAt(live, precondition.path);
    const target = targetValue(call, precondition.path);
    if (sameValue(current, target)) continue;
    allTargets = false;
    if (!sameValue(current, precondition.expectedValue)) {
      throw new AppError(
        "AUTH0_WRITE_FAILED",
        `Execution stopped because ${call.resourceName} changed after the plan was created (${precondition.path}). Review the tenant and create a new plan.`,
      );
    }
  }
  return allTargets ? "target" : "safe_to_apply";
}

function requestBody(
  call: ApiPlanCall,
  live: Record<string, unknown>,
): Record<string, unknown> {
  if (call.bodyStrategy === "merge_live_nested_objects") {
    const body: Record<string, unknown> = {};
    for (const [key, planned] of Object.entries(call.body)) {
      const existing = live[key];
      if (
        planned !== null &&
        typeof planned === "object" &&
        !Array.isArray(planned) &&
        existing !== null &&
        typeof existing === "object" &&
        !Array.isArray(existing)
      ) {
        body[key] = mergeRecords(
          cloneRecord(existing as Record<string, unknown>),
          planned as Record<string, unknown>,
        );
      } else {
        body[key] = structuredClone(planned);
      }
    }
    assertJsonPayload(body);
    return body;
  }
  const liveOptions = record(
    removeNullLiveValues(live.options),
    "connection options",
  );
  const plannedOptions = record(
    call.body.options,
    "planned connection options",
  );
  const body = {
    options: mergeRecords(cloneRecord(liveOptions), plannedOptions),
  };
  assertJsonPayload(body);
  return body;
}

function scopesFor(plan: ApiPlan): string[] {
  const client = plan.calls.some((call) => call.resourceType === "client");
  const connection = plan.calls.some(
    (call) => call.resourceType === "connection",
  );
  const attack = plan.calls.some(
    (call) => call.resourceType === "attack_protection",
  );
  return [
    ...(client ? ["read:clients", "update:clients"] : []),
    ...(connection
      ? [
          "read:connections",
          "read:connections_options",
          "update:connections",
          "update:connections_options",
        ]
      : []),
    ...(attack ? ["read:attack_protection", "update:attack_protection"] : []),
  ];
}

async function managementAuthorization(
  fetcher: Fetcher,
  baseUrl: string,
  config: CheckmateConfig,
  scopes: string[],
  purpose: "validation" | "execution",
): Promise<string> {
  const response = await fetcher(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      grant_type: "client_credentials",
      client_id: config.clientId,
      client_secret: config.clientSecret,
      audience: `${baseUrl}/api/v2/`,
      scope: scopes.join(" "),
    }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `Auth0 could not grant the required ${purpose} scopes (${scopes.join(", ")}) for ${config.profile}.`,
    );
  }
  const token = tokenSchema.safeParse(
    await responseJson(response, `Auth0 ${purpose} token request`),
  );
  if (!token.success) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `Auth0 returned an invalid ${purpose} access token.`,
    );
  }
  if (token.data.scope !== undefined) {
    const granted = new Set(token.data.scope.split(/\s+/).filter(Boolean));
    const missing = scopes.filter((scope) => !granted.has(scope));
    if (missing.length > 0) {
      throw new AppError(
        "AUTH0_WRITE_FAILED",
        `Auth0 ${purpose} is missing required scopes (${missing.join(", ")}) for ${config.profile}.`,
      );
    }
  }
  return `Bearer ${token.data.access_token}`;
}

async function readLiveResource(
  fetcher: Fetcher,
  baseUrl: string,
  call: ApiPlanCall,
  authorization: string,
): Promise<Record<string, unknown>> {
  const url = new URL(call.endpoint, baseUrl);
  if (call.resourceType === "connection") {
    url.searchParams.set("fields", "id,name,strategy,options");
    url.searchParams.set("include_fields", "true");
  }
  const response = await fetcher(url, {
    headers: { authorization },
    signal: AbortSignal.timeout(30_000),
  });
  return record(
    await responseJson(response, `Auth0 read for ${call.resourceName}`),
    call.resourceName,
  );
}

export async function validateApiPlan(
  untrustedPlan: ApiPlan,
  config: CheckmateConfig,
  options: ApiPlanExecutorOptions = {},
): Promise<ApiPlanValidationResult> {
  const plan = apiPlanSchema.parse(untrustedPlan);
  if (plan.profile !== config.profile) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `The ${plan.profile} API plan cannot be validated against the ${config.profile} profile.`,
    );
  }
  const fetcher = options.fetcher ?? fetch;
  const now = options.now ?? (() => new Date());
  const validatedAt = now().toISOString();
  const baseUrl = tenantBaseUrl(config.domain);
  const scopes = scopesFor(plan);
  if (scopes.length === 0) {
    return {
      valid: true,
      profile: config.profile,
      validatedAt,
      calls: [],
    };
  }
  const authorization = await managementAuthorization(
    fetcher,
    baseUrl,
    config,
    scopes,
    "validation",
  );
  const calls: ApiPlanValidationResult["calls"] = [];
  for (const call of plan.calls) {
    try {
      const live = await readLiveResource(
        fetcher,
        baseUrl,
        call,
        authorization,
      );
      const status = classifyLiveState(call, live);
      const body =
        status === "safe_to_apply" ? requestBody(call, live) : undefined;
      calls.push({
        id: call.id,
        endpoint: call.endpoint,
        method: call.method,
        resourceName: call.resourceName,
        status: status === "target" ? "already_applied" : "ready",
        ...(body
          ? {
              ...(options.includeRequestBodies ? { requestBody: body } : {}),
              requestSha256: apiRequestSha256(call.method, call.endpoint, body),
            }
          : {}),
      });
    } catch (error) {
      const message = toErrorMessage(error);
      calls.push({
        id: call.id,
        endpoint: call.endpoint,
        method: call.method,
        resourceName: call.resourceName,
        status: "invalid",
        error: message,
      });
      return {
        valid: false,
        profile: config.profile,
        validatedAt,
        calls,
        error: message,
      };
    }
  }
  return {
    valid: true,
    profile: config.profile,
    validatedAt,
    calls,
  };
}

export async function executeApiPlan(
  untrustedPlan: ApiPlan,
  config: CheckmateConfig,
  options: ApiPlanExecutorOptions = {},
): Promise<ApiExecutionResult> {
  const plan = apiPlanSchema.parse(untrustedPlan);
  if (config.profile !== "dev" || plan.profile !== "dev") {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      "API plan execution is restricted to the dev profile.",
    );
  }
  const fetcher = options.fetcher ?? fetch;
  const now = options.now ?? (() => new Date());
  const startedAt = now().toISOString();
  const baseUrl = tenantBaseUrl(config.domain);
  const scopes = scopesFor(plan);
  if (scopes.length === 0) {
    return {
      status: "succeeded",
      startedAt,
      completedAt: now().toISOString(),
      profile: "dev",
      calls: [],
    };
  }

  const authorization = await managementAuthorization(
    fetcher,
    baseUrl,
    config,
    scopes,
    "execution",
  );
  const calls: ApiCallExecution[] = [];

  for (const call of plan.calls) {
    const correlationId = `checkmate-${randomUUID()}`.slice(0, 64);
    try {
      const live = await readLiveResource(
        fetcher,
        baseUrl,
        call,
        authorization,
      );
      if (classifyLiveState(call, live) === "target") {
        calls.push({
          id: call.id,
          endpoint: call.endpoint,
          status: "already_applied",
          correlationId,
        });
        continue;
      }
      const body = requestBody(call, live);
      const approvedDigests = options.approvedRequestDigests;
      if (approvedDigests) {
        const approved = approvedDigests[call.id];
        const actual = apiRequestSha256(call.method, call.endpoint, body);
        if (!approved || approved !== actual) {
          throw new AppError(
            "AUTH0_WRITE_FAILED",
            `Execution stopped because the exact API request for ${call.resourceName} no longer matches the confirmed preview. Create and confirm a new dev plan.`,
          );
        }
      }
      const response = await fetcher(new URL(call.endpoint, baseUrl), {
        method: "PATCH",
        headers: {
          authorization,
          "content-type": "application/json",
          "x-correlation-id": correlationId,
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(30_000),
      });
      await responseJson(response, `Auth0 update for ${call.resourceName}`);
      const verified = await readLiveResource(
        fetcher,
        baseUrl,
        call,
        authorization,
      );
      if (classifyLiveState(call, verified) !== "target") {
        throw new AppError(
          "AUTH0_WRITE_FAILED",
          `Auth0 did not retain the planned settings for ${call.resourceName}.`,
        );
      }
      calls.push({
        id: call.id,
        endpoint: call.endpoint,
        status: "applied",
        correlationId,
      });
    } catch (error) {
      const message = toErrorMessage(error);
      calls.push({
        id: call.id,
        endpoint: call.endpoint,
        status: "failed",
        correlationId,
        error: message,
      });
      return {
        status: "failed",
        startedAt,
        completedAt: now().toISOString(),
        profile: "dev",
        calls,
        error: message,
      };
    }
  }

  return {
    status: "succeeded",
    startedAt,
    completedAt: now().toISOString(),
    profile: "dev",
    calls,
  };
}
