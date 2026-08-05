import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const hostSchema = z.enum(["127.0.0.1", "localhost"]);
const portSchema = z.coerce.number().int().min(1).max(65_535);
const booleanSchema = z
  .enum(["true", "false"])
  .transform((value) => value === "true");
const reasoningSchema = z.enum(["low", "medium", "high"]);

export const AUTH0_READ_ONLY_TOOLS = [
  "auth0_list_logs",
  "auth0_get_log",
  "auth0_list_applications",
  "auth0_get_application",
] as const;

export interface ChatConfig {
  projectRoot: string;
  publicDirectory: string;
  reportsDirectory: string;
  host: "127.0.0.1" | "localhost";
  port: number;
  model: string;
  reasoningEffort: "low" | "medium" | "high";
  openAiApiKey: string;
  remediationUrl: string;
  auth0Enabled: boolean;
  auth0Command: string;
  auth0Arguments: string[];
  scanTargets: Record<
    "dev" | "prod",
    { configured: boolean; tenantDomain?: string }
  >;
  devTenantDomain?: string;
  devRemediationDisabledReason?: string;
  devPlanningEnabled: boolean;
  devRemediationEnabled: boolean;
}

export function defaultProjectRoot(): string {
  const currentDirectory = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(currentDirectory, "../../..");
}

function resolveFromProject(projectRoot: string, value: string): string {
  return path.isAbsolute(value) ? value : path.resolve(projectRoot, value);
}

export function loadChatConfig(
  env: NodeJS.ProcessEnv = process.env,
): ChatConfig {
  const projectRoot = path.resolve(
    env.CHECKMATE_CHAT_PROJECT_ROOT ?? defaultProjectRoot(),
  );
  const apiKey = env.OPENAI_API_KEY?.trim();
  if (!apiKey) {
    throw new Error("OPENAI_API_KEY is required to start the chatbot.");
  }

  const host = hostSchema.parse(env.CHECKMATE_CHAT_HOST ?? "127.0.0.1");
  const port = portSchema.parse(env.CHECKMATE_CHAT_PORT ?? "4320");
  const auth0Enabled = booleanSchema.parse(
    env.CHECKMATE_CHAT_AUTH0_ENABLED ?? "true",
  );
  const model = (
    env.OPENAI_MODEL ??
    env.CHECKMATE_CHAT_MODEL ??
    "gpt-5.5"
  ).trim();
  if (!/^[a-zA-Z0-9._:-]+$/.test(model)) {
    throw new Error("OPENAI_MODEL contains unsupported characters.");
  }

  const auth0Tools = AUTH0_READ_ONLY_TOOLS.join(",");
  const defaultAuth0Arguments = [
    path.resolve(
      projectRoot,
      "node_modules/@auth0/auth0-mcp-server/dist/index.js",
    ),
    "run",
    "--tools",
    auth0Tools,
    "--read-only",
  ];
  let auth0Arguments = defaultAuth0Arguments;
  if (env.CHECKMATE_CHAT_AUTH0_ARGS) {
    const parsed: unknown = JSON.parse(env.CHECKMATE_CHAT_AUTH0_ARGS);
    if (
      !Array.isArray(parsed) ||
      !parsed.every((argument) => typeof argument === "string")
    ) {
      throw new Error("CHECKMATE_CHAT_AUTH0_ARGS must be a JSON string array.");
    }
    auth0Arguments = parsed;
  }

  const devTenantDomain = env.AUTH0CHECKMATE_DEV_DOMAIN?.trim();
  const prodTenantDomain = env.AUTH0CHECKMATE_PROD_DOMAIN?.trim();
  const devWriteDomain = env.CHECKMATE_CHAT_DEV_WRITE_DOMAIN?.trim();
  const devCredentialsConfigured = Boolean(
    devTenantDomain &&
    env.AUTH0CHECKMATE_DEV_CLIENT_ID?.trim() &&
    env.AUTH0CHECKMATE_DEV_CLIENT_SECRET?.trim(),
  );
  const prodCredentialsConfigured = Boolean(
    prodTenantDomain &&
    env.AUTH0CHECKMATE_PROD_CLIENT_ID?.trim() &&
    env.AUTH0CHECKMATE_PROD_CLIENT_SECRET?.trim(),
  );
  let devRemediationDisabledReason: string | undefined;
  if (!devCredentialsConfigured) {
    devRemediationDisabledReason = "Dev tenant credentials are incomplete.";
  } else if (!devWriteDomain || devWriteDomain !== devTenantDomain) {
    devRemediationDisabledReason =
      "CHECKMATE_CHAT_DEV_WRITE_DOMAIN must exactly match the configured dev tenant.";
  }
  const devRemediationEnabled = !devRemediationDisabledReason;
  return {
    projectRoot,
    publicDirectory: path.resolve(projectRoot, "apps/checkmate-chat/public"),
    reportsDirectory: resolveFromProject(
      projectRoot,
      env.CHECKMATE_REPORTS_DIR ?? "reports",
    ),
    host,
    port,
    model,
    reasoningEffort: reasoningSchema.parse(
      env.OPENAI_REASONING_EFFORT ??
        env.CHECKMATE_CHAT_REASONING_EFFORT ??
        "high",
    ),
    openAiApiKey: apiKey,
    remediationUrl:
      env.CHECKMATE_CHAT_REMEDIATION_URL ?? "http://127.0.0.1:4317",
    auth0Enabled,
    auth0Command: env.CHECKMATE_CHAT_AUTH0_COMMAND ?? process.execPath,
    auth0Arguments,
    scanTargets: {
      dev: {
        configured: devCredentialsConfigured,
        ...(devTenantDomain ? { tenantDomain: devTenantDomain } : {}),
      },
      prod: {
        configured: prodCredentialsConfigured,
        ...(prodTenantDomain ? { tenantDomain: prodTenantDomain } : {}),
      },
    },
    ...(devTenantDomain ? { devTenantDomain } : {}),
    ...(devRemediationDisabledReason ? { devRemediationDisabledReason } : {}),
    devPlanningEnabled: devCredentialsConfigured,
    devRemediationEnabled,
  };
}
