import { z } from "zod";
import type { CheckmateConfig } from "../config/env.js";
import type { NormalizedCheckmateFinding } from "../findings/types.js";
import type {
  ActionableChange,
  ConfigurationValue,
} from "../remediation/actionable-change.js";
import { AppError } from "../utils/errors.js";
import type { Fetcher } from "./application-inventory.js";

const tokenSchema = z.object({ access_token: z.string().min(1) });
const connectionSchema = z
  .object({
    id: z.string().min(1),
    name: z.string().min(1),
    strategy: z.string().optional(),
    options: z.record(z.unknown()).optional(),
  })
  .passthrough();
const connectionsSchema = z.array(connectionSchema);
const recordSchema = z.record(z.unknown());

const CONNECTION_VALIDATORS = new Set([
  "checkPasswordPolicy",
  "checkPasswordComplexity",
  "checkPasswordNoPersonalInfo",
  "checkPasswordHistory",
  "checkAuthenticationMethods",
  "checkEmailAttributeVerification",
]);
const LEGACY_PASSWORD_VALIDATORS = new Set([
  "checkPasswordPolicy",
  "checkPasswordComplexity",
  "checkPasswordNoPersonalInfo",
  "checkPasswordHistory",
]);
const ATTACK_VALIDATORS = new Set(["checkBruteForce", "checkBreachedPassword"]);

function tenantBaseUrl(domain: string): string {
  if (!/^[a-zA-Z0-9.-]+\.auth0\.com$/.test(domain)) {
    throw new AppError(
      "AUTH0_READ_FAILED",
      "The selected profile domain is not a valid Auth0 tenant domain.",
    );
  }
  return `https://${domain}`;
}

async function parseJson(response: Response, label: string): Promise<unknown> {
  if (!response.ok) {
    throw new AppError(
      "AUTH0_READ_FAILED",
      `${label} failed with status ${response.status}.`,
    );
  }
  try {
    return (await response.json()) as unknown;
  } catch (error) {
    throw new AppError("AUTH0_READ_FAILED", `${label} returned invalid JSON.`, {
      cause: error,
    });
  }
}

function record(value: unknown): Record<string, unknown> | undefined {
  const parsed = recordSchema.safeParse(value);
  return parsed.success ? parsed.data : undefined;
}

function valueAt(
  source: Record<string, unknown>,
  path: readonly string[],
): ConfigurationValue {
  let current: unknown = source;
  for (const segment of path) {
    const currentRecord = record(current);
    if (!currentRecord) return null;
    current = currentRecord[segment];
  }
  if (
    typeof current === "string" ||
    typeof current === "number" ||
    typeof current === "boolean" ||
    current === null
  ) {
    return current;
  }
  if (
    Array.isArray(current) &&
    current.every((item) => typeof item === "string")
  ) {
    return current;
  }
  return null;
}

function sameValue(
  left: ConfigurationValue,
  right: ConfigurationValue,
): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function change(
  resourceType: ActionableChange["resourceType"],
  resourceId: string,
  resourceName: string,
  configPath: string,
  currentValue: ConfigurationValue,
  targetValue: ConfigurationValue,
): ActionableChange | undefined {
  if (sameValue(currentValue, targetValue)) return undefined;
  return {
    resourceType,
    resourceId,
    resourceName,
    configPath,
    currentValue,
    targetValue,
  };
}

function connectionChanges(
  finding: NormalizedCheckmateFinding,
  connection: z.infer<typeof connectionSchema>,
): ActionableChange[] {
  const options = connection.options ?? {};
  if (
    record(options.password_options) &&
    LEGACY_PASSWORD_VALIDATORS.has(finding.validatorId ?? "")
  ) {
    return [];
  }
  const proposed: Array<ActionableChange | undefined> = [];
  switch (finding.validatorId) {
    case "checkPasswordPolicy": {
      const current = valueAt(options, ["passwordPolicy"]);
      if (current !== "good" && current !== "excellent") {
        proposed.push(
          change(
            "connection",
            connection.id,
            connection.name,
            "options.passwordPolicy",
            current,
            "good",
          ),
        );
      }
      break;
    }
    case "checkPasswordComplexity": {
      const current = valueAt(options, [
        "password_complexity_options",
        "min_length",
      ]);
      if (typeof current !== "number" || current < 12) {
        proposed.push(
          change(
            "connection",
            connection.id,
            connection.name,
            "options.password_complexity_options.min_length",
            current,
            12,
          ),
        );
      }
      break;
    }
    case "checkPasswordNoPersonalInfo":
      proposed.push(
        change(
          "connection",
          connection.id,
          connection.name,
          "options.password_no_personal_info.enable",
          valueAt(options, ["password_no_personal_info", "enable"]),
          true,
        ),
      );
      break;
    case "checkPasswordHistory":
      proposed.push(
        change(
          "connection",
          connection.id,
          connection.name,
          "options.password_history.enable",
          valueAt(options, ["password_history", "enable"]),
          true,
        ),
      );
      break;
    case "checkAuthenticationMethods":
      proposed.push(
        change(
          "connection",
          connection.id,
          connection.name,
          "options.authentication_methods.passkey.enabled",
          valueAt(options, ["authentication_methods", "passkey", "enabled"]),
          true,
        ),
      );
      break;
    case "checkEmailAttributeVerification": {
      const current = valueAt(options, [
        "attributes",
        "email",
        "verification_method",
      ]);
      if (current !== null && current !== "otp") {
        proposed.push(
          change(
            "connection",
            connection.id,
            connection.name,
            "options.attributes.email.verification_method",
            current,
            "otp",
          ),
        );
      }
      break;
    }
  }
  return proposed.filter((item): item is ActionableChange => Boolean(item));
}

function addString(values: ConfigurationValue, required: string[]): string[] {
  const existing = Array.isArray(values) ? values : [];
  return [...new Set([...existing, ...required])];
}

function attackChanges(
  finding: NormalizedCheckmateFinding,
  config: Record<string, unknown>,
): ActionableChange[] {
  const resourceId = finding.validatorId ?? finding.id;
  const proposed: Array<ActionableChange | undefined> = [];
  if (finding.validatorId === "checkBruteForce") {
    proposed.push(
      change(
        "attack_protection",
        resourceId,
        "Brute Force Protection",
        "enabled",
        valueAt(config, ["enabled"]),
        true,
      ),
      change(
        "attack_protection",
        resourceId,
        "Brute Force Protection",
        "shields",
        valueAt(config, ["shields"]),
        addString(valueAt(config, ["shields"]), ["block", "user_notification"]),
      ),
    );
  }
  if (finding.validatorId === "checkBreachedPassword") {
    proposed.push(
      change(
        "attack_protection",
        resourceId,
        "Breached Password Detection",
        "enabled",
        valueAt(config, ["enabled"]),
        true,
      ),
      change(
        "attack_protection",
        resourceId,
        "Breached Password Detection",
        "shields",
        valueAt(config, ["shields"]),
        addString(valueAt(config, ["shields"]), ["block"]),
      ),
      change(
        "attack_protection",
        resourceId,
        "Breached Password Detection",
        "stage.pre-user-registration.shields",
        valueAt(config, ["stage", "pre-user-registration", "shields"]),
        addString(
          valueAt(config, ["stage", "pre-user-registration", "shields"]),
          ["block"],
        ),
      ),
      change(
        "attack_protection",
        resourceId,
        "Breached Password Detection",
        "stage.pre-change-password.shields",
        valueAt(config, ["stage", "pre-change-password", "shields"]),
        addString(
          valueAt(config, ["stage", "pre-change-password", "shields"]),
          ["block"],
        ),
      ),
    );
  }
  return proposed.filter((item): item is ActionableChange => Boolean(item));
}

export type ActionableConfigurationMap = Map<string, ActionableChange[]>;

export async function loadActionableConfiguration(
  findings: readonly NormalizedCheckmateFinding[],
  config: CheckmateConfig,
  fetcher: Fetcher = fetch,
): Promise<ActionableConfigurationMap> {
  const baseUrl = tenantBaseUrl(config.domain);
  const needsConnections = findings.some((finding) =>
    CONNECTION_VALIDATORS.has(finding.validatorId ?? ""),
  );
  const needsAttack = findings.some((finding) =>
    ATTACK_VALIDATORS.has(finding.validatorId ?? ""),
  );
  const scopes = [
    ...(needsConnections
      ? ["read:connections", "read:connections_options"]
      : []),
    ...(needsAttack ? ["read:attack_protection"] : []),
  ];
  if (scopes.length === 0) return new Map();

  try {
    const tokenResponse = await fetcher(`${baseUrl}/oauth/token`, {
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
    if (!tokenResponse.ok) {
      throw new AppError(
        "AUTH0_READ_FAILED",
        `Auth0 could not grant the read-only configuration scopes (${scopes.join(", ")}). Add the missing scopes to the selected CheckMate M2M application.`,
      );
    }
    const token = tokenSchema.safeParse(
      await parseJson(tokenResponse, "Auth0 configuration token request"),
    );
    if (!token.success) {
      throw new AppError(
        "AUTH0_READ_FAILED",
        "Auth0 returned an invalid configuration access token.",
      );
    }
    const headers = { authorization: `Bearer ${token.data.access_token}` };
    let connections: z.infer<typeof connectionsSchema> = [];
    if (needsConnections) {
      const url = new URL(`${baseUrl}/api/v2/connections`);
      url.searchParams.set("strategy", "auth0");
      url.searchParams.set("fields", "id,name,strategy,options");
      url.searchParams.set("include_fields", "true");
      url.searchParams.set("per_page", "100");
      const response = await fetcher(url, {
        headers,
        signal: AbortSignal.timeout(30_000),
      });
      const parsed = connectionsSchema.safeParse(
        await parseJson(response, "Auth0 database connection read"),
      );
      if (
        !parsed.success ||
        parsed.data.some((connection) => !connection.options)
      ) {
        throw new AppError(
          "AUTH0_READ_FAILED",
          "Auth0 did not return database connection options. Grant read:connections and read:connections_options to the selected CheckMate M2M application.",
        );
      }
      connections = parsed.data;
    }

    let bruteForce: Record<string, unknown> | undefined;
    let breachedPassword: Record<string, unknown> | undefined;
    if (findings.some((finding) => finding.validatorId === "checkBruteForce")) {
      const response = await fetcher(
        `${baseUrl}/api/v2/attack-protection/brute-force-protection`,
        {
          headers,
          signal: AbortSignal.timeout(30_000),
        },
      );
      bruteForce = record(
        await parseJson(response, "Auth0 brute-force protection read"),
      );
    }
    if (
      findings.some(
        (finding) => finding.validatorId === "checkBreachedPassword",
      )
    ) {
      const response = await fetcher(
        `${baseUrl}/api/v2/attack-protection/breached-password-detection`,
        {
          headers,
          signal: AbortSignal.timeout(30_000),
        },
      );
      breachedPassword = record(
        await parseJson(response, "Auth0 breached-password protection read"),
      );
    }

    const result: ActionableConfigurationMap = new Map();
    for (const finding of findings) {
      let changes: ActionableChange[] = [];
      if (CONNECTION_VALIDATORS.has(finding.validatorId ?? "")) {
        const name = finding.affectedResource?.name;
        const matching = connections.filter(
          (connection) => !name || connection.name === name,
        );
        changes = matching.flatMap((connection) =>
          connectionChanges(finding, connection),
        );
      } else if (finding.validatorId === "checkBruteForce" && bruteForce) {
        changes = attackChanges(finding, bruteForce);
      } else if (
        finding.validatorId === "checkBreachedPassword" &&
        breachedPassword
      ) {
        changes = attackChanges(finding, breachedPassword);
      }
      if (changes.length > 0) result.set(finding.id, changes);
    }
    return result;
  } catch (error) {
    if (error instanceof AppError) throw error;
    throw new AppError(
      "AUTH0_READ_FAILED",
      "Unable to read live Auth0 configuration for actionable suggestions.",
      { cause: error },
    );
  }
}
