import type { NormalizedCheckmateFinding } from "../findings/types.js";
import { isSensitiveKey } from "../security/sensitive-fields.js";
import { REDACTED, redactText } from "../security/redaction.js";

const MAX_STRING_LENGTH = 2_000;
const MAX_ARRAY_ITEMS = 20;
const MAX_DEPTH = 5;

export interface AiFindingPayload {
  id: string;
  validatorId?: string;
  title: string;
  status: string;
  severity?: string;
  description?: string;
  recommendation?: string;
  affectedResource?: {
    type?: string;
    id?: string;
    name?: string;
  };
  evidence?: unknown;
}

function sanitizeString(
  value: string,
  sensitiveValues: readonly string[],
): string {
  const redacted = redactText(value, sensitiveValues);
  return redacted.length > MAX_STRING_LENGTH
    ? `${redacted.slice(0, MAX_STRING_LENGTH - 1)}…`
    : redacted;
}

function sanitizeValue(
  value: unknown,
  sensitiveValues: readonly string[],
  depth = 0,
): unknown {
  if (depth > MAX_DEPTH) return "[TRUNCATED]";
  if (typeof value === "string") return sanitizeString(value, sensitiveValues);
  if (typeof value === "number" || typeof value === "boolean" || value === null)
    return value;
  if (Array.isArray(value)) {
    return value
      .slice(0, MAX_ARRAY_ITEMS)
      .map((item) => sanitizeValue(item, sensitiveValues, depth + 1));
  }
  if (value !== null && typeof value === "object") {
    const source = value as Record<string, unknown>;
    const fieldName =
      typeof source.field === "string" ? source.field : undefined;
    return Object.fromEntries(
      Object.entries(source).map(([key, item]) => {
        if (
          isSensitiveKey(key) ||
          (key === "value" && fieldName && isSensitiveKey(fieldName))
        ) {
          return [key, REDACTED];
        }
        return [key, sanitizeValue(item, sensitiveValues, depth + 1)];
      }),
    );
  }
  return undefined;
}

function assignString(
  target: Record<string, unknown>,
  key: string,
  value: string | undefined,
  sensitiveValues: readonly string[],
): void {
  if (value) target[key] = sanitizeString(value, sensitiveValues);
}

export function buildAiFindingPayload(
  finding: NormalizedCheckmateFinding,
  sensitiveValues: readonly string[] = [],
): AiFindingPayload {
  const payload: Record<string, unknown> = {
    id: sanitizeString(finding.id, sensitiveValues),
    title: sanitizeString(finding.title, sensitiveValues),
    status: finding.status,
  };
  assignString(payload, "validatorId", finding.validatorId, sensitiveValues);
  assignString(payload, "severity", finding.severity, sensitiveValues);
  assignString(payload, "description", finding.description, sensitiveValues);
  assignString(
    payload,
    "recommendation",
    finding.recommendation,
    sensitiveValues,
  );
  if (finding.affectedResource) {
    payload.affectedResource = sanitizeValue(
      finding.affectedResource,
      sensitiveValues,
    );
  }
  if (finding.evidence !== undefined) {
    payload.evidence = sanitizeValue(finding.evidence, sensitiveValues);
  }
  return payload as unknown as AiFindingPayload;
}

export function collectSensitiveEnvironmentValues(
  env: NodeJS.ProcessEnv,
): string[] {
  return Object.entries(env)
    .filter(([key, value]) => isSensitiveKey(key) && Boolean(value))
    .map(([, value]) => value as string);
}
