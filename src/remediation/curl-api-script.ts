import type { ApiPlanCall } from "./api-plan.js";

function bashQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function base64Json(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64");
}

function scopes(call: ApiPlanCall): string {
  if (call.resourceType === "client") return "read:clients update:clients";
  if (call.resourceType === "connection") {
    return "read:connections read:connections_options update:connections update:connections_options";
  }
  if (call.resourceType === "attack_protection") {
    return "read:attack_protection update:attack_protection";
  }
  return "read:resource_servers update:resource_servers";
}

function readEndpoint(call: ApiPlanCall): string {
  return call.resourceType === "connection"
    ? `${call.endpoint}?fields=id,name,strategy,options&include_fields=true`
    : call.endpoint;
}

const TOKEN_PAYLOAD_SCRIPT = `const fs = require("node:fs");
const values = fs.readFileSync(0).toString("utf8").split("\\0");
if (values.length < 5) throw new Error("Unable to prepare the Auth0 token request.");
const [clientId, clientSecret, audience, scope] = values;
process.stdout.write(JSON.stringify({
  grant_type: "client_credentials",
  client_id: clientId,
  client_secret: clientSecret,
  audience,
  scope,
}));`;

const TOKEN_PARSER_SCRIPT = `const fs = require("node:fs");
try {
  const token = JSON.parse(fs.readFileSync(0, "utf8"));
  if (typeof token.access_token !== "string" || token.access_token.length === 0) {
    throw new Error("Auth0 returned no access token.");
  }
  if (token.access_token.length > 16384 || /[\\r\\n]/.test(token.access_token)) {
    throw new Error("Auth0 returned an unsafe access token value.");
  }
  if (typeof token.scope === "string") {
    const granted = new Set(token.scope.split(/\\s+/).filter(Boolean));
    const missing = process.env.SCOPES.split(/\\s+/).filter((scope) => !granted.has(scope));
    if (missing.length > 0) throw new Error("Auth0 token is missing scopes: " + missing.join(", "));
  }
  process.stdout.write(token.access_token);
} catch (error) {
  console.error(error instanceof Error ? error.message : "Invalid Auth0 token response.");
  process.exit(1);
}`;

const REQUEST_BUILDER_SCRIPT = `const crypto = require("node:crypto");
const fs = require("node:fs");

function pathValue(source, dottedPath) {
  return dottedPath.split(".").reduce((current, segment) =>
    current !== null && typeof current === "object" && !Array.isArray(current)
      ? current[segment]
      : undefined, source);
}

function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function merge(current, planned) {
  if (current !== null && typeof current === "object" && !Array.isArray(current) &&
      planned !== null && typeof planned === "object" && !Array.isArray(planned)) {
    const result = structuredClone(current);
    for (const [key, value] of Object.entries(planned)) result[key] = merge(result[key], value);
    return result;
  }
  return structuredClone(planned);
}

function stripNulls(value) {
  if (Array.isArray(value)) return value.map(stripNulls);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value)
      .filter(([, nested]) => nested !== null && nested !== undefined)
      .map(([key, nested]) => [key, stripNulls(nested)]));
  }
  return value;
}

function canonical(value) {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value !== null && typeof value === "object") {
    return "{" + Object.entries(value)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, nested]) => JSON.stringify(key) + ":" + canonical(nested))
      .join(",") + "}";
  }
  return JSON.stringify(value) ?? "null";
}

try {
  const live = JSON.parse(fs.readFileSync(0, "utf8"));
  const planned = JSON.parse(Buffer.from(process.env.CHECKMATE_PLANNED_B64, "base64").toString("utf8"));
  const preconditions = JSON.parse(Buffer.from(process.env.CHECKMATE_PRECONDITIONS_B64, "base64").toString("utf8"));
  const allTargets = preconditions.every((item) => same(pathValue(live, item.path), pathValue(planned, item.path)));
  if (allTargets) {
    process.stdout.write(JSON.stringify({ state: "already_applied" }));
    process.exit(0);
  }
  const safe = preconditions.every((item) => {
    const current = pathValue(live, item.path);
    return same(current, item.expectedValue) || same(current, pathValue(planned, item.path));
  });
  if (!safe) throw new Error("Execution stopped: live configuration drifted from the validated plan.");

  let body;
  if (process.env.CHECKMATE_BODY_STRATEGY === "planned_partial") {
    body = structuredClone(planned);
  } else if (process.env.CHECKMATE_BODY_STRATEGY === "merge_live_nested_objects") {
    body = Object.fromEntries(Object.entries(planned).map(([key, value]) => [key, merge(live[key], value)]));
  } else if (process.env.CHECKMATE_BODY_STRATEGY === "merge_live_connection_options") {
    body = { options: merge(stripNulls(live.options ?? {}), planned.options) };
  } else {
    throw new Error("Execution stopped: unsupported body strategy.");
  }

  const digest = crypto.createHash("sha256")
    .update("PATCH\\n" + process.env.CHECKMATE_ENDPOINT + "\\n" + canonical(body), "utf8")
    .digest("hex");
  if (digest !== process.env.CHECKMATE_EXPECTED_REQUEST_SHA256) {
    throw new Error("Execution stopped: the exact PATCH request changed after package validation.");
  }
  process.stdout.write(JSON.stringify({ state: "safe_to_apply", body }));
} catch (error) {
  console.error(error instanceof Error ? error.message : "Unable to prepare the PATCH request.");
  process.exit(1);
}`;

const RESPONSE_FIELD_SCRIPT = `const fs = require("node:fs");
const value = JSON.parse(fs.readFileSync(0, "utf8"));
const field = process.argv[1];
if (field === "body") process.stdout.write(JSON.stringify(value.body));
else process.stdout.write(String(value[field] ?? ""));`;

const VERIFY_SCRIPT = `const fs = require("node:fs");
function pathValue(source, dottedPath) {
  return dottedPath.split(".").reduce((current, segment) =>
    current !== null && typeof current === "object" && !Array.isArray(current)
      ? current[segment]
      : undefined, source);
}
function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}
function preservationDifference(before, after, selectedPaths, currentPath = "") {
  if ((before === null || before === undefined) && (after === null || after === undefined)) return undefined;
  if (currentPath && selectedPaths.includes(currentPath)) return undefined;
  if (before !== null && typeof before === "object" && !Array.isArray(before)) {
    if (after === null || typeof after !== "object" || Array.isArray(after)) return currentPath || "resource";
    for (const [key, value] of Object.entries(before)) {
      const path = currentPath ? currentPath + "." + key : key;
      if (selectedPaths.includes(path)) continue;
      const nestedSelection = selectedPaths.some((item) => item.startsWith(path + "."));
      const afterValue = after[key];
      if (nestedSelection) {
        const difference = preservationDifference(value, afterValue, selectedPaths, path);
        if (difference) return difference;
      } else if (!((value === null || value === undefined) && (afterValue === null || afterValue === undefined)) && !same(value, afterValue)) return path;
    }
  } else if (!same(before, after)) return currentPath || "resource";
  return undefined;
}
try {
  const live = JSON.parse(fs.readFileSync(0, "utf8"));
  const before = JSON.parse(fs.readFileSync(process.env.CHECKMATE_BEFORE_FILE, "utf8"));
  const planned = JSON.parse(Buffer.from(process.env.CHECKMATE_PLANNED_B64, "base64").toString("utf8"));
  const preconditions = JSON.parse(Buffer.from(process.env.CHECKMATE_PRECONDITIONS_B64, "base64").toString("utf8"));
  const verified = preconditions.every((item) =>
    JSON.stringify(pathValue(live, item.path)) === JSON.stringify(pathValue(planned, item.path)));
  if (!verified) throw new Error("Auth0 did not retain every planned setting.");
  const difference = preservationDifference(before, live, preconditions.map((item) => item.path));
  if (difference) throw new Error("Auth0 changed an unselected setting: " + difference);
} catch (error) {
  console.error(error instanceof Error ? error.message : "Unable to verify the PATCH result.");
  process.exit(1);
}`;

export interface CurlApiScript {
  shell: "bash";
  requiredEnvironmentVariables: string[];
  script: string;
}

export function buildCurlApiScript(
  profile: "dev" | "prod",
  call: ApiPlanCall,
  requestSha256: string,
  expectedDomain: string,
): CurlApiScript {
  if (!/^[a-zA-Z0-9.-]+\.auth0\.com$/.test(expectedDomain)) {
    throw new Error(
      "The curl API script requires a valid Auth0 tenant domain.",
    );
  }
  const prefix = `AUTH0CHECKMATE_${profile.toUpperCase()}`;
  const domainVariable = `${prefix}_DOMAIN`;
  const clientIdVariable = `${prefix}_CLIENT_ID`;
  const clientSecretVariable = `${prefix}_CLIENT_SECRET`;

  return {
    shell: "bash",
    requiredEnvironmentVariables: [
      domainVariable,
      clientIdVariable,
      clientSecretVariable,
    ],
    script: `#!/usr/bin/env bash
set -euo pipefail

# Generated from a live-preflighted CheckMate API plan.
# Requires only bash, curl, and Node.js. Credentials are read from the environment.
umask 077
for command in curl node; do
  command -v "\${command}" >/dev/null 2>&1 || {
    echo "Missing required command: \${command}" >&2
    exit 1
  }
done

EXPECTED_DOMAIN=${bashQuote(expectedDomain)}
DOMAIN="\${${domainVariable}:?Set ${domainVariable}}"
CLIENT_ID="\${${clientIdVariable}:?Set ${clientIdVariable}}"
CLIENT_SECRET="\${${clientSecretVariable}:?Set ${clientSecretVariable}}"
export -n CLIENT_ID CLIENT_SECRET 2>/dev/null || true
unset ${clientIdVariable} ${clientSecretVariable}
if [[ "\${DOMAIN}" != "\${EXPECTED_DOMAIN}" ]]; then
  echo "Execution stopped: ${domainVariable} must exactly match the validated tenant \${EXPECTED_DOMAIN}." >&2
  exit 1
fi

export BASE_URL="https://\${DOMAIN}"
export SCOPES=${bashQuote(scopes(call))}
export CHECKMATE_ENDPOINT=${bashQuote(call.endpoint)}
export CHECKMATE_READ_ENDPOINT=${bashQuote(readEndpoint(call))}
export CHECKMATE_RESOURCE_NAME=${bashQuote(call.resourceName)}
export CHECKMATE_BODY_STRATEGY=${bashQuote(call.bodyStrategy)}
export CHECKMATE_EXPECTED_REQUEST_SHA256=${bashQuote(requestSha256)}
export CHECKMATE_PLANNED_B64=${bashQuote(base64Json(call.body))}
export CHECKMATE_PRECONDITIONS_B64=${bashQuote(base64Json(call.preconditions))}

WORK_DIRECTORY="$(mktemp -d "\${TMPDIR:-/tmp}/checkmate-curl.XXXXXX")"
TOKEN_PAYLOAD_FILE="\${WORK_DIRECTORY}/token-request.json"
AUTH_HEADER_FILE="\${WORK_DIRECTORY}/authorization-header"
BEFORE_FILE="\${WORK_DIRECTORY}/before.json"
cleanup() {
  rm -f "\${TOKEN_PAYLOAD_FILE}" "\${AUTH_HEADER_FILE}" "\${BEFORE_FILE}"
  rmdir "\${WORK_DIRECTORY}" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
export CHECKMATE_BEFORE_FILE="\${BEFORE_FILE}"

printf '%s\\0%s\\0%s\\0%s\\0' \
  "\${CLIENT_ID}" "\${CLIENT_SECRET}" "\${BASE_URL}/api/v2/" "\${SCOPES}" |
  node -e ${bashQuote(TOKEN_PAYLOAD_SCRIPT)} > "\${TOKEN_PAYLOAD_FILE}"
unset CLIENT_SECRET

TOKEN_RESPONSE="$(
  curl --fail-with-body --silent --show-error \\
    --retry 3 --retry-delay 1 --retry-max-time 20 \\
    --request POST "\${BASE_URL}/oauth/token" \\
    --header 'content-type: application/json' \\
    --data-binary "@\${TOKEN_PAYLOAD_FILE}"
)"
export -n TOKEN_RESPONSE 2>/dev/null || true
ACCESS_TOKEN="$(printf '%s' "\${TOKEN_RESPONSE}" | node -e ${bashQuote(TOKEN_PARSER_SCRIPT)})"
export -n ACCESS_TOKEN 2>/dev/null || true
printf 'Authorization: Bearer %s\\n' "\${ACCESS_TOKEN}" > "\${AUTH_HEADER_FILE}"
unset ACCESS_TOKEN TOKEN_RESPONSE CLIENT_ID

read_resource() {
  curl --fail-with-body --silent --show-error \\
    --retry 3 --retry-delay 1 --retry-max-time 20 \\
    "\${BASE_URL}\${CHECKMATE_READ_ENDPOINT}" \\
    --header "@\${AUTH_HEADER_FILE}"
}

LIVE="$(read_resource)"
printf '%s' "\${LIVE}" > "\${BEFORE_FILE}"
REQUEST="$(printf '%s' "\${LIVE}" | node -e ${bashQuote(REQUEST_BUILDER_SCRIPT)})"
STATE="$(printf '%s' "\${REQUEST}" | node -e ${bashQuote(RESPONSE_FIELD_SCRIPT)} state)"
if [[ "\${STATE}" == "already_applied" ]]; then
  echo "No change needed: \${CHECKMATE_RESOURCE_NAME} already has the planned settings."
  exit 0
fi
PATCH_BODY="$(printf '%s' "\${REQUEST}" | node -e ${bashQuote(RESPONSE_FIELD_SCRIPT)} body)"

printf '%s' "\${PATCH_BODY}" |
  curl --fail-with-body --silent --show-error --output /dev/null \\
    --request PATCH "\${BASE_URL}\${CHECKMATE_ENDPOINT}" \\
    --header "@\${AUTH_HEADER_FILE}" \\
    --header 'content-type: application/json' \\
    --header "x-correlation-id: checkmate-curl-$(date +%s)" \\
    --data-binary @-

VERIFIED="$(read_resource)"
printf '%s' "\${VERIFIED}" | node -e ${bashQuote(VERIFY_SCRIPT)}
echo "Applied and verified: \${CHECKMATE_RESOURCE_NAME}"
`,
  };
}
