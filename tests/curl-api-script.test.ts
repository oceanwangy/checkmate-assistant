import { chmod, mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { apiRequestSha256 } from "../src/auth0/api-plan-executor.js";
import type { ApiPlanCall } from "../src/remediation/api-plan.js";
import { buildCurlApiScript } from "../src/remediation/curl-api-script.js";
import { buildApiPlanShellScript } from "../src/remediation/api-plan-shell.js";

function connectionCall(): ApiPlanCall {
  return {
    id: "api-call-1",
    method: "PATCH",
    endpoint: "/api/v2/connections/con_database",
    resourceType: "connection",
    resourceId: "con_database",
    resourceName: "Username-Password-Authentication",
    bodyStrategy: "merge_live_connection_options",
    actionIds: ["action-history"],
    preconditions: [
      { path: "options.password_history.enable", expectedValue: false },
    ],
    body: { options: { password_history: { enable: true } } },
  };
}

describe("generated curl API scripts", () => {
  it("uses profile-specific environment variables and contains valid Bash", () => {
    const call = connectionCall();
    const generated = buildCurlApiScript(
      "prod",
      call,
      "a".repeat(64),
      "prod-tenant.auth0.com",
    );

    expect(generated.requiredEnvironmentVariables).toEqual([
      "AUTH0CHECKMATE_PROD_DOMAIN",
      "AUTH0CHECKMATE_PROD_CLIENT_ID",
      "AUTH0CHECKMATE_PROD_CLIENT_SECRET",
    ]);
    expect(generated.script).toContain(
      'CLIENT_ID="${AUTH0CHECKMATE_PROD_CLIENT_ID:?Set AUTH0CHECKMATE_PROD_CLIENT_ID}"',
    );
    expect(generated.script).toContain(
      "EXPECTED_DOMAIN='prod-tenant.auth0.com'",
    );
    expect(generated.script).toContain("--request PATCH");
    expect(generated.script).toContain("--data-binary @-");
    expect(generated.script).toContain("umask 077");
    expect(generated.script).toContain('AUTH_HEADER_FILE="${WORK_DIRECTORY}');
    expect(generated.script).toContain('--header "@${AUTH_HEADER_FILE}"');
    expect(generated.script).not.toContain(
      '--header "authorization: Bearer ${ACCESS_TOKEN}"',
    );
    expect(generated.script).not.toContain("jq");
    expect(
      spawnSync("bash", ["-n"], {
        input: generated.script,
        encoding: "utf8",
      }),
    ).toMatchObject({ status: 0, stderr: "" });
  });

  it("obtains a token, preserves live connection options, patches, and verifies", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-curl-"));
    const patchBodyFile = path.join(directory, "patch-body.json");
    const tokenBodyFile = path.join(directory, "token-body.json");
    const curlArgsFile = path.join(directory, "curl-args.txt");
    const fakeCurl = path.join(directory, "curl");
    const scriptFile = path.join(directory, "change.sh");
    const before = {
      id: "con_database",
      name: "Username-Password-Authentication",
      options: {
        password_history: { enable: false, size: 5 },
        requires_username: false,
        passwordPolicy: null,
      },
    };
    const expectedBody = {
      options: {
        password_history: { enable: true, size: 5 },
        requires_username: false,
      },
    };
    const after = { ...before, options: expectedBody.options };
    await writeFile(
      fakeCurl,
      `#!/usr/bin/env bash
set -euo pipefail
if [[ -n "\${AUTH0CHECKMATE_DEV_CLIENT_SECRET:-}" || -n "\${CLIENT_SECRET:-}" ]]; then
  echo "credential leaked into curl environment" >&2
  exit 91
fi
printf '%s\n' "$*" >> "\${CURL_ARGS_FILE}"
if [[ "$*" == *"/oauth/token"* ]]; then
  for argument in "$@"; do
    if [[ "\${argument}" == @* ]]; then
      cat "\${argument#@}" > "\${TOKEN_BODY_FILE}"
    fi
  done
  printf '%s' '{"access_token":"test-token","scope":"read:connections read:connections_options update:connections update:connections_options"}'
elif [[ "$*" == *"--request PATCH"* ]]; then
  cat > "\${PATCH_BODY_FILE}"
else
  if [[ -s "\${PATCH_BODY_FILE}" ]]; then
    printf '%s' '${JSON.stringify(after)}'
  else
    printf '%s' '${JSON.stringify(before)}'
  fi
fi
`,
    );
    await chmod(fakeCurl, 0o700);

    const call = connectionCall();
    const digest = apiRequestSha256(call.method, call.endpoint, expectedBody);
    const generated = buildCurlApiScript(
      "dev",
      call,
      digest,
      "tenant.auth0.com",
    );
    await writeFile(scriptFile, generated.script, { mode: 0o700 });
    const result = spawnSync("bash", [scriptFile], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${directory}:${process.env.PATH ?? ""}`,
        PATCH_BODY_FILE: patchBodyFile,
        TOKEN_BODY_FILE: tokenBodyFile,
        CURL_ARGS_FILE: curlArgsFile,
        AUTH0CHECKMATE_DEV_DOMAIN: "tenant.auth0.com",
        AUTH0CHECKMATE_DEV_CLIENT_ID: "client-from-env",
        AUTH0CHECKMATE_DEV_CLIENT_SECRET: "secret-from-env",
      },
    });

    expect(result).toMatchObject({ status: 0, stderr: "" });
    expect(result.stdout).toContain(
      "Applied and verified: Username-Password-Authentication",
    );
    expect(JSON.parse(await readFile(patchBodyFile, "utf8"))).toEqual(
      expectedBody,
    );
    expect(JSON.parse(await readFile(tokenBodyFile, "utf8"))).toMatchObject({
      client_id: "client-from-env",
      client_secret: "secret-from-env",
    });
    expect(generated.script).not.toContain("client-from-env");
    expect(generated.script).not.toContain("secret-from-env");
    const curlArguments = await readFile(curlArgsFile, "utf8");
    expect(curlArguments).not.toContain("secret-from-env");
    expect(curlArguments).not.toContain("test-token");
  });

  it("stops before authentication when the configured tenant does not match", () => {
    const generated = buildCurlApiScript(
      "dev",
      connectionCall(),
      "a".repeat(64),
      "expected.auth0.com",
    );
    const result = spawnSync("bash", {
      input: generated.script,
      encoding: "utf8",
      env: {
        ...process.env,
        AUTH0CHECKMATE_DEV_DOMAIN: "wrong.auth0.com",
        AUTH0CHECKMATE_DEV_CLIENT_ID: "client-from-env",
        AUTH0CHECKMATE_DEV_CLIENT_SECRET: "secret-from-env",
      },
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "must exactly match the validated tenant expected.auth0.com",
    );
    expect(result.stderr).not.toContain("secret-from-env");
  });

  it("runs every validated call in its own subshell", () => {
    const first = connectionCall();
    const second = {
      ...connectionCall(),
      id: "api-call-2",
      resourceName: "Second database",
    };
    const script = buildApiPlanShellScript({
      schemaVersion: 1,
      generatedAt: "2026-08-03T10:00:00.000Z",
      sourceReport: "report.json",
      profile: "dev",
      tenantDomain: "tenant.auth0.com",
      validatedAt: "2026-08-03T10:01:00.000Z",
      unchangedActionIds: [],
      alreadyCompliantActionIds: [],
      calls: [
        {
          ...first,
          curl: {
            shell: "bash",
            requiredEnvironmentVariables: ["A", "B", "C"],
            script: "#!/usr/bin/env bash\necho first\nexit 0\n",
          },
        },
        {
          ...second,
          curl: {
            shell: "bash",
            requiredEnvironmentVariables: ["A", "B", "C"],
            script: "#!/usr/bin/env bash\necho second\n",
          },
        },
      ],
    });
    const result = spawnSync("bash", {
      input: script,
      encoding: "utf8",
    });

    expect(result).toMatchObject({ status: 0, stderr: "" });
    expect(result.stdout).toContain("first");
    expect(result.stdout).toContain("second");
    expect(result.stdout).toContain(
      "Applied and verified all validated API calls.",
    );
  });
});
