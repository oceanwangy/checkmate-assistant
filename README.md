# Checkmate Remediation Assistant

`checkmate-assistant` is a proof-of-concept TypeScript CLI and local web interface that turns Auth0 CheckMate JSON reports into a safe, finding-driven remediation workflow. It runs CheckMate, normalises findings, verifies supported settings against the live tenant, uses OpenAI to select and explain actionable changes, and records human decisions. Tenant writes are restricted to an explicitly confirmed development execution.

## Architecture

```text
Auth0 tenant
    ↓
Auth0 CheckMate
    ↓
CheckMate JSON report
    ↓
Checkmate Remediation Assistant
    ↓
Normalised findings
    ↓
Redacted finding data → OpenAI explanation
    ↓
Human questions and decision
    ↓
Local review record
    ↓
Dev and production change package
    ├── Auth0 API plan (YAML)
    └── Auth0 Terraform review configuration
             ↓
Terraform validation and API preflight gates
             ↓
Explicit dev API execution and verification
```

CheckMate reports are the primary and only source of security findings. The assistant does not independently scan a tenant. Parsing, validation, filtering, child-process execution, and future change application remain deterministic application responsibilities.

The AI explains only the selected CheckMate finding. The CLI displays CheckMate's wording before the explanation. AI output uses short bullet points and cannot create a new finding or apply a change.

The report adapter accepts:

- CheckMate's current findings-only summary array, grouped by validator with `details` entries;
- the flatter `finding_name` / `finding_title` format shown in Auth0's published example;
- tolerant report envelopes using `findings`, `results`, `checks`, `validators`, `full_report`, or `summary` arrays.

Every normalised finding retains its original `raw` object. Unknown fields are not discarded.

## Prerequisites

- Node.js 20.18.3 or newer (Node.js 22 LTS is recommended for this POC)
- npm
- Terraform CLI 1.5 or newer
- Auth0 CheckMate 1.8.1, installed automatically as a runtime dependency
- A dedicated Auth0 Machine-to-Machine application with CheckMate's documented read scopes
- For dev execution only: `update:connections`, `update:connections_options`, and/or `update:attack_protection`, depending on the accepted changes
- An OpenAI API key and separately configured API billing for the `review` and `chat` commands

CheckMate is pinned in `package.json` and installed locally by `npm install`; no global npm installation or `PATH` configuration is required. See the [official Auth0 CheckMate README](https://github.com/auth0/auth0-checkmate#readme) for the current Auth0 scopes and tenant setup details. The assistant launches CheckMate's packaged entry point non-interactively using its supported environment variables.

## Setup

```sh
npm install
cp .env.example .env
```

Edit `.env` locally. Never commit it:

```dotenv
OPENAI_API_KEY=your-openai-api-key
OPENAI_MODEL=gpt-5.5
OPENAI_REASONING_EFFORT=high
OPENAI_TIMEOUT_MS=180000

AUTH0CHECKMATE_PROD_DOMAIN=your-tenant.auth0.com
AUTH0CHECKMATE_PROD_CLIENT_ID=your-client-id
AUTH0CHECKMATE_PROD_CLIENT_SECRET=your-client-secret

AUTH0CHECKMATE_DEV_DOMAIN=your-development-tenant.auth0.com
AUTH0CHECKMATE_DEV_CLIENT_ID=your-development-client-id
AUTH0CHECKMATE_DEV_CLIENT_SECRET=your-development-client-secret

AUTH0CHECKMATE_DISABLE_PDF_REPORTING=true
AUTH0CHECKMATE_FILE_PATH=./reports
AUTH0CHECKMATE_TIMEOUT_MS=300000

CHECKMATE_CHAT_HOST=127.0.0.1
CHECKMATE_CHAT_PORT=4320
CHECKMATE_CHAT_AUTH0_ENABLED=true
CHECKMATE_CHAT_REMEDIATION_URL=http://127.0.0.1:4317
CHECKMATE_REPORTS_DIR=./reports
CHECKMATE_CHAT_DEV_WRITE_DOMAIN=your-development-tenant.auth0.com
```

`gpt-5.5` with high reasoning is the default review model. `OPENAI_MODEL` and `OPENAI_REASONING_EFFORT` can override these settings. Scan, import, and list commands do not require an OpenAI key.

## Commands

Run a scan using an allowlisted profile:

```sh
npm run dev -- scan --profile prod
npm run dev -- scan --profile dev --verbose
```

CheckMate receives `AUTH0CHECKMATE_DOMAIN`, `AUTH0CHECKMATE_CLIENT_ID`, and `AUTH0CHECKMATE_CLIENT_SECRET` through its child-process environment. Credentials are never command arguments. The executable and argument list are fixed, shell mode is disabled, and unrelated parent-process credentials are not forwarded.

Import and validate an existing report without Auth0 credentials:

```sh
npm run dev -- import-report ./path/to/checkmate-report.json
```

The command validates the source before copying it to `reports/`. A report already in that directory is not copied again.

List findings:

```sh
npm run dev -- list-findings --report ./reports/example.json
npm run dev -- list-findings --report ./reports/example.json --status failed
npm run dev -- list-findings --report ./reports/example.json --status warning
npm run dev -- list-findings --report ./reports/example.json --status all
```

The default status is `failed`. `passed` and `unknown` are also accepted for reports that contain those statuses.

Start the local browser interface and run CheckMate from its start screen:

```sh
npm run dev -- ui --profile dev --status failed
```

Select `Run CheckMate scan`. Every UI session starts with a new scan; it does not reuse an older report. The UI runs the bundled CheckMate dependency with the selected profile, saves a new JSON file under `reports/`, and automatically begins guidance after the report is ready. Use the separate CLI `review` command when intentionally reviewing an existing report.

You can add an admin note explaining a decision, then choose `Accept AI suggestion` or `Remain unchanged` for every recommendation. Notes are optional and are stored in the local JSON audit record when provided. After all decisions are saved, select `Submit`. Both `dev` and `prod` profiles must be configured. The assistant reads each tenant independently and creates this package next to the JSON review record:

```text
<review>.change-package/
├── dev/
│   ├── api-plan.yml
│   └── main.tf
└── prod/
    ├── api-plan.yml
    └── main.tf
```

Each API plan uses that environment's real Auth0 resource IDs and current values. Settings already compliant in one environment are recorded and omitted from its calls. The YAML groups accepted settings into minimal Auth0 `PATCH` calls, records expected current values for drift checks, and excludes unchanged items.

The Terraform files use the official `auth0/auth0` provider to read the affected resources and provide a validated, reviewable representation of the exact proposed changes. They deliberately do not declare partial managed `auth0_connection` resources: the provider warns that omitted nested connection options can overwrite existing configuration. The validated YAML API plan remains the current POC's executable artifact.

For application-level CheckMate findings, the assistant reads the matching live Auth0 client before making a recommendation. Three deterministic recommendations are grouped by setting: set JWT signing to RS256, disable cross-origin authentication, and remove only the `implicit` grant type. Each group displays application checkboxes so the administrator can approve individual applications while preserving every other environment-specific setting.

The review modal shows both environments, both output files, every exact change, and the validation result. Each `api-plan.yml` and `main.tf` can be opened in a readable popup or downloaded directly. Terraform validation runs `terraform fmt -check`, `terraform init -backend=false`, and `terraform validate`. The API preflight obtains the exact required read/update scopes, re-reads every target resource, synthesizes and structurally checks the final PATCH body, and checks all drift preconditions without making a `PATCH` request.

Read-only Auth0 configuration calls automatically retry up to three times when Auth0 returns HTTP 429. The retry uses `Retry-After` or `X-RateLimit-Reset` when available and otherwise uses bounded exponential backoff with jitter.

The saved development `api-plan.yml` is the canonical execution artifact. The application records its SHA-256 digest at submission, reads and parses the file again immediately before execution, and stops if its digest changed after review. The execution audit record stores the same digest.

The modal provides `Execute changes` only when both development validations pass and requires explicit confirmation. Both gates run again immediately before execution. Execution then re-reads every resource, stops on unexpected drift, merges changes into complete live connection options where Auth0 requires full replacement, sends sequential PATCH requests with correlation IDs, and re-reads each resource to verify the result. Execution status is stored in the JSON review record. Production execution is blocked; its artifacts are for the formal production change process.

Review failed findings interactively:

```sh
REPORT="$(ls -t reports/*.json | head -n 1)"
npm run dev -- review --report "$REPORT" --profile dev --status failed
```

Start with one finding to verify API access and control cost:

```sh
npm run dev -- review --report "$REPORT" --profile dev --status failed --limit 1
```

The interactive display is concise by default. To also show the optional AI-generated `What it means` and `Why it matters` sections:

```sh
npm run dev -- review --report "$REPORT" --status failed --limit 1 --show-explanation
```

For each finding, the command:

1. Shows the CheckMate title, status, severity, resource, message, and recommendation when present. Validator IDs and raw evidence stay out of the interactive display.
2. Sends only selected, normalised, redacted fields to OpenAI—not the raw report.
3. Prints short bullets explaining what the finding means and why it matters.
4. Asks up to four finding-specific questions using text, single-select, or keyboard checkbox controls as appropriate.
5. Records `approved`, `rejected`, `deferred`, `accepted_risk`, or `needs_investigation`, with a required rationale.
6. Saves after every decision under `remediation-plans/` as a validated JSON review record.

The OpenAI request uses the Responses API with strict structured output and `store: false`. User answers and decisions remain local in this milestone and are not sent back to OpenAI.

Build and link the package to use the final command name:

```sh
npm run build
npm link
checkmate-assistant --help
```

## One-page security chatbot

The customer-facing chatbot under `apps/checkmate-chat` turns natural-language security questions into short, evidence-backed answers. It connects to two separate MCP servers:

```text
Browser → local chatbot backend → gpt-5.5 (high reasoning)
                                ├── CheckMate MCP (required report evidence)
                                ├── Auth0 MCP (optional live read-only context)
                                └── deterministic dev remediation controller
                                      ↓
                                  exact API preview
                                      ↓
                                  human confirmation
                                      ↓
                                  dev-only executor and verification
```

The chatbot starts every question by reading the newest valid report in `reports/`. It can then search findings, inspect application posture, or collect security-topic context. When the official Auth0 MCP Server is authenticated, it may also read applications and logs to close a useful evidence gap. Only these four Auth0 tools are allowed: `auth0_list_logs`, `auth0_get_log`, `auth0_list_applications`, and `auth0_get_application`.

The official Auth0 MCP authentication is the only additional manual setup. Run it once and complete the browser/device login:

```sh
npx @auth0/auth0-mcp-server init --read-only
```

Then start the one-page app:

```sh
npm run chat
```

Open `http://127.0.0.1:4320`. If Auth0 MCP is not authenticated, the page still works in report-only mode and labels live Auth0 as unavailable. Good customer-demo questions include:

- “I recently experienced a credential stuffing attack. What should I do first?”
- “What are the most important security weaknesses in this tenant?”
- “How should I harden the GrantMate application?”

Each answer shows whether a statement is based on CheckMate report evidence, live Auth0 data, or general guidance. The evidence drawer lists the exact report, finding IDs, and MCP tools used. Raw reports are never sent to OpenAI; only bounded, normalised MCP results are sent. Auth0 secrets, tokens, email addresses, and full IP addresses are redacted. Requests use `store: false`.

For a concrete recommendation that maps to a supported action, the backend reads the matching live development configuration and builds the Management API plan deterministically. The AI cannot supply an endpoint or request body. The page displays every `PATCH` URL, affected setting, before/after value, and the request body. Sensitive live values are redacted in the browser, while the confirmation remains bound to a SHA-256 digest of the complete request.

Execution requires both a confirmation checkbox and the exact phrase `EXECUTE DEV`. Plans expire after ten minutes and are single-use. Immediately before execution, the application obtains fresh least-privilege credentials, reads the resources again, rebuilds each request, and stops if its digest or a planned value changed. It then applies calls sequentially with correlation IDs and reads each resource again to verify the target values. A local audit record is written under `remediation-plans/chat-executions/`.

Only `AUTH0CHECKMATE_DEV_*` credentials are loaded by this path. Read-only API preparation is available when those dev credentials are configured. Execution additionally requires `CHECKMATE_CHAT_DEV_WRITE_DOMAIN` to exactly match `AUTH0CHECKMATE_DEV_DOMAIN`. Production plans and production credentials are not accepted by the chat executor. The interface instructs administrators to validate in development and use their production change management process rather than applying a chatbot change directly to production. The official Auth0 MCP connection remains read-only; confirmed writes use the existing deterministic API-plan executor rather than a model-callable update tool. `Review changes` continues to open the larger dual-environment workflow.

The local HTTP service binds to loopback, checks the request host and origin, and uses a session-specific CSRF token.

## CheckMate MCP Server

The repository also contains an independent, read-only MCP server under `packages/checkmate-mcp-server`. It gives an MCP host structured access to CheckMate reports so the host's AI can answer questions such as:

- “I recently experienced credential stuffing. Which controls should I review?”
- “How can I harden the security posture of Example SPA?”
- “What are the most important failed controls in the latest report?”

The MCP server does not call OpenAI, authenticate to Auth0, execute CheckMate, or change a tenant. It reads JSON files only from its configured `reports` directory. The MCP host supplies the AI reasoning. This keeps report evidence and AI interpretation as separate layers.

Build and start it over stdio:

```sh
npm run build
npm run mcp -- --reports-dir ./reports
```

MCP hosts normally start stdio servers themselves. Configure the built server with absolute paths:

```json
{
  "mcpServers": {
    "checkmate": {
      "command": "node",
      "args": [
        "/absolute/path/to/checkmate-assistant/packages/checkmate-mcp-server/dist/cli.js",
        "--reports-dir",
        "/absolute/path/to/checkmate-assistant/reports"
      ]
    }
  }
}
```

It can run alone. If the official Auth0 MCP Server is also configured, add it as a separate sibling entry in the MCP host; neither server depends on the other. CheckMate supplies report posture and finding provenance, while the Auth0 server may supply separately authorised live resources or logs. Follow the [official Auth0 MCP Server setup](https://github.com/auth0/auth0-mcp-server#readme) for that optional server.

The CheckMate MCP server exposes:

- `checkmate_list_reports`
- `checkmate_get_report_summary`
- `checkmate_search_findings`
- `checkmate_get_finding`
- `checkmate_get_application_posture`
- `checkmate_get_security_topic_context`

It also exposes the `checkmate://reports/latest/summary` resource and reusable `investigate-security-question` and `harden-application` prompts. The newest valid JSON report is selected when `reportId` is omitted. Tool responses include report and finding IDs, freshness, findings-only coverage warnings, and redacted evidence.

Optional settings can be passed as CLI arguments or environment variables:

```text
--max-report-age-days / CHECKMATE_MAX_REPORT_AGE_DAYS
--max-report-bytes    / CHECKMATE_MAX_REPORT_BYTES
--reports-dir         / CHECKMATE_REPORTS_DIR
```

## Verification

```sh
npm run build
npm run lint
npm test
npm run format:check
```

Tests mock child-process execution and the OpenAI provider. They require no Auth0 or OpenAI credentials.

Generated Terraform is also checked against the provider schema during submission. The first validation may download the pinned Auth0 provider into the generated change-package directory.

## Report caveats

CheckMate 1.8.1 currently writes a JSON summary containing only red/yellow finding details; green/passed validators are filtered out before serialization. The assistant therefore prints `Passed checks: 0` plus an explicit note that passed validators were not included. It does not infer a total or invent pass results.

The current CheckMate JSON also omits tenant and generation metadata. During `scan`, the selected domain is supplied as summary context. For imported reports, the domain remains “not included in report” unless a supported envelope provides it. A file's modification time is used as the best available report timestamp and should not be mistaken for a scanner-authored timestamp.

A real report from the target tenant is still needed to confirm any tenant/version-specific field variants and to improve affected-resource extraction. Unsupported structures fail with a clear error instead of being guessed.

## Security boundaries

- Scan, review, package generation, Terraform validation, and API preflight perform no Auth0 write operations. Only the explicitly confirmed dev API execution step can write.
- Production execution is blocked.
- OpenAI is called only by explicit review or chatbot workflows. The chatbot model can invoke only the bounded read-only MCP allowlists; it cannot invoke CheckMate execution or Auth0 write APIs. Confirmed dev execution remains deterministic application code based on an expiring, digest-bound plan.
- The raw CheckMate report, environment, API key, Auth0 credentials, and Management API tokens are never sent to OpenAI.
- Only selected normalised fields are sent. Sensitive keys, known credential values, bearer values, and JWT-shaped strings are redacted.
- OpenAI responses use a strict schema, short bullet arrays, and low verbosity. The remediation review uses no model tools; the chatbot exposes only its documented read-only MCP tools.
- The CheckMate MCP server is read-only, has no Auth0 or OpenAI credentials, accepts report IDs rather than arbitrary paths, rejects oversized reports, and redacts sensitive evidence before returning it.
- Finite AI questions use select controls. The AI may only use standard yes/no/investigation choices; it cannot invent application names.
- Application checkboxes come from a narrow, finding-triggered, read-only Auth0 `read:clients` lookup. There is no generic Management API request function.
- Each stored decision references its CheckMate finding ID and preserves the available CheckMate wording.
- No generic shell command or generic Auth0 Management API function exists.
- Chat plans are dev-only, expire after ten minutes, require a checkbox plus `EXECUTE DEV`, and are revalidated against the exact confirmed request digest before any PATCH.
- The runner invokes only the pinned CheckMate package entry point through the current Node.js runtime, with no user-controlled executable or arguments.
- Secrets are excluded from command arguments, logs, errors, reports, snapshots, and generated files.
- Verbose child output is redacted against the active client secret.
- Sensitive object keys including secret, token, password, API key, and authorization are recursively redacted.
- `.env*`, reports, and remediation plans are ignored, while placeholders remain tracked.

CheckMate itself reads tenant configuration through the Auth0 Management API and consumes tenant rate limits. Use a dedicated least-privilege application and review the official scope list.

## Milestones

1. **Milestone 1 — complete:** safe CheckMate scan, import, normalisation, and finding listing.
2. **Milestone 2 — complete:** redacted OpenAI explanation, interactive questions, and local decision records.
3. **Milestone 3 — complete:** generate environment-specific YAML API plans and Terraform review configurations from accepted action-level decisions, with an in-browser review.
4. **Milestone 4 — complete for supported actions:** validate Terraform and preflight-check API plans for both environments; require a fresh development preflight and confirmation before sequential API execution and verification.
5. **Milestone 5 — first read-only slice complete:** expose report summaries, finding search, application posture, security-topic context, and grounded prompt templates through a standalone stdio MCP server.
6. **Milestone 6 — planned:** rerun the same CheckMate validators, record verification evidence, and test rollback.

Production changes remain outside the current POC. Future MCP capabilities will remain narrow and will keep tenant writes behind the existing reviewed change-package workflow.
