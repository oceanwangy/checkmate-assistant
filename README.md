# Checkmate Remediation Assistant

`checkmate-assistant` combines two separate capabilities: a deterministic remediation UI, and an AI chatbot grounded in read-only CheckMate report evidence. The remediation workflow runs CheckMate, verifies supported settings against the live tenant, creates reviewed deployment artifacts, and restricts tenant writes to explicitly confirmed development execution. The chatbot uses OpenAI only for natural-language conversation over bounded report and live read-only evidence.

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
Live-verified deterministic recommendations
    ↓
Human questions and decision
    ↓
Local review record
    ↓
Dev and production change package
    ├── Auth0 API plan (YAML)
    ├── Executable Bash API plan
    └── Executable Auth0 Terraform configuration
             ↓
Terraform validation and API preflight gates
             ↓
Explicit dev API execution and verification
```

CheckMate reports are the primary and only source of security findings. Remediation selection, wording, grouping, package generation, validation, and execution use versioned TypeScript mappings and do not call OpenAI. Unknown settings fail closed instead of becoming executable recommendations. The separate chatbot can interpret bounded report evidence, but it cannot invent an endpoint or request body.

The report adapter accepts:

- CheckMate's current findings-only summary array, grouped by validator with `details` entries;
- the flatter `finding_name` / `finding_title` format shown in Auth0's published example;
- tolerant report envelopes using `findings`, `results`, `checks`, `validators`, `full_report`, or `summary` arrays.

Every normalised finding retains its original `raw` object. Unknown fields are not discarded.

## Prerequisites

- Node.js 20.18.3 or newer (Node.js 22 LTS is recommended for this POC)
- npm
- Terraform CLI 1.5 or newer
- Auth0 CheckMate 1.8.3, installed automatically as a runtime dependency
- A dedicated Auth0 Machine-to-Machine application with CheckMate's documented read scopes
- For dev execution only: `update:connections`, `update:connections_options`, and/or `update:attack_protection`, depending on the accepted changes
- An OpenAI API key and separately configured API billing only for the optional chatbot

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

`gpt-5.5` with high reasoning is the default chatbot model. `OPENAI_MODEL` and `OPENAI_REASONING_EFFORT` can override these settings. Scan, remediation review, package generation, and execution do not require an OpenAI key.

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

Select `Run CheckMate scan`. Every UI session starts with a new scan; it does not reuse an older report. The UI runs the bundled CheckMate dependency with the selected profile, saves a new JSON file under `reports/`, and prepares deterministic guidance after the report is ready.

Before starting, confirm that development mirrors production's security-relevant configuration while keeping tenant domains, resource IDs, credentials, users, logs, and customer data separate. You can add an optional admin note, then choose `Accept suggestion` or `Remain unchanged` for every recommendation. After all decisions are saved, select `Submit`. Both `dev` and `prod` profiles must be configured. The assistant reads each tenant independently and creates this package next to the JSON review record:

```text
<review>.change-package/
├── dev/
│   ├── api-plan.yml
│   ├── apply-api-plan.sh
│   └── main.tf
└── prod/
    ├── api-plan.yml
    ├── apply-api-plan.sh
    └── main.tf
```

Each API plan uses that environment's real Auth0 resource IDs and current values. Settings already compliant in one environment are recorded and omitted. The YAML groups accepted settings into minimal tenant-bound `PATCH` calls, records drift preconditions, and stamps the exact live-merged request digest. The companion Bash script obtains credentials from environment variables and reproduces the same drift, digest, rate-limit, and post-change verification controls.

The Terraform files are genuine deployment configurations using the official `auth0/auth0` provider. Import blocks adopt existing resources, `prevent_destroy` prevents deletion, and targeted `ignore_changes` entries preserve unrelated imported settings. Package creation requires both the API mapping and Terraform mapping to validate; partial dual-format coverage is rejected.

For application-level CheckMate findings, the assistant reads the matching live Auth0 client before making a recommendation. Three deterministic recommendations are grouped by setting: set JWT signing to RS256, disable cross-origin authentication, and remove only the `implicit` grant type. Each group displays application checkboxes so the administrator can approve individual applications while preserving every other environment-specific setting.

The review modal shows both environments, all three output files, every exact change, and the validation result. Terraform validation runs `fmt`, `init`, `validate`, and a credentialed read-only `plan`; its machine-readable output is rejected for destroy, replacement, unexpected resource types, or unimported creates. API preflight re-reads every resource and validates the exact request without making a `PATCH`.

Read-only Auth0 calls automatically retry up to five times for HTTP 429 using Auth0 rate-limit headers or bounded exponential backoff. A rate-limited `PATCH` is never retried blindly: execution waits, re-reads, verifies preconditions and the confirmed digest, then resumes safely.

The saved development `api-plan.yml` is the canonical execution artifact. The application records its SHA-256 digest, reads it again before execution, and stops if the file or live-merged request changed after review.

The modal provides `Execute changes` only when development validations pass and requires explicit confirmation. Execution re-reads every resource, stops on drift, sends sequential PATCH requests with correlation IDs, and verifies selected and preserved fields. Failed executions can resume after review, and applied calls can be rolled back in reverse order. Production execution is blocked; its package goes through the formal production change process.

Build and link the package to use the final command name:

```sh
npm run build
npm link
checkmate-assistant --help
```

## One-page security chatbot

The customer-facing chatbot under `apps/checkmate-chat` turns natural-language security questions into short, evidence-backed answers. Report evidence is read in-process; the official Auth0 MCP Server is the only MCP connection:

```text
Browser → local chatbot backend → gpt-5.5 (high reasoning)
                                ├── in-process CheckMate report tools (required report evidence)
                                ├── Auth0 MCP (optional live read-only context)
                                └── deterministic dev remediation controller
                                      ↓
                                  exact API preview
                                      ↓
                                  human confirmation
                                      ↓
                                  dev-only executor and verification
```

The chatbot starts with two explicit assessment actions: `Run CheckMate for dev` and `Run CheckMate for prod`. Each action creates a new CheckMate report and binds the browser session to that exact report ID. Every subsequent report lookup is forced to the selected report, so development and production evidence cannot be mixed by a generic “latest report” lookup. Development conversations may offer supported, separately confirmed changes. Production conversations are advisory only and cannot create or execute remediation plans.

After a scan, the chatbot can search findings, inspect application posture, or collect security-topic context through read-only in-process report tools backed by the shared `@checkmate-assistant/core` query library. When the official Auth0 MCP Server is authenticated, it may also read applications and logs to close a useful evidence gap. Only these four Auth0 tools are allowed: `auth0_list_logs`, `auth0_get_log`, `auth0_list_applications`, and `auth0_get_application`. CheckMate execution belongs to the chatbot backend; the report tools remain a read-only report interface.

The official Auth0 MCP authentication is the only additional manual setup. Run it once and complete the browser/device login:

```sh
npx @auth0/auth0-mcp-server init --read-only
```

Then start the one-page app:

```sh
npm run chat
```

Open `http://127.0.0.1:4320`, then run a fresh development or production assessment before asking a question. If Auth0 MCP is not authenticated, the page still works from the selected CheckMate report. Good customer-demo questions include:

- “I recently experienced a credential stuffing attack. What should I do first?”
- “What are the most important security weaknesses in this tenant?”
- “How should I harden the GrantMate application?”

Each answer shows whether a statement is based on CheckMate report evidence, live Auth0 data, or general guidance. The evidence drawer lists the exact report, finding IDs, and tools used. Raw reports are never sent to OpenAI; only bounded, normalised tool results are sent. Auth0 secrets, tokens, email addresses, and full IP addresses are redacted. Requests use `store: false`.

For a concrete recommendation that maps to a supported action, the backend reads the matching live development configuration and builds the Management API plan deterministically. The AI cannot supply an endpoint or request body. The page displays every `PATCH` URL, affected setting, before/after value, and the request body. Sensitive live values are redacted in the browser, while the confirmation remains bound to a SHA-256 digest of the complete request.

Execution requires both a confirmation checkbox and the exact phrase `EXECUTE DEV`. Plans expire after ten minutes and are single-use. Immediately before execution, the application obtains fresh least-privilege credentials, reads the resources again, rebuilds each request, and stops if its digest or a planned value changed. It then applies calls sequentially with correlation IDs and reads each resource again to verify the target values. A local audit record is written under `remediation-plans/chat-executions/`.

Only `AUTH0CHECKMATE_DEV_*` credentials are loaded by this path. Read-only API preparation is available when those dev credentials are configured. Execution additionally requires `CHECKMATE_CHAT_DEV_WRITE_DOMAIN` to exactly match `AUTH0CHECKMATE_DEV_DOMAIN`. Production plans and production credentials are not accepted by the chat executor. The interface instructs administrators to validate in development and use their production change management process rather than applying a chatbot change directly to production. The official Auth0 MCP connection remains read-only; confirmed writes use the existing deterministic API-plan executor rather than a model-callable update tool. `Remediation Review` continues to open the larger dual-environment workflow.

The local HTTP service binds to loopback, checks the request host and origin, and uses a session-specific CSRF token.

## CheckMate report tools

The chatbot's report evidence comes from six read-only in-process tools implemented over the shared `@checkmate-assistant/core` query library:

- `checkmate_list_reports`
- `checkmate_get_report_summary`
- `checkmate_search_findings`
- `checkmate_get_finding`
- `checkmate_get_application_posture`
- `checkmate_get_security_topic_context`

The newest valid JSON report is selected when `reportId` is omitted, and the chat session pins every lookup to its scanned report. Tool responses include report and finding IDs, freshness, findings-only coverage warnings, and redacted evidence. The tools hold no Auth0 or OpenAI credentials, accept report IDs rather than arbitrary paths, and reject oversized reports.

## Verification

```sh
npm run build
npm run lint
npm test
npm run format:check
```

Tests mock child-process execution, Auth0 reads, and the chatbot model. They require no Auth0 or OpenAI credentials.

Generated Terraform is also checked against the provider schema during submission. The first validation may download the pinned Auth0 provider into the generated change-package directory.

## Report caveats

CheckMate 1.8.3 writes a JSON summary containing validator detail outcomes. A validator's parent colour is its priority: red is high, yellow is moderate, green is low, blue is informational, and violet is a GenAI insight. The posture model compares the report with the version-locked 1.8.3 catalog: its 36 red/yellow/green validators provide 118 available points, and scorable validators absent from a complete findings-only report are counted as passed.

The current CheckMate JSON also omits tenant and generation metadata. During `scan`, the selected domain is supplied as summary context. For imported reports, the domain remains “not included in report” unless a supported envelope provides it. A file's modification time is used as the best available report timestamp and should not be mistaken for a scanner-authored timestamp.

A real report from the target tenant is still needed to confirm any tenant/version-specific field variants and to improve affected-resource extraction. Unsupported structures fail with a clear error instead of being guessed.

## Security boundaries

- Scan, review, package generation, Terraform validation, and API preflight perform no Auth0 write operations. Only the explicitly confirmed dev API execution step can write.
- Production execution is blocked.
- The remediation UI does not call OpenAI. Recommendations and deployment artifacts come from versioned, testable mappings over supported CheckMate validators and narrow live Auth0 reads.
- OpenAI is called only by the explicit chatbot workflow. The chatbot model can invoke only bounded read-only tool allowlists; it cannot invoke CheckMate execution or Auth0 write APIs. Confirmed dev execution remains deterministic application code based on an expiring, digest-bound plan.
- The raw CheckMate report, environment, API key, Auth0 credentials, and Management API tokens are never sent to OpenAI.
- Only selected normalised fields are sent. Sensitive keys, known credential values, bearer values, and JWT-shaped strings are redacted.
- OpenAI responses use a strict schema, short bullet arrays, and low verbosity. The chatbot exposes only its documented read-only tools.
- The in-process CheckMate report tools are read-only, hold no Auth0 or OpenAI credentials, accept report IDs rather than arbitrary paths, reject oversized reports, and redact sensitive evidence before returning it.
- Application and connection checkboxes come from narrow, finding-triggered, read-only Auth0 lookups. There is no generic Management API request function.
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
2. **Milestone 2 — complete:** deterministic remediation guidance and local administrator decision records.
3. **Milestone 3 — complete:** generate environment-specific YAML, Bash, and executable Terraform packages from accepted action-level decisions.
4. **Milestone 4 — complete for supported actions:** validate Terraform and API plans for both environments; require explicit development confirmation, drift checks, execution verification, resume, and rollback.
5. **Milestone 5 — complete:** expose report summaries, finding search, application posture, and security-topic context through the shared read-only report query library used in-process by the chatbot.
6. **Milestone 6 — planned:** rerun the same CheckMate validators and record post-change verification evidence.

Production changes remain outside the current POC. The Auth0 MCP connection stays read-only, and tenant writes remain behind the existing reviewed change-package workflow.
