# Checkmate Remediation Assistant

`checkmate-assistant` is a proof-of-concept TypeScript CLI and local web interface that turns Auth0 CheckMate JSON reports into a safe, finding-driven remediation workflow. It runs CheckMate, normalises findings, verifies supported settings against the live tenant, uses OpenAI to select and explain actionable changes, and records human decisions. It remains read-only for Auth0 tenants.

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
Validated YAML API plan
    ↓
Explicit dev execution and verification
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
- Auth0 CheckMate 1.8.1, installed automatically as a runtime dependency
- A dedicated Auth0 Machine-to-Machine application with CheckMate's documented read scopes
- For dev execution only: `update:connections`, `update:connections_options`, and/or `update:attack_protection`, depending on the accepted changes
- An OpenAI API key and separately configured API billing for the `review` command

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

Select `Run CheckMate scan`. The UI runs the bundled CheckMate dependency with the selected profile, saves the JSON under `reports/`, and automatically begins AI guidance after the report is ready. You can also select `Run new scan` from an existing review.

To review an existing report instead of running a new scan:

```sh
npm run dev -- ui --report ./reports/example.json --profile dev --status failed
```

Choose `Accept AI suggestion` or `Remain unchanged` for every recommendation. After all decisions are saved, select `Submit`. This creates a validated `.api-plan.yml` file next to the JSON review record and opens it in a review modal. The YAML groups accepted settings into minimal Auth0 `PATCH` calls, records expected current values for drift checks, and excludes unchanged items.

The review modal provides `Execute changes` only for the `dev` profile and requires an explicit confirmation. Execution re-reads every resource, stops on unexpected drift, merges changes into complete live connection options where Auth0 requires full replacement, sends sequential PATCH requests with correlation IDs, and re-reads each resource to verify the result. Execution status is stored in the JSON review record. Production execution is blocked.

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
npm run dev -- review --report "$REPORT" --profile dev --status failed --limit 1 --show-explanation
```

For each finding, the command:

1. Shows the CheckMate title, status, severity, resource, message, and recommendation when present. Validator IDs and raw evidence stay out of the interactive display.
2. Sends only selected, normalised, redacted fields to OpenAI—not the raw report.
3. Prints short bullets explaining what the finding means and why it matters.
4. Asks up to four finding-specific questions using text, single-select, or keyboard checkbox controls as appropriate.
5. Records `approved`, `rejected`, `deferred`, `accepted_risk`, or `needs_investigation`, with a required rationale.
6. Saves after every decision under `remediation-plans/` as a validated JSON review record.

The OpenAI request uses the Responses API with strict structured output and `store: false`. User answers and decisions remain local in this milestone and are not sent back to OpenAI.

For the `checkManagementAPIUserAccess` finding, the CheckMate JSON does not contain the tenant's application inventory. When a review profile is available, the deterministic application code makes one narrow, read-only `read:clients` lookup and presents the returned application names and client IDs as a checkbox list. Use the arrow keys to move, Space to toggle, and Enter to confirm. Exclusive choices are also available for no approved applications, needs investigation, or remaining unchanged. The inventory and selections are not sent to OpenAI. If a profile cannot be inferred from the report filename, pass `--profile dev` or `--profile prod` explicitly.

Build and link the package to use the final command name:

```sh
npm run build
npm link
checkmate-assistant --help
```

## Verification

```sh
npm run build
npm run lint
npm test
npm run format:check
```

Tests mock child-process execution and the OpenAI provider. They require no Auth0 or OpenAI credentials.

## Report caveats

CheckMate 1.8.1 currently writes a JSON summary containing only red/yellow finding details; green/passed validators are filtered out before serialization. The assistant therefore prints `Passed checks: 0` plus an explicit note that passed validators were not included. It does not infer a total or invent pass results.

The current CheckMate JSON also omits tenant and generation metadata. During `scan`, the selected domain is supplied as summary context. For imported reports, the domain remains “not included in report” unless a supported envelope provides it. A file's modification time is used as the best available report timestamp and should not be mistaken for a scanner-authored timestamp.

A real report from the target tenant is still needed to confirm any tenant/version-specific field variants and to improve affected-resource extraction. Unsupported structures fail with a clear error instead of being guessed.

## Security boundaries

- Scan, review, and YAML submission perform no Auth0 write operations. Only the explicitly confirmed dev execution step can write.
- Production execution is blocked.
- OpenAI is called only by explicit review workflows. The AI cannot invoke CheckMate or Auth0 write APIs; execution is deterministic application code based on accepted plan actions.
- The raw CheckMate report, environment, API key, Auth0 credentials, and Management API tokens are never sent to OpenAI.
- Only selected normalised fields are sent. Sensitive keys, known credential values, bearer values, and JWT-shaped strings are redacted.
- OpenAI responses use a strict schema, short bullet arrays, low verbosity, and no tools.
- Finite AI questions use select controls. The AI may only use standard yes/no/investigation choices; it cannot invent application names.
- Application checkboxes come from a narrow, finding-triggered, read-only Auth0 `read:clients` lookup. There is no generic Management API request function.
- Each stored decision references its CheckMate finding ID and preserves the available CheckMate wording.
- No generic shell command or generic Auth0 Management API function exists.
- The runner invokes only the pinned CheckMate package entry point through the current Node.js runtime, with no user-controlled executable or arguments.
- Secrets are excluded from command arguments, logs, errors, reports, snapshots, and generated files.
- Verbose child output is redacted against the active client secret.
- Sensitive object keys including secret, token, password, API key, and authorization are recursively redacted.
- `.env*`, reports, and remediation plans are ignored, while placeholders remain tracked.

CheckMate itself reads tenant configuration through the Auth0 Management API and consumes tenant rate limits. Use a dedicated least-privilege application and review the official scope list.

## Milestones

1. **Milestone 1 — complete:** safe CheckMate scan, import, normalisation, and finding listing.
2. **Milestone 2 — complete:** redacted OpenAI explanation, interactive questions, and local decision records.
3. **Milestone 3 — complete:** validate and write a YAML API plan from accepted action-level decisions, with an in-browser review.
4. **Milestone 4 — complete for supported actions:** retrieve development configuration, show the planned diff, require confirmation, apply sequential calls, and verify the resulting settings.
5. **Milestone 5 — planned:** rerun the same CheckMate validators, record verification evidence, and test rollback.

Production changes remain outside the current POC. A future MCP server, if added, will expose only narrow operations tied to reports, plans, approved development changes, and verification.
