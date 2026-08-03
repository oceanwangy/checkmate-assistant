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
    └── Executable Auth0 Terraform configuration
             ↓
Terraform validation and API preflight gates
             ↓
Explicit dev API execution and verification
```

CheckMate reports are the primary and only source of security findings. The assistant does not independently scan a tenant. Parsing, validation, filtering, child-process execution, and future change application remain deterministic application responsibilities.

The AI interprets live-verified CheckMate findings and recommends supported changes. It does not generate Terraform or API requests directly. Deterministic mappings create both artifacts, and independent Terraform and Management API validators must approve them before the package is released.

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
- An OpenAI API key and separately configured API billing for remediation review

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

Select `Run CheckMate scan`. Every UI session starts with a new scan; it does not reuse an older report. The UI runs the bundled CheckMate dependency with the selected profile, saves a new JSON file under `reports/`, and automatically begins guidance after the report is ready. Use the separate CLI `review` command when intentionally reviewing an existing report.

Before starting an assessment, the administrator must confirm that the development tenant mirrors production's security-relevant Auth0 configuration. Environment-specific tenant domains, resource IDs, credentials, users, logs, and customer data remain separate. This configuration baseline is required so that development validation is representative without copying production identities, secrets, or data.

You can add an admin note explaining a decision, then choose `Accept AI suggestion` or `Remain unchanged` for every recommendation. Notes are optional and are stored in the local JSON audit record when provided. After all decisions are saved, select `Submit`. Both `dev` and `prod` profiles must be configured. The assistant reads each tenant independently and creates this package next to the JSON review record:

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

Each API plan uses that environment's real Auth0 resource IDs and current values. Settings already compliant in one environment are recorded and omitted from its calls. The YAML groups accepted settings into minimal Auth0 `PATCH` calls, records expected current values for drift checks, and excludes unchanged items. It stores only the selected, secret-free patch fields plus the safe live-merge strategy. Package preflight calculates and stores a SHA-256 digest of each exact live-merged request; validation and execution rebuild that request and stop if the digest changes.

Every finalized YAML call also contains an executable Bash `curl` script, and the package writes those calls into a directly downloadable `apply-api-plan.sh` companion. Each call runs in an isolated subshell so an already-compliant call cannot skip later calls. Development scripts read `AUTH0CHECKMATE_DEV_DOMAIN`, `AUTH0CHECKMATE_DEV_CLIENT_ID`, and `AUTH0CHECKMATE_DEV_CLIENT_SECRET`; production scripts use the matching `AUTH0CHECKMATE_PROD_*` variables. Credentials and access tokens are never written into either artifact. The script uses the existing Node.js runtime to reproduce the application's live merge, drift check, request digest, PATCH, and post-change verification, so it does not require `jq`.

Generated curl scripts use private temporary files for the OAuth request and authorization header, remove credential variables as soon as the token is obtained, and delete temporary material on exit. Secrets and bearer tokens are not placed in curl process arguments. Token and read requests use bounded transient retries; PATCH requests are never retried blindly. Post-PATCH verification checks both the selected target fields and the preservation of unselected live fields.

The Terraform files are genuine deployment configurations built with the official `auth0/auth0` provider. They declare managed resources for supported application, database-connection, and attack-protection changes. Terraform 1.5 import blocks adopt each existing resource into the selected state before updating it, `prevent_destroy` blocks accidental deletion, and targeted `ignore_changes` entries preserve every unrelated imported setting. Connection resources explicitly protect unselected nested options because the Auth0 provider warns that omitted connection options can otherwise be removed.

Every accepted automatic recommendation must have both a safe official-provider Terraform mapping and a validated Management API mapping. Package creation refuses partial coverage. The Auth0 Management API itself is a system resource server, and the official provider documents system resource servers as non-modifiable, so its application-access policy remains an additional manual recommendation and cannot enter the automatic dual-format package.

For application-level CheckMate findings, the assistant reads the matching live Auth0 client before making a recommendation. Three deterministic recommendations are grouped by setting: set JWT signing to RS256, disable cross-origin authentication, and remove only the `implicit` grant type. Each group displays application checkboxes so the administrator can approve individual applications while preserving every other environment-specific setting.

The review modal shows both environments, all three output files, every exact change, Terraform coverage, and the validation result. Each `api-plan.yml`, `apply-api-plan.sh`, and `main.tf` can be opened in a readable popup or downloaded directly. Terraform validation formats the file, runs `terraform init -upgrade -backend=false`, validates it against the pinned Auth0 provider schema, and creates a credentialed, read-only Terraform plan against the matching tenant. The machine-readable plan is rejected if it contains a destroy, replacement, unexpected resource type, or unimported create. Exit code `2` is accepted as the expected result when the plan contains safe changes. The development API preflight obtains the required read/update scopes. The production API preflight requests read scopes only. Both re-read every target resource, synthesize and structurally check the final PATCH body, check all drift preconditions, and stamp every call with its exact request digest without making a `PATCH` request.

During submission, the application also obtains a production Management API token without requesting a narrowed scope and inspects the granted scope list. Detected production create, update, or delete scopes produce a visible warning but do not stop package generation. If Auth0 does not expose the granted scopes, the UI records that access could not be verified. Local production credentials should remain read-only; the formal production deployment process supplies its own protected write identity.

The generated provider block contains no credentials. When using a downloaded package manually, provide `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, and `AUTH0_CLIENT_SECRET`, select an appropriate Terraform backend, review `terraform plan`, and apply the development package first. Promote the separately generated production package through the normal production change-management process.

Read-only Auth0 configuration, API-plan preflight, verification, and credential-inspection calls automatically retry up to five times when Auth0 returns HTTP 429. The retry uses `Retry-After` or `X-RateLimit-Reset` when available and otherwise uses bounded exponential backoff with jitter. Requests for one environment are sequenced, and dev/prod validation is also sequenced when both profiles temporarily point to the same tenant, avoiding avoidable global-rate-limit collisions. A rate-limited PATCH is not retried blindly: execution waits, re-reads the resource, accepts success if the target is present, and otherwise retries only while the original preconditions and exact request digest still match. The generated `apply-api-plan.sh` uses the same controlled recovery.

The saved development `api-plan.yml` is the canonical execution artifact. The application records the complete file's SHA-256 digest at submission, reads and parses it again immediately before execution, and stops if that file changed after review. It separately compares each rebuilt PATCH request with the request digest stamped during package creation, so live nested configuration drift also stops execution. The execution audit record stores the file digest.

The modal provides `Execute changes` only when both development validations pass and requires explicit confirmation. The saved artifact hash is checked before execution. Execution then performs its own live precondition and exact-request validation while re-reading every resource, stops on unexpected drift, merges changes into complete live connection options where Auth0 requires full replacement, sends sequential PATCH requests with correlation IDs, and re-reads each resource to verify selected and preserved fields. This avoids duplicating the package API and Terraform preflights immediately before an API-only execution. If execution stops, already applied calls are verified and skipped when the administrator resumes. Applied calls can also be rolled back in reverse order to their reviewed original values, with drift checks and post-rollback verification. Every apply, resume, and rollback attempt is appended to the JSON audit record. Production execution is blocked; its artifacts are for the formal production change process.

Compatibility-sensitive recommendations are intentionally unselected when first displayed. This includes RS256 migration, passkey enablement, callback removal, and Implicit grant removal. The administrator must select the affected applications, connections, or URLs after confirming compatibility. Cross-origin authentication remains selected by default under the current deterministic policy.

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

CheckMate 1.8.3 writes a JSON summary containing validators with red or yellow detail outcomes. A validator's parent colour is its priority: red is high, yellow is moderate, green is low, blue is informational, and violet is a GenAI insight. The posture model compares the summary with the version-locked 1.8.3 registry: its 36 red/yellow/green validators provide 118 available points, and scorable validators absent from a complete report are counted as passed.

The current CheckMate JSON also omits tenant and generation metadata. During `scan`, the selected domain is supplied as summary context. For imported reports, the domain remains “not included in report” unless a supported envelope provides it. A file's modification time is used as the best available report timestamp and should not be mistaken for a scanner-authored timestamp.

A real report from the target tenant is still needed to confirm any tenant/version-specific field variants and to improve affected-resource extraction. Unsupported structures fail with a clear error instead of being guessed.

## Security boundaries

- Scan, review, package generation, Terraform validation, and API preflight perform no Auth0 write operations. Only the explicitly confirmed dev API execution step can write.
- Production execution is blocked.
- OpenAI is called only by the explicit remediation-review workflow and cannot invoke CheckMate execution or Auth0 write APIs.
- The raw CheckMate report, environment, API key, Auth0 credentials, and Management API tokens are never sent to OpenAI.
- Only selected normalised fields are sent. Sensitive keys, known credential values, bearer values, and JWT-shaped strings are redacted.
- OpenAI responses use a strict schema, short bullet arrays, and low verbosity. The remediation review uses no model tools.
- Finite AI questions use select controls. The AI may only use standard yes/no/investigation choices; it cannot invent application names.
- Automatic choices come from narrow, finding-triggered Auth0 reads for supported applications, database connections, and attack-protection settings. System Management API policy findings remain manual because they cannot satisfy the dual-format requirement.
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
3. **Milestone 3 — complete:** generate environment-specific executable YAML API plans and official-provider Terraform configurations from accepted action-level decisions, with an in-browser review.
4. **Milestone 4 — complete for supported actions:** validate Terraform and preflight-check API plans for both environments; require explicit confirmation, live drift checks, exact-request verification, and sequential API execution.
5. **Milestone 5 — planned:** rerun the same CheckMate validators, record verification evidence, and test rollback.

Production changes remain outside the current POC.
