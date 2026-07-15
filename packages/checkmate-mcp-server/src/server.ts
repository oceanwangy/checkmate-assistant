import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { FindingStatus } from "@checkmate-assistant/core";
import {
  findApplicationFindings,
  findTopicFindings,
  searchFindings,
  SECURITY_TOPICS,
  toFindingView,
  type SecurityTopic,
} from "./query.js";
import {
  ReportRepository,
  type ReportRepositoryOptions,
} from "./report-repository.js";

const findingStatusSchema = z.enum(["passed", "failed", "warning", "unknown"]);
const securityTopicSchema = z.enum([
  "credential_stuffing",
  "application_hardening",
  "mfa",
  "network_access",
  "password_security",
  "token_security",
]);

type JsonObject = Record<string, unknown>;

function success(output: JsonObject) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(output, null, 2) }],
    structuredContent: output,
  };
}

function failure(error: unknown) {
  const message = error instanceof Error ? error.message : "Unknown error.";
  return {
    content: [{ type: "text" as const, text: `Error: ${message}` }],
    isError: true,
  };
}

async function safely(operation: () => Promise<JsonObject>) {
  try {
    return success(await operation());
  } catch (error) {
    return failure(error);
  }
}

function reportCaveats(metadata: {
  reportId: string;
  findingsOnly: boolean;
  stale: boolean;
  freshnessWarning?: string;
}): string[] {
  const caveats: string[] = [];
  if (metadata.findingsOnly) {
    caveats.push(
      "This is a findings-only report. An absent finding does not prove that a control passed.",
    );
  }
  if (metadata.stale && metadata.freshnessWarning) {
    caveats.push(metadata.freshnessWarning);
  }
  caveats.push(
    `Ground conclusions in report ${metadata.reportId} and cite findingId values.`,
  );
  return caveats;
}

export type CheckmateMcpServerOptions = ReportRepositoryOptions;

export function createCheckmateMcpServer(
  options: CheckmateMcpServerOptions,
): McpServer {
  const repository = new ReportRepository(options);
  const server = new McpServer(
    { name: "checkmate-mcp-server", version: "0.1.0" },
    {
      instructions: [
        "Use CheckMate report data as posture evidence, not as proof that a security incident occurred.",
        "Prefer the newest valid report unless the user names another report.",
        "Cite reportId and findingId values in substantive answers.",
        "State when a report is stale or findings-only, and identify live configuration or logs needed to close evidence gaps.",
        "This server is read-only. It does not make Auth0 tenant changes and does not call an AI model.",
      ].join(" "),
    },
  );

  server.registerTool(
    "checkmate_list_reports",
    {
      title: "List CheckMate reports",
      description:
        "List available CheckMate JSON reports, newest first. Use this before selecting a historical report. Invalid files are reported but never loaded as evidence.",
      inputSchema: {},
    },
    () =>
      safely(async () => {
        const reports = await repository.listReports();
        return {
          reports,
          newestValidReportId: reports.find((report) => report.valid)?.reportId,
        };
      }),
  );

  server.registerTool(
    "checkmate_get_report_summary",
    {
      title: "Get CheckMate report summary",
      description:
        "Get status counts, provenance, freshness, and coverage caveats for a CheckMate report. Omit reportId to use the newest valid report.",
      inputSchema: {
        reportId: z.string().max(255).optional(),
      },
    },
    ({ reportId }) =>
      safely(async () => {
        const context = await repository.getReport(reportId);
        return {
          report: context.metadata,
          caveats: reportCaveats(context.metadata),
        };
      }),
  );

  server.registerTool(
    "checkmate_search_findings",
    {
      title: "Search CheckMate findings",
      description:
        "Search normalized CheckMate findings by words, status, severity, or affected resource. The default status filter returns failed, warning, and unknown findings. Omit reportId to use the newest valid report.",
      inputSchema: {
        reportId: z.string().max(255).optional(),
        query: z.string().max(500).optional(),
        statuses: z.array(findingStatusSchema).max(4).optional(),
        severities: z.array(z.string().max(40)).max(10).optional(),
        resource: z.string().max(300).optional(),
        limit: z.number().int().min(1).max(50).optional(),
      },
    },
    ({ reportId, query, statuses, severities, resource, limit }) =>
      safely(async () => {
        const context = await repository.getReport(reportId);
        const searchOptions: {
          query?: string;
          statuses?: FindingStatus[];
          severities?: string[];
          resource?: string;
          limit?: number;
        } = {};
        if (query !== undefined) searchOptions.query = query;
        if (statuses !== undefined) searchOptions.statuses = statuses;
        if (severities !== undefined) searchOptions.severities = severities;
        if (resource !== undefined) searchOptions.resource = resource;
        if (limit !== undefined) searchOptions.limit = limit;
        const findings = searchFindings(context.report.findings, searchOptions);
        return {
          report: context.metadata,
          resultCount: findings.length,
          findings,
          caveats: reportCaveats(context.metadata),
        };
      }),
  );

  server.registerTool(
    "checkmate_get_finding",
    {
      title: "Get a CheckMate finding",
      description:
        "Get one normalized CheckMate finding with redacted evidence. Use a findingId returned by another CheckMate tool.",
      inputSchema: {
        reportId: z.string().max(255).optional(),
        findingId: z.string().min(1).max(200),
      },
    },
    ({ reportId, findingId }) =>
      safely(async () => {
        const context = await repository.getReport(reportId);
        const finding = context.report.findings.find(
          (candidate) => candidate.id === findingId,
        );
        if (!finding) {
          throw new Error(
            `Finding "${findingId}" does not exist in report ${context.metadata.reportId}.`,
          );
        }
        return {
          report: context.metadata,
          finding: toFindingView(finding, true),
          caveats: reportCaveats(context.metadata),
        };
      }),
  );

  server.registerTool(
    "checkmate_get_application_posture",
    {
      title: "Get application posture",
      description:
        "Find all CheckMate results associated with an application name or client ID. This only reports what the selected report contains; it does not read live Auth0 configuration.",
      inputSchema: {
        reportId: z.string().max(255).optional(),
        application: z.string().min(1).max(300),
      },
    },
    ({ reportId, application }) =>
      safely(async () => {
        const context = await repository.getReport(reportId);
        const findings = findApplicationFindings(
          context.report.findings,
          application,
        );
        return {
          report: context.metadata,
          applicationQuery: application,
          resultCount: findings.length,
          findings,
          interpretation:
            findings.length === 0
              ? "No matching application findings were present. This does not prove the application is secure or that it exists in the tenant."
              : "Use failed and warning findings as report-grounded hardening opportunities. Confirm live configuration and business requirements before changing the application.",
          caveats: reportCaveats(context.metadata),
        };
      }),
  );

  server.registerTool(
    "checkmate_get_security_topic_context",
    {
      title: "Get security-topic context",
      description:
        "Collect CheckMate findings relevant to a supported security question, such as credential stuffing, MFA, application hardening, network access, password security, or token security.",
      inputSchema: {
        reportId: z.string().max(255).optional(),
        topic: securityTopicSchema,
      },
    },
    ({ reportId, topic }) =>
      safely(async () => {
        const context = await repository.getReport(reportId);
        const typedTopic = topic as SecurityTopic;
        const definition = SECURITY_TOPICS[typedTopic];
        const findings = findTopicFindings(context.report.findings, typedTopic);
        return {
          report: context.metadata,
          topic: typedTopic,
          title: definition.title,
          purpose: definition.purpose,
          resultCount: findings.length,
          findings,
          additionalEvidenceNeeded: definition.additionalEvidenceNeeded,
          responseGuidance: [
            "Lead with failed and warning findings that directly support actionable suggestions.",
            "Separate report-grounded facts from general security guidance.",
            "Do not claim the report proves an attack occurred or identifies its source.",
            "Ask for live logs or configuration when required evidence is missing.",
          ],
          caveats: reportCaveats(context.metadata),
        };
      }),
  );

  server.registerResource(
    "latest-checkmate-summary",
    "checkmate://reports/latest/summary",
    {
      title: "Latest CheckMate report summary",
      description:
        "Summary and provenance for the newest valid report in the configured reports directory.",
      mimeType: "application/json",
    },
    async (uri) => {
      const context = await repository.getReport();
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: "application/json",
            text: JSON.stringify(
              {
                report: context.metadata,
                caveats: reportCaveats(context.metadata),
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  server.registerPrompt(
    "investigate-security-question",
    {
      title: "Investigate a security question",
      description:
        "Answer a security question using CheckMate posture evidence and clearly identified evidence gaps.",
      argsSchema: {
        question: z.string().min(1).max(2000),
        reportId: z.string().max(255).optional(),
      },
    },
    ({ question, reportId }) => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: [
              `Question: ${question}`,
              `Report selection: ${reportId ?? "newest valid CheckMate report"}.`,
              "Use checkmate_get_security_topic_context and checkmate_search_findings to gather evidence.",
              "Cite the reportId and findingId for every report-grounded conclusion.",
              "Give short, actionable suggestions. Separate CheckMate evidence from general advice.",
              "State what live Auth0 configuration, logs, or business context is still needed.",
              "Do not claim that a CheckMate report proves a security incident occurred.",
            ].join("\n"),
          },
        },
      ],
    }),
  );

  server.registerPrompt(
    "harden-application",
    {
      title: "Harden an Auth0 application",
      description:
        "Review CheckMate findings for one application and propose grounded hardening priorities.",
      argsSchema: {
        application: z.string().min(1).max(300),
        reportId: z.string().max(255).optional(),
      },
    },
    ({ application, reportId }) => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: [
              `Review the security posture of Auth0 application: ${application}.`,
              `Report selection: ${reportId ?? "newest valid CheckMate report"}.`,
              "Call checkmate_get_application_posture first.",
              "Prioritize failed or warning results and cite reportId and findingId values.",
              "Do not treat missing findings as passed controls, especially for findings-only reports.",
              "Separate obvious hardening from changes that require business requirements or live configuration.",
            ].join("\n"),
          },
        },
      ],
    }),
  );

  return server;
}
