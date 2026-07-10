import type {
  LoadedCheckmateReport,
  ReportCounts,
  ReportSummary,
} from "./types.js";
import { displayPath } from "../utils/filesystem.js";

export function countFindings(report: LoadedCheckmateReport): ReportCounts {
  return report.findings.reduce<ReportCounts>(
    (counts, finding) => {
      counts[finding.status] += 1;
      return counts;
    },
    { passed: 0, failed: 0, warning: 0, unknown: 0 },
  );
}

export function createReportSummary(
  report: LoadedCheckmateReport,
  tenantOverride?: string,
): ReportSummary {
  const summary: ReportSummary = {
    ...countFindings(report),
    reportPath: report.sourcePath,
    passedChecksIncluded:
      !report.findingsOnly ||
      report.findings.some((item) => item.status === "passed"),
  };
  const tenant = report.tenant ?? tenantOverride;
  if (tenant) summary.tenant = tenant;
  if (report.generatedAt) summary.generatedAt = report.generatedAt;
  return summary;
}

export function formatReportSummary(summary: ReportSummary): string {
  const lines = [
    `Tenant/domain: ${summary.tenant ?? "not included in report"}`,
    `Report timestamp: ${summary.generatedAt ?? "not included in report"}`,
    `Passed checks: ${summary.passed}`,
    `Failed checks: ${summary.failed}`,
    `Warnings: ${summary.warning}`,
  ];
  if (summary.unknown > 0) lines.push(`Unknown status: ${summary.unknown}`);
  if (!summary.passedChecksIncluded) {
    lines.push(
      "Passed-check note: this findings-only report does not include passed validators.",
    );
  }
  lines.push(`JSON report: ${displayPath(summary.reportPath)}`);
  return lines.join("\n");
}
