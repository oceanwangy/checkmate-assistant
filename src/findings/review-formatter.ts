import type { AiFindingAnalysis } from "../ai/provider.js";
import type { NormalizedCheckmateFinding } from "./types.js";
import { redactText } from "../security/redaction.js";
import { safeTerminalText } from "../utils/terminal.js";

function safe(value: string, sensitiveValues: readonly string[]): string {
  return safeTerminalText(redactText(value, sensitiveValues));
}

function formatResource(
  finding: NormalizedCheckmateFinding,
): string | undefined {
  if (!finding.affectedResource) return undefined;
  const parts = [
    finding.affectedResource.type,
    finding.affectedResource.name,
    finding.affectedResource.id,
  ].filter((part): part is string => Boolean(part));
  return parts.length > 0 ? parts.join(" / ") : undefined;
}

export function formatFindingForReview(
  finding: NormalizedCheckmateFinding,
  position: number,
  total: number,
  sensitiveValues: readonly string[] = [],
): string {
  const lines = [`Finding ${position} of ${total}`, "", "CheckMate report:"];
  lines.push(`- Title: ${safe(finding.title, sensitiveValues)}`);
  lines.push(`- Status: ${finding.status}`);
  if (finding.severity)
    lines.push(`- Severity: ${safe(finding.severity, sensitiveValues)}`);
  const resource = formatResource(finding);
  if (resource) lines.push(`- Resource: ${safe(resource, sensitiveValues)}`);
  if (finding.description)
    lines.push(`- Message: ${safe(finding.description, sensitiveValues)}`);
  if (finding.recommendation) {
    lines.push(
      `- Recommendation: ${safe(finding.recommendation, sensitiveValues)}`,
    );
  }
  return lines.join("\n");
}

function addBullets(
  lines: string[],
  heading: string,
  bullets: readonly string[],
): void {
  lines.push("", heading);
  for (const bullet of bullets) lines.push(`- ${safeTerminalText(bullet)}`);
}

export function formatAiAnalysis(
  analysis: AiFindingAnalysis,
  showExplanation = false,
): string {
  const lines = ["AI review (based only on this CheckMate finding):"];
  if (showExplanation) {
    addBullets(lines, "What it means:", analysis.whatItMeans);
    addBullets(lines, "Why it matters:", analysis.whyItMatters);
  }
  if (analysis.remediationConsiderations.length > 0) {
    addBullets(lines, "Suggested action:", analysis.remediationConsiderations);
  }
  if (analysis.questions.length > 0) {
    addBullets(
      lines,
      "Questions:",
      analysis.questions.map((question) => question.prompt),
    );
  }
  return lines.join("\n");
}
