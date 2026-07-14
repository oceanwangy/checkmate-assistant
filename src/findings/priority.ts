import type { NormalizedCheckmateFinding } from "./types.js";

export type FindingPriority = "obvious" | "review" | "app_specific";

const OBVIOUS_HARDENING_PATTERNS = [
  /\bmfa\b/,
  /multi[- ]factor/,
  /network (acl|allowlist|access control)/,
  /ip (allowlist|restriction|filter)/,
  /token (lifetime|expiration|expiry)/,
  /(signing|encryption) algorithm/,
  /\b(alg|hs256|rs256)\b/,
  /cross[- ]origin authentication/,
  /implicit grant/,
  /breached password/,
  /brute[- ]force/,
  /password policy/,
  /management api user access/,
];

const APP_SPECIFIC_PATTERNS = [
  /\bapplication\b/,
  /\bclient\b/,
  /callback url/,
  /logout url/,
  /allowed origin/,
  /grant type/,
];

function searchableText(finding: NormalizedCheckmateFinding): string {
  return [
    finding.validatorId,
    finding.title,
    finding.description,
    finding.recommendation,
    finding.affectedResource?.type,
    finding.affectedResource?.name,
  ]
    .filter((value): value is string => Boolean(value))
    .join(" ")
    .toLowerCase();
}

export function classifyFindingPriority(
  finding: NormalizedCheckmateFinding,
): FindingPriority {
  const text = searchableText(finding);
  if (OBVIOUS_HARDENING_PATTERNS.some((pattern) => pattern.test(text))) {
    return "obvious";
  }
  if (APP_SPECIFIC_PATTERNS.some((pattern) => pattern.test(text))) {
    return "app_specific";
  }
  return "review";
}

function severityScore(severity: string | undefined): number {
  switch (severity?.toLowerCase()) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}

const priorityScore: Record<FindingPriority, number> = {
  obvious: 3,
  review: 2,
  app_specific: 1,
};

export function prioritizeFindings(
  findings: readonly NormalizedCheckmateFinding[],
): NormalizedCheckmateFinding[] {
  return findings
    .map((finding, index) => ({ finding, index }))
    .sort((left, right) => {
      const priorityDifference =
        priorityScore[classifyFindingPriority(right.finding)] -
        priorityScore[classifyFindingPriority(left.finding)];
      if (priorityDifference !== 0) return priorityDifference;
      const severityDifference =
        severityScore(right.finding.severity) -
        severityScore(left.finding.severity);
      return severityDifference || left.index - right.index;
    })
    .map(({ finding }) => finding);
}
