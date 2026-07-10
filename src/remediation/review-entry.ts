import type { AiFindingAnalysis } from "../ai/provider.js";
import type { NormalizedCheckmateFinding } from "../findings/types.js";
import { redactText } from "../security/redaction.js";
import type { RemediationDecisionStatus } from "./plan-schema.js";
import type { ReviewAnswer, ReviewEntry } from "./review-schema.js";
import type { ActionableChange } from "./actionable-change.js";

export function redactAnalysis(
  analysis: AiFindingAnalysis,
  sensitiveValues: readonly string[],
): AiFindingAnalysis {
  const clean = (items: readonly string[]) =>
    items.map((item) => redactText(item, sensitiveValues));
  return {
    whatItMeans: clean(analysis.whatItMeans),
    whyItMatters: clean(analysis.whyItMatters),
    questions: analysis.questions.map((question) => ({
      ...question,
      prompt: redactText(question.prompt, sensitiveValues),
      options: question.options.map((option) => ({
        value: redactText(option.value, sensitiveValues),
        label: redactText(option.label, sensitiveValues),
      })),
    })),
    remediationConsiderations: clean(analysis.remediationConsiderations),
  };
}

export function boundedUserText(
  value: string,
  sensitiveValues: readonly string[],
): string {
  return redactText(value, sensitiveValues).slice(0, 4_000);
}

export function boundedAnswer(
  value: string | string[],
  sensitiveValues: readonly string[],
): string | string[] {
  return Array.isArray(value)
    ? value.map((item) => redactText(item, sensitiveValues).slice(0, 200))
    : boundedUserText(value, sensitiveValues);
}

export function createReviewEntry(
  finding: NormalizedCheckmateFinding,
  analysis: AiFindingAnalysis,
  answers: ReviewAnswer[],
  decision: RemediationDecisionStatus,
  rationale: string,
  decidedAt: string,
  sensitiveValues: readonly string[],
  actionableChanges: readonly ActionableChange[] = [],
): ReviewEntry {
  const entry: ReviewEntry = {
    checkmateFindingId: redactText(finding.id, sensitiveValues),
    checkmateTitle: redactText(finding.title, sensitiveValues),
    checkmateStatus: finding.status,
    analysis,
    answers,
    decision: {
      status: decision,
      rationale: boundedUserText(rationale, sensitiveValues),
      decidedAt,
    },
  };
  if (actionableChanges.length > 0) {
    entry.actionableChanges = [...actionableChanges];
  }
  if (finding.validatorId) {
    entry.checkmateValidatorId = redactText(
      finding.validatorId,
      sensitiveValues,
    );
  }
  if (finding.description) {
    entry.checkmateMessage = redactText(finding.description, sensitiveValues);
  }
  if (finding.recommendation) {
    entry.checkmateRecommendation = redactText(
      finding.recommendation,
      sensitiveValues,
    );
  }
  return entry;
}
