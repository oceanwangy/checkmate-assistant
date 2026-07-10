import type { AiFindingAnalysis, AiReviewQuestion } from "../ai/provider.js";
import type { NormalizedCheckmateFinding } from "../findings/types.js";

const MANAGEMENT_API_USER_ACCESS = "checkManagementAPIUserAccess";

function isApplicationApprovalQuestion(question: AiReviewQuestion): boolean {
  const text = question.prompt.toLowerCase();
  return (
    text.includes("application") &&
    (text.includes("approve") || text.includes("access"))
  );
}

export function planReviewQuestions(
  finding: NormalizedCheckmateFinding,
  analysis: AiFindingAnalysis,
): AiFindingAnalysis {
  if (finding.validatorId !== MANAGEMENT_API_USER_ACCESS) return analysis;
  const remaining = analysis.questions.filter(
    (question) => !isApplicationApprovalQuestion(question),
  );
  return {
    ...analysis,
    questions: remaining.slice(0, 3),
  };
}
