import type { NormalizedCheckmateFinding } from "../findings/types.js";
import type { ActionableChange } from "../remediation/actionable-change.js";
import { z } from "zod";

export interface ReviewContext {
  answers: Record<string, string>;
}

const conciseBulletSchema = z.string().trim().min(1).max(220);

export const questionOptionSchema = z.object({
  value: z.string().trim().min(1).max(200),
  label: z.string().trim().min(1).max(240),
});

export const aiReviewQuestionSchema = z.object({
  id: z.string().trim().min(1).max(80),
  prompt: conciseBulletSchema,
  inputType: z.enum(["text", "single_select", "multi_select"]),
  options: z.array(questionOptionSchema).max(1_000),
});

export type AiReviewQuestion = z.infer<typeof aiReviewQuestionSchema>;

export const aiFindingAnalysisSchema = z
  .object({
    whatItMeans: z.array(conciseBulletSchema).min(1).max(4),
    whyItMatters: z.array(conciseBulletSchema).min(1).max(4),
    questions: z.array(aiReviewQuestionSchema).max(3),
    remediationConsiderations: z.array(conciseBulletSchema).min(1).max(4),
  })
  .strict();

export type AiFindingAnalysis = z.infer<typeof aiFindingAnalysisSchema>;

export const aiReportTriageItemSchema = z
  .object({
    findingId: z.string().trim().min(1).max(200),
    actionId: z.string().trim().min(1).max(200),
    recommendationTitle: z.string().trim().min(1).max(120),
    whatItMeans: z.array(conciseBulletSchema).min(1).max(3),
    suggestedChanges: z.array(conciseBulletSchema).length(1),
    reason: z.array(conciseBulletSchema).min(1).max(3),
  })
  .strict();

export const aiReportTriageSchema = z
  .object({ selectedFindings: z.array(aiReportTriageItemSchema).max(12) })
  .strict();

export type AiReportTriageItem = z.infer<typeof aiReportTriageItemSchema>;

export interface AiProvider {
  analyseFinding(
    finding: NormalizedCheckmateFinding,
    context: ReviewContext,
  ): Promise<AiFindingAnalysis>;
  answerQuestion?(
    finding: NormalizedCheckmateFinding,
    analysis: AiFindingAnalysis,
    question: string,
  ): Promise<string[]>;
  triageFindings?(
    findings: readonly NormalizedCheckmateFinding[],
    actionableConfiguration?: ReadonlyMap<string, readonly ActionableChange[]>,
  ): Promise<AiReportTriageItem[]>;
}
