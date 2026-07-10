import { z } from "zod";
import { aiFindingAnalysisSchema } from "../ai/provider.js";
import { remediationDecisionStatusSchema } from "./plan-schema.js";
import { actionableChangeSchema } from "./actionable-change.js";

export const reviewAnswerSchema = z.object({
  questionId: z.string().min(1).max(80),
  prompt: z.string().min(1).max(220),
  inputType: z.enum(["text", "single_select", "multi_select"]),
  answer: z.union([
    z.string().max(4_000),
    z.array(z.string().max(200)).max(1_000),
  ]),
});

export const reviewEntrySchema = z.object({
  checkmateFindingId: z.string().min(1),
  actionableChangeId: z.string().min(1).optional(),
  checkmateValidatorId: z.string().min(1).optional(),
  checkmateTitle: z.string().min(1),
  checkmateStatus: z.enum(["passed", "failed", "warning", "unknown"]),
  checkmateMessage: z.string().optional(),
  checkmateRecommendation: z.string().optional(),
  analysis: aiFindingAnalysisSchema,
  answers: z.array(reviewAnswerSchema),
  actionableChanges: z.array(actionableChangeSchema).optional(),
  decision: z.object({
    status: remediationDecisionStatusSchema,
    rationale: z.string().min(1).max(4_000),
    decidedAt: z.string().datetime(),
  }),
});

const executionCallSchema = z.object({
  id: z.string().min(1),
  endpoint: z.string().startsWith("/api/v2/"),
  status: z.enum(["applied", "already_applied", "failed"]),
  correlationId: z.string().min(1).max(64),
  error: z.string().min(1).optional(),
});

export const reviewSessionSchema = z.object({
  schemaVersion: z.literal(1),
  report: z.object({
    sourceReport: z.string().min(1),
    tenant: z.string().min(1).optional(),
    reportTimestamp: z.string().optional(),
  }),
  review: z.object({
    model: z.string().min(1),
    startedAt: z.string().datetime(),
    lastUpdatedAt: z.string().datetime(),
    completedAt: z.string().datetime().optional(),
  }),
  decisions: z.array(reviewEntrySchema),
  execution: z
    .object({
      planFile: z.string().min(1),
      status: z.enum(["succeeded", "failed"]),
      startedAt: z.string().datetime(),
      completedAt: z.string().datetime(),
      profile: z.literal("dev"),
      calls: z.array(executionCallSchema),
      error: z.string().min(1).optional(),
    })
    .optional(),
});

export type ReviewAnswer = z.infer<typeof reviewAnswerSchema>;
export type ReviewEntry = z.infer<typeof reviewEntrySchema>;
export type ReviewSession = z.infer<typeof reviewSessionSchema>;
