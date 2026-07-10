import { z } from "zod";

export const remediationDecisionStatusSchema = z.enum([
  "approved",
  "rejected",
  "deferred",
  "accepted_risk",
  "needs_investigation",
]);

export type RemediationDecisionStatus = z.infer<
  typeof remediationDecisionStatusSchema
>;

export const remediationEntrySchema = z.object({
  checkmate_finding_id: z.string().min(1),
  checkmate_validator_id: z.string().min(1).optional(),
  decision: z.object({
    status: remediationDecisionStatusSchema,
    rationale: z.string().min(1),
  }),
});

export const remediationPlanSchema = z.object({
  report: z.object({
    tenant: z.string().min(1),
    source_report: z.string().min(1),
    generated_at: z.string().datetime(),
  }),
  remediations: z.array(remediationEntrySchema),
});

export type RemediationPlan = z.infer<typeof remediationPlanSchema>;
