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
