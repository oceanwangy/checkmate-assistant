import { z } from "zod";
import { AppError } from "../utils/errors.js";

export const DEFAULT_OPENAI_MODEL = "gpt-5.5";
export const DEFAULT_OPENAI_REASONING_EFFORT = "high";

const modelSchema = z
  .string()
  .trim()
  .min(1)
  .regex(/^[a-zA-Z0-9._:-]+$/, "OPENAI_MODEL contains unsupported characters.");
const timeoutSchema = z.coerce.number().int().positive().max(300_000);
const reasoningEffortSchema = z.enum(["low", "medium", "high"]);

export interface AiConfig {
  apiKey: string;
  model: string;
  timeoutMs: number;
  reasoningEffort: z.infer<typeof reasoningEffortSchema>;
}

export function loadAiConfig(env: NodeJS.ProcessEnv = process.env): AiConfig {
  const apiKey = env.OPENAI_API_KEY?.trim();
  if (!apiKey) {
    throw new AppError(
      "MISSING_CONFIGURATION",
      "Missing required environment variable:\nOPENAI_API_KEY",
    );
  }

  const model = modelSchema.safeParse(env.OPENAI_MODEL ?? DEFAULT_OPENAI_MODEL);
  if (!model.success) {
    throw new AppError(
      "MISSING_CONFIGURATION",
      model.error.issues[0]?.message ?? "Invalid OPENAI_MODEL.",
    );
  }

  const timeout = timeoutSchema.safeParse(env.OPENAI_TIMEOUT_MS ?? "180000");
  if (!timeout.success) {
    throw new AppError(
      "MISSING_CONFIGURATION",
      "OPENAI_TIMEOUT_MS must be a positive integer no greater than 300000.",
    );
  }

  const reasoningEffort = reasoningEffortSchema.safeParse(
    env.OPENAI_REASONING_EFFORT ?? DEFAULT_OPENAI_REASONING_EFFORT,
  );
  if (!reasoningEffort.success) {
    throw new AppError(
      "MISSING_CONFIGURATION",
      "OPENAI_REASONING_EFFORT must be low, medium, or high.",
    );
  }

  return {
    apiKey,
    model: model.data,
    timeoutMs: timeout.data,
    reasoningEffort: reasoningEffort.data,
  };
}
