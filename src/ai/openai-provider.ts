import OpenAI from "openai";
import { zodTextFormat } from "openai/helpers/zod";
import { z } from "zod";
import {
  aiFindingAnalysisSchema,
  type AiFindingAnalysis,
  type AiProvider,
  type AiReportTriageItem,
  aiReportTriageSchema,
} from "./provider.js";
import {
  buildAiFindingPayload,
  type AiFindingPayload,
} from "./finding-payload.js";
import type { NormalizedCheckmateFinding } from "../findings/types.js";
import type { ActionableChange } from "../remediation/actionable-change.js";
import {
  buildActionCandidates,
  type ActionCandidate,
} from "../remediation/action-candidates.js";
import { ACTIVE_REPORT_GUIDANCE_PROMPT } from "./report-guidance-prompts.js";
import { AppError } from "../utils/errors.js";
import { redactText } from "../security/redaction.js";

export const FINDING_ANALYSIS_INSTRUCTIONS = `
You explain one Auth0 CheckMate finding at a time.

Rules:
- Treat the supplied CheckMate JSON as the only source of tenant findings.
- Do not scan for, introduce, or recommend unrelated findings.
- Use the title, validator, resource, message, evidence, and recommendation wording from the JSON.
- Explain technical meaning in plain English without changing the reported facts.
- Do not claim tenant details that are absent from the JSON.
- Use short sentences. Each array item is one concise bullet. Do not include Markdown bullet markers.
- Act as a security triage assistant, not a configuration interviewer.
- Put the clearest useful action first in remediationConsiderations.
- For obvious hardening findings, give a direct recommendation. Examples include enforcing MFA, applying a network allowlist, shortening an excessive token lifetime, or replacing a weak algorithm.
- Use an exact secure target from CheckMate when one is supplied.
- When the report gives an unsafe value but no target, suggest a conservative baseline and clearly call it a proposed baseline that needs compatibility validation.
- Do not ask review questions. The reviewer will only accept the suggestion or leave the setting unchanged.
- Use single_select for yes/no, status, or other finite questions.
- Use multi_select only when the supplied JSON contains the exact selectable items.
- Use text only when a concise free-form answer is genuinely required.
- Never request an application-by-application inventory.
- Discuss an individual application only when the finding identifies that exact application and reports a clear misconfiguration.
- Never ask the user to type a list of applications, APIs, clients, or resources.
- Selection options must use only: Yes, No, Not applicable, or Needs investigation.
- Base remediation considerations on CheckMate's recommendation, current value, and evidence.
- If the JSON has no recommendation, suggest investigation rather than inventing a configuration change.
- Never request or reproduce credentials, secrets, tokens, passwords, or API keys.
`.trim();

export interface AnalysisRequest {
  model: string;
  finding: AiFindingPayload;
}

export type AnalysisRequester = (request: AnalysisRequest) => Promise<unknown>;

export interface FollowUpRequest extends AnalysisRequest {
  analysis: AiFindingAnalysis;
  question: string;
}

export type FollowUpRequester = (request: FollowUpRequest) => Promise<unknown>;

export interface ReportTriageRequest {
  model: string;
  findings: AiFindingPayload[];
  actionableConfiguration: ActionCandidate[];
}

export type ReportTriageRequester = (
  request: ReportTriageRequest,
) => Promise<unknown>;

export const REPORT_TRIAGE_INSTRUCTIONS = ACTIVE_REPORT_GUIDANCE_PROMPT;

const followUpAnswerSchema = z
  .object({ answer: z.array(z.string().trim().min(1).max(220)).min(1).max(4) })
  .strict();

const FOLLOW_UP_INSTRUCTIONS = `
Answer one follow-up question about one Auth0 CheckMate finding.

Rules:
- Use only the supplied finding and analysis for tenant-specific facts.
- If the answer is not present, say what must be checked. Do not guess.
- Explain how the answer affects the suggested action when relevant.
- Use short sentences. Return one to four concise bullets.
- Do not request or reproduce credentials, secrets, tokens, passwords, or API keys.
- Do not produce an application-by-application inventory.
`.trim();

const STANDARD_AI_OPTIONS = [
  { value: "yes", label: "Yes" },
  { value: "no", label: "No" },
  { value: "not_applicable", label: "Not applicable" },
  { value: "needs_investigation", label: "Needs investigation" },
] as const;
const ALLOWED_AI_OPTION_VALUES: ReadonlySet<string> = new Set(
  STANDARD_AI_OPTIONS.map((option) => option.value),
);

function normalizeAiQuestion(
  question: AiFindingAnalysis["questions"][number],
): AiFindingAnalysis["questions"][number] {
  if (question.inputType === "text") return { ...question, options: [] };

  const groundedOptions = question.options.filter((option) =>
    ALLOWED_AI_OPTION_VALUES.has(option.value),
  );
  return {
    ...question,
    inputType: "single_select",
    options:
      groundedOptions.length >= 2
        ? groundedOptions
        : STANDARD_AI_OPTIONS.map((option) => ({ ...option })),
  };
}

interface OpenAiProviderOptions {
  apiKey: string;
  model: string;
  timeoutMs: number;
  sensitiveValues?: readonly string[];
  requester?: AnalysisRequester;
  followUpRequester?: FollowUpRequester;
  triageRequester?: ReportTriageRequester;
  reasoningEffort?: "low" | "medium" | "high";
  triageInstructions?: string;
}

function createRequester(options: OpenAiProviderOptions): AnalysisRequester {
  const client = new OpenAI({
    apiKey: options.apiKey,
    timeout: options.timeoutMs,
    maxRetries: 2,
  });
  return async ({ model, finding }) => {
    const response = await client.responses.parse({
      model,
      instructions: FINDING_ANALYSIS_INSTRUCTIONS,
      input: JSON.stringify({ checkmateFinding: finding }),
      reasoning: { effort: options.reasoningEffort ?? "high" },
      text: {
        format: zodTextFormat(
          aiFindingAnalysisSchema,
          "checkmate_finding_analysis",
        ),
        verbosity: "low",
      },
      max_output_tokens: 4_000,
      store: false,
    });
    return response.output_parsed;
  };
}

function createFollowUpRequester(
  options: OpenAiProviderOptions,
): FollowUpRequester {
  const client = new OpenAI({
    apiKey: options.apiKey,
    timeout: options.timeoutMs,
    maxRetries: 2,
  });
  return async ({ model, finding, analysis, question }) => {
    const response = await client.responses.parse({
      model,
      instructions: FOLLOW_UP_INSTRUCTIONS,
      input: JSON.stringify({ checkmateFinding: finding, analysis, question }),
      reasoning: { effort: options.reasoningEffort ?? "high" },
      text: {
        format: zodTextFormat(
          followUpAnswerSchema,
          "checkmate_follow_up_answer",
        ),
        verbosity: "low",
      },
      max_output_tokens: 2_000,
      store: false,
    });
    return response.output_parsed;
  };
}

function createTriageRequester(
  options: OpenAiProviderOptions,
): ReportTriageRequester {
  const client = new OpenAI({
    apiKey: options.apiKey,
    timeout: options.timeoutMs,
    maxRetries: 2,
  });
  return async ({ model, findings, actionableConfiguration }) => {
    const response = await client.responses.parse({
      model,
      instructions: options.triageInstructions ?? REPORT_TRIAGE_INSTRUCTIONS,
      input: JSON.stringify({
        checkmateFindings: findings,
        actionableConfiguration,
      }),
      reasoning: { effort: options.reasoningEffort ?? "high" },
      text: {
        format: zodTextFormat(aiReportTriageSchema, "checkmate_report_triage"),
        verbosity: "low",
      },
      max_output_tokens: 12_000,
      store: false,
    });
    return response.output_parsed;
  };
}

export class OpenAiProvider implements AiProvider {
  private readonly model: string;
  private readonly sensitiveValues: readonly string[];
  private readonly requester: AnalysisRequester;
  private readonly followUpRequester: FollowUpRequester;
  private readonly triageRequester: ReportTriageRequester;

  constructor(options: OpenAiProviderOptions) {
    this.model = options.model;
    this.sensitiveValues = options.sensitiveValues ?? [];
    this.requester = options.requester ?? createRequester(options);
    this.followUpRequester =
      options.followUpRequester ?? createFollowUpRequester(options);
    this.triageRequester =
      options.triageRequester ?? createTriageRequester(options);
  }

  async analyseFinding(
    finding: NormalizedCheckmateFinding,
  ): Promise<AiFindingAnalysis> {
    const payload = buildAiFindingPayload(finding, this.sensitiveValues);
    let output: unknown;
    try {
      output = await this.requester({ model: this.model, finding: payload });
    } catch (error) {
      throw new AppError(
        "AI_REQUEST_FAILED",
        "OpenAI could not analyse the CheckMate finding. Check API access, billing, model availability, and network connectivity.",
        { cause: error },
      );
    }

    const parsed = aiFindingAnalysisSchema.safeParse(output);
    if (!parsed.success) {
      throw new AppError(
        "AI_RESPONSE_INVALID",
        "OpenAI returned an invalid finding analysis. No decision was recorded for this finding.",
        { cause: parsed.error },
      );
    }
    const questions = parsed.data.questions.map(normalizeAiQuestion);
    return {
      whatItMeans: parsed.data.whatItMeans.map((item) =>
        redactText(item, this.sensitiveValues),
      ),
      whyItMatters: parsed.data.whyItMatters.map((item) =>
        redactText(item, this.sensitiveValues),
      ),
      questions: questions.map((question) => ({
        ...question,
        prompt: redactText(question.prompt, this.sensitiveValues),
        options: question.options.map((option) => ({
          value: redactText(option.value, this.sensitiveValues),
          label: redactText(option.label, this.sensitiveValues),
        })),
      })),
      remediationConsiderations: parsed.data.remediationConsiderations.map(
        (item) => redactText(item, this.sensitiveValues),
      ),
    };
  }

  async answerQuestion(
    finding: NormalizedCheckmateFinding,
    analysis: AiFindingAnalysis,
    question: string,
  ): Promise<string[]> {
    const payload = buildAiFindingPayload(finding, this.sensitiveValues);
    let output: unknown;
    try {
      output = await this.followUpRequester({
        model: this.model,
        finding: payload,
        analysis: redactAnalysisForFollowUp(analysis, this.sensitiveValues),
        question: redactText(question, this.sensitiveValues).slice(0, 1_000),
      });
    } catch (error) {
      throw new AppError(
        "AI_REQUEST_FAILED",
        "OpenAI could not answer the follow-up question.",
        { cause: error },
      );
    }
    const parsed = followUpAnswerSchema.safeParse(output);
    if (!parsed.success) {
      throw new AppError(
        "AI_RESPONSE_INVALID",
        "OpenAI returned an invalid follow-up answer.",
        { cause: parsed.error },
      );
    }
    return parsed.data.answer.map((item) =>
      redactText(item, this.sensitiveValues),
    );
  }

  async triageFindings(
    findings: readonly NormalizedCheckmateFinding[],
    actionableConfiguration: ReadonlyMap<
      string,
      readonly ActionableChange[]
    > = new Map(),
  ): Promise<AiReportTriageItem[]> {
    const payloads = findings.map((finding) =>
      buildAiFindingPayload(finding, this.sensitiveValues),
    );
    const actionCandidates = buildActionCandidates(actionableConfiguration);
    let output: unknown;
    try {
      output = await this.triageRequester({
        model: this.model,
        findings: payloads,
        actionableConfiguration: actionCandidates,
      });
    } catch (error) {
      throw new AppError(
        "AI_REQUEST_FAILED",
        "OpenAI could not triage the CheckMate report.",
        { cause: error },
      );
    }
    const parsed = aiReportTriageSchema.safeParse(output);
    if (!parsed.success) {
      throw new AppError(
        "AI_RESPONSE_INVALID",
        "OpenAI returned an invalid report triage.",
        { cause: parsed.error },
      );
    }
    const validActions = new Map(
      actionCandidates.map((candidate) => [candidate.actionId, candidate]),
    );
    const validIds = new Set(payloads.map((finding) => finding.id));
    const seen = new Set<string>();
    return parsed.data.selectedFindings
      .filter((item) => {
        const action = validActions.get(item.actionId);
        if (
          !validIds.has(item.findingId) ||
          (actionCandidates.length > 0 &&
            (!action || action.findingId !== item.findingId)) ||
          seen.has(item.actionId)
        ) {
          return false;
        }
        seen.add(item.actionId);
        return true;
      })
      .map((item) => {
        return {
          findingId: item.findingId,
          actionId: item.actionId,
          recommendationTitle: redactText(
            item.recommendationTitle,
            this.sensitiveValues,
          ),
          whatItMeans: item.whatItMeans.map((text) =>
            redactText(text, this.sensitiveValues),
          ),
          suggestedChanges: item.suggestedChanges.map((text) =>
            redactText(text, this.sensitiveValues),
          ),
          reason: item.reason.map((text) =>
            redactText(text, this.sensitiveValues),
          ),
        };
      });
  }
}

function redactAnalysisForFollowUp(
  analysis: AiFindingAnalysis,
  sensitiveValues: readonly string[],
): AiFindingAnalysis {
  const redactItems = (items: readonly string[]) =>
    items.map((item) => redactText(item, sensitiveValues));
  return {
    whatItMeans: redactItems(analysis.whatItMeans),
    whyItMatters: redactItems(analysis.whyItMatters),
    questions: analysis.questions.map((question) => ({
      ...question,
      prompt: redactText(question.prompt, sensitiveValues),
      options: question.options.map((option) => ({
        value: redactText(option.value, sensitiveValues),
        label: redactText(option.label, sensitiveValues),
      })),
    })),
    remediationConsiderations: redactItems(analysis.remediationConsiderations),
  };
}
