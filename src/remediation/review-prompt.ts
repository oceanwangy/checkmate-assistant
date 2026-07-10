import { checkbox, input, select } from "@inquirer/prompts";
import type { AiReviewQuestion } from "../ai/provider.js";
import type { RemediationDecisionStatus } from "./plan-schema.js";
import { AppError } from "../utils/errors.js";
import { safeTerminalText } from "../utils/terminal.js";

const DECISIONS: ReadonlyArray<{
  value: RemediationDecisionStatus;
  name: string;
}> = [
  { value: "approved", name: "Approved" },
  { value: "rejected", name: "Rejected" },
  { value: "deferred", name: "Deferred" },
  { value: "accepted_risk", name: "Accepted risk" },
  { value: "needs_investigation", name: "Needs investigation" },
];

export type ReviewQuestionAnswer = string | string[];

export interface ReviewPrompt {
  askFindingQuestion(question: AiReviewQuestion): Promise<ReviewQuestionAnswer>;
  selectDecision(): Promise<RemediationDecisionStatus>;
  askRationale(): Promise<string>;
  close(): void;
}

export class ConsoleReviewPrompt implements ReviewPrompt {
  private async run<T>(action: () => Promise<T>): Promise<T> {
    try {
      return await action();
    } catch (error) {
      throw new AppError(
        "REVIEW_INPUT_CLOSED",
        "Interactive review input was closed.",
        {
          cause: error,
        },
      );
    }
  }

  async askFindingQuestion(
    question: AiReviewQuestion,
  ): Promise<ReviewQuestionAnswer> {
    const message = safeTerminalText(question.prompt);
    if (question.inputType === "text") {
      return this.run(() => input({ message }));
    }

    const choices = question.options.map((option) => ({
      value: option.value,
      name: safeTerminalText(option.label),
    }));
    if (question.inputType === "single_select") {
      return this.run(() => select({ message, choices, loop: false }));
    }

    return this.run(() =>
      checkbox({
        message,
        choices,
        loop: false,
        pageSize: 15,
        required: true,
      }),
    );
  }

  selectDecision(): Promise<RemediationDecisionStatus> {
    return this.run(() =>
      select({
        message: "Decision",
        choices: DECISIONS,
        loop: false,
      }),
    );
  }

  askRationale(): Promise<string> {
    return this.run(() =>
      input({
        message: "Rationale",
        required: true,
      }),
    );
  }

  close(): void {
    // Inquirer prompts close their input resources after each answer.
  }
}
