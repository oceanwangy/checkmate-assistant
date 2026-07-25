import type {
  FindingStatus,
  NormalizedCheckmateFinding,
} from "../findings/types.js";
import {
  POSTURE_CATEGORIES,
  POSTURE_CONTROLS,
  POSTURE_IMPORTANCE_WEIGHTS,
  POSTURE_MODEL_VERSION,
  type PostureControl,
} from "./control-catalog.js";

export type PostureRating = "red" | "amber" | "green";
export type PostureControlState =
  "failed" | "warning" | "unknown" | "no_issue_reported";

export interface PostureOpenControl {
  validatorId: string;
  title: string;
}

export interface PostureCategoryScore {
  id: string;
  title: string;
  score: number;
  maximum: number;
  openControls: number;
}

export interface PostureSnapshot {
  score: number;
  rating: PostureRating;
  categories: PostureCategoryScore[];
  openFoundationalControls: PostureOpenControl[];
  openHighControls: PostureOpenControl[];
}

export interface PostureAssessment {
  modelVersion: string;
  evidenceBasis: "complete_checkmate_findings_report";
  current: PostureSnapshot;
  projected: PostureSnapshot;
  delta: number;
  catalogControlCount: number;
  reportedControlCount: number;
  unscoredValidatorIds: string[];
}

export interface EvaluatePostureOptions {
  projectedResolvedValidatorIds?: ReadonlySet<string>;
  projectedValidatorProgress?: ReadonlyMap<string, number>;
}

export function classifyPostureScore(score: number): PostureRating {
  if (score < 50) return "red";
  if (score < 70) return "amber";
  return "green";
}

interface ControlResult {
  control: PostureControl;
  factor: number;
  state: PostureControlState;
}

const statusFactor: Record<FindingStatus, number> = {
  passed: 1,
  warning: 0.5,
  unknown: 0.25,
  failed: 0,
};

function controlResult(
  control: PostureControl,
  findings: readonly NormalizedCheckmateFinding[],
): ControlResult {
  const statuses = findings
    .filter((finding) => finding.validatorId === control.validatorId)
    .map((finding) => finding.status);
  if (
    statuses.length === 0 ||
    statuses.every((status) => status === "passed")
  ) {
    return { control, factor: 1, state: "no_issue_reported" };
  }
  const factor = Math.min(...statuses.map((status) => statusFactor[status]));
  const state: PostureControlState = statuses.includes("failed")
    ? "failed"
    : statuses.includes("unknown")
      ? "unknown"
      : "warning";
  return { control, factor, state };
}

function projectedControlResult(
  result: ControlResult,
  progress: number,
): ControlResult {
  const boundedProgress = Math.max(0, Math.min(1, progress));
  const factor = result.factor + (1 - result.factor) * boundedProgress;
  return {
    ...result,
    factor,
    ...(factor === 1 ? { state: "no_issue_reported" as const } : {}),
  };
}

function round(value: number, precision = 1): number {
  const multiplier = 10 ** precision;
  return Math.round(value * multiplier) / multiplier;
}

function snapshot(results: readonly ControlResult[]): PostureSnapshot {
  const categories = POSTURE_CATEGORIES.map((category) => {
    const controls = results.filter(
      (result) => result.control.category === category.id,
    );
    const totalWeight = controls.reduce(
      (sum, result) =>
        sum + POSTURE_IMPORTANCE_WEIGHTS[result.control.importance],
      0,
    );
    const earnedWeight = controls.reduce(
      (sum, result) =>
        sum +
        POSTURE_IMPORTANCE_WEIGHTS[result.control.importance] * result.factor,
      0,
    );
    return {
      id: category.id,
      title: category.title,
      score: round(category.budget * (earnedWeight / totalWeight)),
      maximum: category.budget,
      openControls: controls.filter((result) => result.factor < 1).length,
    };
  });
  const score = Math.round(
    categories.reduce((sum, category) => sum + category.score, 0),
  );
  const openFoundationalControls = results
    .filter(
      (result) =>
        result.factor < 1 && result.control.importance === "foundational",
    )
    .map(({ control }) => ({
      validatorId: control.validatorId,
      title: control.title,
    }));
  const openHighControls = results
    .filter(
      (result) => result.factor < 1 && result.control.importance === "high",
    )
    .map(({ control }) => ({
      validatorId: control.validatorId,
      title: control.title,
    }));
  const rating = classifyPostureScore(score);
  return {
    score,
    rating,
    categories,
    openFoundationalControls,
    openHighControls,
  };
}

export function evaluatePosture(
  findings: readonly NormalizedCheckmateFinding[],
  options: EvaluatePostureOptions = {},
): PostureAssessment {
  const currentResults = POSTURE_CONTROLS.map((item) =>
    controlResult(item, findings),
  );
  const resolvedValidatorIds =
    options.projectedResolvedValidatorIds ?? new Set();
  const projectedResults = currentResults.map((result) =>
    projectedControlResult(
      result,
      resolvedValidatorIds.has(result.control.validatorId)
        ? 1
        : (options.projectedValidatorProgress?.get(
            result.control.validatorId,
          ) ?? 0),
    ),
  );
  const current = snapshot(currentResults);
  const projected = snapshot(projectedResults);
  const catalogValidatorIds = new Set(
    POSTURE_CONTROLS.map((item) => item.validatorId),
  );
  const reportedValidatorIds = new Set(
    findings.flatMap((finding) =>
      finding.validatorId ? [finding.validatorId] : [],
    ),
  );
  return {
    modelVersion: POSTURE_MODEL_VERSION,
    evidenceBasis: "complete_checkmate_findings_report",
    current,
    projected,
    delta: projected.score - current.score,
    catalogControlCount: POSTURE_CONTROLS.length,
    reportedControlCount: [...reportedValidatorIds].filter((validatorId) =>
      catalogValidatorIds.has(validatorId),
    ).length,
    unscoredValidatorIds: [...reportedValidatorIds]
      .filter((validatorId) => !catalogValidatorIds.has(validatorId))
      .sort(),
  };
}
