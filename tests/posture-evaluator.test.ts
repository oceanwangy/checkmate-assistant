import { describe, expect, it } from "vitest";
import type { NormalizedCheckmateFinding } from "../src/findings/types.js";
import {
  classifyPostureScore,
  evaluatePosture,
} from "../src/posture/evaluator.js";

function finding(
  validatorId: string,
  status: NormalizedCheckmateFinding["status"] = "failed",
): NormalizedCheckmateFinding {
  return {
    id: `${validatorId}-1`,
    validatorId,
    title: validatorId,
    status,
    raw: {},
  };
}

describe("tenant configuration posture", () => {
  it("returns green for a report with no catalog control issues", () => {
    const assessment = evaluatePosture([]);

    expect(assessment.modelVersion).toBe("auth0-posture-v1");
    expect(assessment.current).toMatchObject({ score: 100, rating: "green" });
    expect(assessment.projected).toEqual(assessment.current);
    expect(assessment.delta).toBe(0);
  });

  it("uses posture points for colour while retaining foundational control context", () => {
    const assessment = evaluatePosture([finding("checkGuardianPolicy")]);

    expect(assessment.current.score).toBeGreaterThan(60);
    expect(assessment.current.rating).toBe("green");
    expect(assessment.current.openFoundationalControls).toEqual([
      {
        validatorId: "checkGuardianPolicy",
        title: "MFA policy",
      },
    ]);
  });

  it("does not override a points-based colour for a high-impact warning", () => {
    const assessment = evaluatePosture([
      finding("checkManagementAPIUserAccess", "warning"),
    ]);

    expect(assessment.current.score).toBeGreaterThanOrEqual(85);
    expect(assessment.current.rating).toBe("green");
    expect(assessment.current.openHighControls).toHaveLength(1);
  });

  it("raises only the projection when an accepted change resolves a validator", () => {
    const assessment = evaluatePosture([finding("checkGuardianPolicy")], {
      projectedResolvedValidatorIds: new Set(["checkGuardianPolicy"]),
    });

    expect(assessment.current.rating).toBe("green");
    expect(assessment.current.score).toBeLessThan(100);
    expect(assessment.projected).toMatchObject({ score: 100, rating: "green" });
    expect(assessment.delta).toBeGreaterThan(0);
  });

  it("awards partial points when only some actions for a validator are accepted", () => {
    const assessment = evaluatePosture([finding("checkPasswordPolicy")], {
      projectedValidatorProgress: new Map([["checkPasswordPolicy", 0.5]]),
    });

    expect(assessment.projected.score).toBeGreaterThan(
      assessment.current.score,
    );
    expect(assessment.projected.score).toBeLessThan(100);
  });

  it("weights a foundational control more heavily than a low-impact control", () => {
    const foundational = evaluatePosture([finding("checkGuardianPolicy")]);
    const low = evaluatePosture([finding("checkPasswordHistory")]);

    expect(foundational.current.score).toBeLessThan(low.current.score);
  });

  it("reports CheckMate validators that are intentionally outside the score", () => {
    const assessment = evaluatePosture([finding("checkSupportUrl")]);

    expect(assessment.current.score).toBe(100);
    expect(assessment.reportedControlCount).toBe(0);
    expect(assessment.unscoredValidatorIds).toEqual(["checkSupportUrl"]);
  });

  it("classifies 70 posture points as green", () => {
    expect(classifyPostureScore(49)).toBe("red");
    expect(classifyPostureScore(50)).toBe("amber");
    expect(classifyPostureScore(69)).toBe("amber");
    expect(classifyPostureScore(70)).toBe("green");
  });
});
