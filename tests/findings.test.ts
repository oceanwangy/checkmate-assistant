import { describe, expect, it } from "vitest";
import { filterFindings } from "../src/findings/filter.js";
import type { NormalizedCheckmateFinding } from "../src/findings/types.js";
import {
  classifyFindingPriority,
  prioritizeFindings,
} from "../src/findings/priority.js";

const findings: NormalizedCheckmateFinding[] = [
  { id: "1", title: "Failed", status: "failed", raw: {} },
  { id: "2", title: "Warning", status: "warning", raw: {} },
  { id: "3", title: "Passed", status: "passed", raw: {} },
  { id: "4", title: "Unknown", status: "unknown", raw: {} },
];

describe("findings", () => {
  it("filters by status or returns all", () => {
    expect(filterFindings(findings, "failed").map((item) => item.id)).toEqual([
      "1",
    ]);
    expect(filterFindings(findings, "all")).toHaveLength(4);
  });

  it("puts obvious tenant hardening before app-specific review", () => {
    const appFinding: NormalizedCheckmateFinding = {
      id: "app",
      title: "Application callback URL",
      status: "failed",
      severity: "High",
      raw: {},
    };
    const mfaFinding: NormalizedCheckmateFinding = {
      id: "mfa",
      title: "MFA is not enforced",
      status: "failed",
      severity: "Medium",
      raw: {},
    };
    expect(classifyFindingPriority(appFinding)).toBe("app_specific");
    expect(classifyFindingPriority(mfaFinding)).toBe("obvious");
    expect(
      prioritizeFindings([appFinding, mfaFinding]).map(({ id }) => id),
    ).toEqual(["mfa", "app"]);
  });
});
