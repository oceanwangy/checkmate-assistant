import { describe, expect, it } from "vitest";
import { buildAiFindingPayload } from "../src/ai/finding-payload.js";
import type { NormalizedCheckmateFinding } from "../src/findings/types.js";

describe("AI finding payload", () => {
  it("sends only normalized fields and redacts sensitive evidence", () => {
    const finding: NormalizedCheckmateFinding = {
      id: "finding-1",
      validatorId: "checkExample",
      title: "Finding mentions known-secret",
      status: "failed",
      description: "A client_secret=raw-secret was detected.",
      evidence: {
        field: "client_secret",
        value: "raw-secret",
        authorization: "Bearer raw-token",
      },
      raw: { complete: "raw report must not be sent" },
    };

    const payload = buildAiFindingPayload(finding, ["known-secret"]);
    expect(payload).not.toHaveProperty("raw");
    expect(JSON.stringify(payload)).not.toContain("known-secret");
    expect(JSON.stringify(payload)).not.toContain("raw-secret");
    expect(JSON.stringify(payload)).not.toContain("raw-token");
    expect(payload.evidence).toMatchObject({
      field: "client_secret",
      value: "[REDACTED]",
      authorization: "[REDACTED]",
    });
  });
});
