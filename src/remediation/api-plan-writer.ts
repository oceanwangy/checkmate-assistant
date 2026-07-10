import { rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { stringify } from "yaml";
import { apiPlanSchema, type ApiPlan } from "./api-plan.js";
import { ensureDirectory } from "../utils/filesystem.js";
import { AppError } from "../utils/errors.js";

export function createApiPlanOutputPath(reviewOutputPath: string): string {
  return reviewOutputPath.replace(/\.json$/i, ".api-plan.yml");
}

export async function writeApiPlan(
  outputPath: string,
  plan: ApiPlan,
): Promise<void> {
  const validated = apiPlanSchema.safeParse(plan);
  if (!validated.success) {
    throw new AppError(
      "REVIEW_WRITE_ERROR",
      "The API plan is invalid and was not written.",
      { cause: validated.error },
    );
  }
  await ensureDirectory(path.dirname(outputPath));
  const temporaryPath = `${outputPath}.${process.pid}.tmp`;
  try {
    await writeFile(temporaryPath, stringify(validated.data), {
      encoding: "utf8",
      mode: 0o600,
    });
    await rename(temporaryPath, outputPath);
  } catch (error) {
    throw new AppError(
      "REVIEW_WRITE_ERROR",
      `Unable to write API plan: ${outputPath}`,
      { cause: error },
    );
  }
}
