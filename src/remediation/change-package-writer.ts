import { rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { ensureDirectory } from "../utils/filesystem.js";
import type { ProfileName } from "../config/profiles.js";

export interface EnvironmentArtifactPaths {
  apiPlan: string;
  terraform: string;
}

export interface ChangePackagePaths {
  directory: string;
  dev: EnvironmentArtifactPaths;
  prod: EnvironmentArtifactPaths;
}

export function createChangePackagePaths(
  reviewOutputPath: string,
): ChangePackagePaths {
  const directory = reviewOutputPath.replace(/\.json$/i, ".change-package");
  const environment = (profile: ProfileName): EnvironmentArtifactPaths => {
    const environmentDirectory = path.join(directory, profile);
    return {
      apiPlan: path.join(environmentDirectory, "api-plan.yml"),
      terraform: path.join(environmentDirectory, "main.tf"),
    };
  };
  return {
    directory,
    dev: environment("dev"),
    prod: environment("prod"),
  };
}

export async function writeTextArtifact(
  outputPath: string,
  content: string,
): Promise<void> {
  await ensureDirectory(path.dirname(outputPath));
  const temporaryPath = `${outputPath}.${process.pid}.tmp`;
  await writeFile(temporaryPath, content, { encoding: "utf8", mode: 0o600 });
  await rename(temporaryPath, outputPath);
}
