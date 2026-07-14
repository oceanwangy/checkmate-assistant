import { spawn } from "node:child_process";
import type { SpawnOptions } from "node:child_process";
import path from "node:path";
import { toErrorMessage } from "../utils/errors.js";

const OUTPUT_LIMIT = 200_000;

export interface TerraformCommandRequest {
  args: readonly string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
  timeoutMs: number;
}

export interface TerraformCommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export type TerraformCommandRunner = (
  request: TerraformCommandRequest,
) => Promise<TerraformCommandResult>;

export interface TerraformValidationResult {
  valid: boolean;
  validatedAt: string;
  terraformFile: string;
  steps: Array<{
    command: "fmt" | "init" | "validate";
    valid: boolean;
    message: string;
  }>;
  error?: string;
}

function appendLimited(current: string, chunk: Buffer | string): string {
  const combined = current + chunk.toString();
  return combined.length > OUTPUT_LIMIT
    ? combined.slice(combined.length - OUTPUT_LIMIT)
    : combined;
}

export const spawnTerraformCommand: TerraformCommandRunner = async (request) =>
  new Promise((resolve, reject) => {
    const options: SpawnOptions = {
      cwd: request.cwd,
      env: request.env,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    };
    const child = spawn("terraform", [...request.args], options);
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, request.timeoutMs);
    child.stdout?.on("data", (chunk: Buffer) => {
      stdout = appendLimited(stdout, chunk);
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr = appendLimited(stderr, chunk);
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code) => {
      clearTimeout(timer);
      if (timedOut) {
        reject(new Error("Terraform validation timed out."));
        return;
      }
      resolve({ exitCode: code ?? -1, stdout, stderr });
    });
  });

function safeTerraformEnvironment(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const allowed = [
    "PATH",
    "HOME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
  ];
  return {
    ...Object.fromEntries(
      allowed.flatMap((key) =>
        env[key] === undefined ? [] : [[key, env[key]]],
      ),
    ),
    TF_IN_AUTOMATION: "1",
    CHECKPOINT_DISABLE: "1",
  };
}

export async function validateTerraformConfiguration(
  terraformFile: string,
  options: {
    runner?: TerraformCommandRunner;
    env?: NodeJS.ProcessEnv;
    now?: () => Date;
  } = {},
): Promise<TerraformValidationResult> {
  const runner = options.runner ?? spawnTerraformCommand;
  const cwd = path.dirname(terraformFile);
  const env = safeTerraformEnvironment(options.env ?? process.env);
  const now = options.now ?? (() => new Date());
  const steps: TerraformValidationResult["steps"] = [];
  const commands = [
    {
      command: "fmt" as const,
      args: ["fmt", "-check", "-no-color", path.basename(terraformFile)],
    },
    {
      command: "init" as const,
      args: ["init", "-backend=false", "-input=false", "-no-color"],
    },
    {
      command: "validate" as const,
      args: ["validate", "-no-color"],
    },
  ];
  try {
    for (const command of commands) {
      const result = await runner({
        args: command.args,
        cwd,
        env,
        timeoutMs: 120_000,
      });
      const message =
        result.stdout.trim() || result.stderr.trim() || "Validation passed.";
      steps.push({
        command: command.command,
        valid: result.exitCode === 0,
        message,
      });
      if (result.exitCode !== 0) {
        return {
          valid: false,
          validatedAt: now().toISOString(),
          terraformFile,
          steps,
          error: message,
        };
      }
    }
    return {
      valid: true,
      validatedAt: now().toISOString(),
      terraformFile,
      steps,
    };
  } catch (error) {
    const message = toErrorMessage(error);
    return {
      valid: false,
      validatedAt: now().toISOString(),
      terraformFile,
      steps,
      error: message,
    };
  }
}
