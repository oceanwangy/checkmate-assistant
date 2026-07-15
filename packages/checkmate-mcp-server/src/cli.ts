#!/usr/bin/env node
import path from "node:path";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createCheckmateMcpServer } from "./server.js";

interface CliOptions {
  reportsDirectory: string;
  maxReportAgeDays: number;
  maxReportBytes?: number;
  help: boolean;
}

function valueAfter(args: string[], index: number, option: string): string {
  const value = args[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`${option} requires a value.`);
  }
  return value;
}

function positiveNumber(value: string, option: string): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new Error(`${option} must be a non-negative number.`);
  }
  return parsed;
}

function parseArguments(args: string[]): CliOptions {
  let reportsDirectory =
    process.env.CHECKMATE_REPORTS_DIR ?? path.resolve("reports");
  let maxReportAgeDays = positiveNumber(
    process.env.CHECKMATE_MAX_REPORT_AGE_DAYS ?? "7",
    "CHECKMATE_MAX_REPORT_AGE_DAYS",
  );
  let maxReportBytes: number | undefined;
  if (process.env.CHECKMATE_MAX_REPORT_BYTES) {
    maxReportBytes = positiveNumber(
      process.env.CHECKMATE_MAX_REPORT_BYTES,
      "CHECKMATE_MAX_REPORT_BYTES",
    );
  }
  let help = false;

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    switch (argument) {
      case "--reports-dir":
        reportsDirectory = valueAfter(args, index, argument);
        index += 1;
        break;
      case "--max-report-age-days":
        maxReportAgeDays = positiveNumber(
          valueAfter(args, index, argument),
          argument,
        );
        index += 1;
        break;
      case "--max-report-bytes":
        maxReportBytes = positiveNumber(
          valueAfter(args, index, argument),
          argument,
        );
        index += 1;
        break;
      case "--help":
      case "-h":
        help = true;
        break;
      default:
        throw new Error(`Unknown option: ${argument}`);
    }
  }

  const options: CliOptions = {
    reportsDirectory,
    maxReportAgeDays,
    help,
  };
  if (maxReportBytes !== undefined) options.maxReportBytes = maxReportBytes;
  return options;
}

function helpText(): string {
  return [
    "CheckMate MCP Server (read-only, stdio)",
    "",
    "Usage:",
    "  checkmate-mcp-server [options]",
    "",
    "Options:",
    "  --reports-dir <path>          CheckMate JSON report directory (default: ./reports)",
    "  --max-report-age-days <days>  Stale-report threshold (default: 7)",
    "  --max-report-bytes <bytes>    Maximum JSON report size (default: 26214400)",
    "  -h, --help                    Show this help",
    "",
    "Environment equivalents:",
    "  CHECKMATE_REPORTS_DIR",
    "  CHECKMATE_MAX_REPORT_AGE_DAYS",
    "  CHECKMATE_MAX_REPORT_BYTES",
  ].join("\n");
}

async function main(): Promise<void> {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(`${helpText()}\n`);
    return;
  }

  const serverOptions: {
    reportsDirectory: string;
    maxReportAgeDays: number;
    maxReportBytes?: number;
  } = {
    reportsDirectory: options.reportsDirectory,
    maxReportAgeDays: options.maxReportAgeDays,
  };
  if (options.maxReportBytes !== undefined) {
    serverOptions.maxReportBytes = options.maxReportBytes;
  }
  const server = createCheckmateMcpServer(serverOptions);
  const transport = new StdioServerTransport();

  process.on("SIGINT", () => {
    void server.close().finally(() => process.exit(0));
  });
  process.on("SIGTERM", () => {
    void server.close().finally(() => process.exit(0));
  });

  await server.connect(transport);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Unknown error.";
  process.stderr.write(`CheckMate MCP Server failed: ${message}\n`);
  process.exitCode = 1;
});
