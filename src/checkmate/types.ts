import type { ProfileName } from "../config/profiles.js";

export type {
  LoadedCheckmateReport,
  NormalizedCheckmateReport,
} from "@checkmate-assistant/core";

export interface ReportCounts {
  passed: number;
  failed: number;
  warning: number;
  unknown: number;
}

export interface ReportSummary extends ReportCounts {
  tenant?: string;
  generatedAt?: string;
  reportPath: string;
  passedChecksIncluded: boolean;
}

export interface ScanMetadata {
  profile: ProfileName;
  targetDomain: string;
  startedAt: string;
  finishedAt: string;
  checkmateVersion?: string;
  reportPath: string;
  exitCode: number;
}
