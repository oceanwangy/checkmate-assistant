import type { NormalizedCheckmateFinding } from "../findings/types.js";
import type { ProfileName } from "../config/profiles.js";

export interface NormalizedCheckmateReport {
  tenant?: string;
  generatedAt?: string;
  findings: NormalizedCheckmateFinding[];
  raw: unknown;
  findingsOnly: boolean;
}

export interface LoadedCheckmateReport extends NormalizedCheckmateReport {
  sourcePath: string;
}

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
