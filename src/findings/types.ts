export type FindingStatus = "passed" | "failed" | "warning" | "unknown";

export interface AffectedResource {
  type?: string;
  id?: string;
  name?: string;
}

export interface NormalizedCheckmateFinding {
  id: string;
  validatorId?: string;
  title: string;
  status: FindingStatus;
  severity?: string;
  description?: string;
  recommendation?: string;
  affectedResource?: AffectedResource;
  evidence?: unknown;
  raw: unknown;
}
