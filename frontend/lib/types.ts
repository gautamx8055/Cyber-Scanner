/**
 * Mirrors backend/api/schemas.py — keep field names + nullability in sync.
 * The backend is the source of truth; this file is a hand-written copy
 * because no contract-generator runs in this project yet.
 */

export type ScanType = "port" | "vuln" | "web" | "full";
export type ScanStatus = "queued" | "running" | "completed" | "failed";

export type Severity =
  | "Critical"
  | "High"
  | "Medium"
  | "Low"
  | "Info"
  | "Unknown";

export const SEVERITY_ORDER: Severity[] = [
  "Critical",
  "High",
  "Medium",
  "Low",
  "Info",
  "Unknown",
];

export interface ScanSummary {
  id: string;
  target_ip: string;
  target_hostname: string | null;
  scan_type: ScanType;
  status: ScanStatus;
  started_at: string;
  completed_at: string | null;
}

export interface PortOut {
  id: string;
  port: number;
  proto: string;
  state: string;
  service: string | null;
  product: string | null;
  version: string | null;
  banner: string | null;
}

export interface VulnerabilityOut {
  id: string;
  cve_id: string;
  product: string | null;
  version: string | null;
  port: number | null;
  proto: string;
  cvss_score: number | null;
  severity: Severity;
  description: string | null;
  source: string;
}

export interface WebFindingOut {
  id: string;
  finding_type: string;
  severity: Severity;
  url: string | null;
  description: string | null;
  evidence: string | null;
}

export interface ScanDetail extends ScanSummary {
  options: Record<string, unknown> | null;
  results: unknown | null;
  ports: PortOut[];
  vulnerabilities: VulnerabilityOut[];
  web_findings: WebFindingOut[];
}

export interface ScanList {
  total: number;
  limit: number;
  offset: number;
  items: ScanSummary[];
}

export interface ScanCreateBody {
  target: string;
  scan_type: ScanType;
  options?: Record<string, unknown>;
}

// --- WebSocket event envelopes (api/executor.py hub.publish) --------------

export type WSEvent =
  | { type: "status"; status: ScanStatus; scan_type?: ScanType }
  | { type: "resolved"; host: string; ip: string }
  | { type: "started"; phase: string; target: string; total?: number; checks?: string[] }
  | { type: "progress"; done: number; total: number }
  | {
      type: "port";
      port: number;
      proto: string;
      state: string;
      service: string | null;
      product: string | null;
      version: string | null;
    }
  | {
      type: "vuln";
      cve_id: string;
      severity: Severity;
      cvss_score: number | null;
      product: string | null;
      version: string | null;
      port: number | null;
    }
  | {
      type: "finding";
      finding_type: string;
      severity: Severity;
      url: string | null;
    }
  | { type: "phase_error"; phase: string; error: string }
  | { type: "completed"; status: "completed"; summary: Record<string, unknown> }
  | { type: "failed"; status: "failed"; error: string }
  | { type: "error"; error: string };
