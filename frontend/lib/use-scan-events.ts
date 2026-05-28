"use client";

import { useEffect, useRef, useState } from "react";
import { scanEventsURL } from "./api";
import type { ScanStatus, Severity, WSEvent } from "./types";

export interface LivePort {
  port: number;
  proto: string;
  state: string;
  service: string | null;
  product: string | null;
  version: string | null;
}

export interface LiveVuln {
  cve_id: string;
  severity: Severity;
  cvss_score: number | null;
  product: string | null;
  version: string | null;
  port: number | null;
}

export interface LiveFinding {
  finding_type: string;
  severity: Severity;
  url: string | null;
}

export interface LiveScanState {
  status: ScanStatus | "connecting" | "disconnected";
  phase: string | null;
  resolvedIp: string | null;
  progress: { done: number; total: number } | null;
  ports: LivePort[];
  vulnerabilities: LiveVuln[];
  findings: LiveFinding[];
  error: string | null;
  events: WSEvent[];
}

const initial: LiveScanState = {
  status: "connecting",
  phase: null,
  resolvedIp: null,
  progress: null,
  ports: [],
  vulnerabilities: [],
  findings: [],
  error: null,
  events: [],
};

/**
 * Subscribe to /ws/scan/{id} and fold events into a single in-memory
 * scan state. The hook owns one WebSocket per scan id (cleaned up on
 * unmount or id change).
 *
 * Reconnects are NOT attempted on close — the executor always emits a
 * terminal event before closing in the normal case, and an unexpected
 * disconnect should surface to the user rather than be silently retried.
 */
export function useScanEvents(scanId: string): LiveScanState {
  const [state, setState] = useState<LiveScanState>(initial);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    setState(initial);
    const ws = new WebSocket(scanEventsURL(scanId));
    wsRef.current = ws;

    ws.onmessage = (raw) => {
      let evt: WSEvent;
      try {
        evt = JSON.parse(raw.data);
      } catch {
        return;
      }
      setState((s) => applyEvent(s, evt));
    };
    ws.onerror = () =>
      setState((s) => ({ ...s, status: "disconnected", error: "WebSocket error" }));
    ws.onclose = () =>
      setState((s) =>
        s.status === "completed" || s.status === "failed"
          ? s
          : { ...s, status: "disconnected" },
      );

    return () => {
      // Calling close() during the OPENING handshake is a no-op in the spec
      // but spams a console warning; gate on readyState.
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        ws.close();
      }
    };
  }, [scanId]);

  return state;
}

function applyEvent(s: LiveScanState, evt: WSEvent): LiveScanState {
  // Capped event log — keeps memory bounded during long full-scans where
  // tens of thousands of port events could arrive.
  const events = [...s.events.slice(-199), evt];
  switch (evt.type) {
    case "status":
      return { ...s, status: evt.status, events };
    case "resolved":
      return { ...s, resolvedIp: evt.ip, events };
    case "started":
      return {
        ...s,
        phase: evt.phase,
        progress: evt.total ? { done: 0, total: evt.total } : s.progress,
        events,
      };
    case "progress":
      return {
        ...s,
        progress: { done: evt.done, total: evt.total },
        events,
      };
    case "port":
      return {
        ...s,
        ports: [
          ...s.ports,
          {
            port: evt.port,
            proto: evt.proto,
            state: evt.state,
            service: evt.service,
            product: evt.product,
            version: evt.version,
          },
        ],
        events,
      };
    case "vuln":
      return {
        ...s,
        vulnerabilities: [
          ...s.vulnerabilities,
          {
            cve_id: evt.cve_id,
            severity: evt.severity,
            cvss_score: evt.cvss_score,
            product: evt.product,
            version: evt.version,
            port: evt.port,
          },
        ],
        events,
      };
    case "finding":
      return {
        ...s,
        findings: [
          ...s.findings,
          {
            finding_type: evt.finding_type,
            severity: evt.severity,
            url: evt.url,
          },
        ],
        events,
      };
    case "completed":
      return { ...s, status: "completed", events };
    case "failed":
      return { ...s, status: "failed", error: evt.error, events };
    case "error":
      return { ...s, error: evt.error, events };
    default:
      return { ...s, events };
  }
}
