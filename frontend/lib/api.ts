import type {
  ScanCreateBody,
  ScanDetail,
  ScanList,
} from "./types";

/**
 * REST client for the FastAPI backend.
 *
 * - Base URL is taken from NEXT_PUBLIC_API_URL at build time so the same image
 *   can be pointed at dev (http://localhost:8000) or a deployed backend.
 * - All requests run client-side (`use client` components call these); the
 *   browser hits the backend directly. No Next.js API route in between, so
 *   the WebSocket path mirrors the same host.
 */

export const API_URL =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") ?? "http://localhost:8000";

async function request<T>(
  path: string,
  init?: RequestInit & { signal?: AbortSignal },
): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    ...init,
  });
  if (!res.ok) {
    // Try to surface the FastAPI {detail} field; fall back to raw text.
    let detail = res.statusText;
    try {
      const body = await res.json();
      if (body?.detail) detail = body.detail;
    } catch {
      // body wasn't JSON — keep statusText
    }
    throw new Error(`${res.status} ${detail}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  listScans: (limit = 20, offset = 0) =>
    request<ScanList>(`/api/scans?limit=${limit}&offset=${offset}`),

  getScan: (id: string) => request<ScanDetail>(`/api/scans/${id}`),

  createScan: (body: ScanCreateBody) =>
    request<ScanDetail>("/api/scans", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  deleteScan: (id: string) =>
    request<void>(`/api/scans/${id}`, { method: "DELETE" }),
};

/**
 * Build the WebSocket URL for live scan events. Derived from API_URL so a
 * single env var configures both REST and WS endpoints.
 */
export function scanEventsURL(id: string): string {
  const wsBase = API_URL.replace(/^http/, "ws");
  return `${wsBase}/ws/scan/${id}`;
}

/**
 * Build a downloadable export URL. The route lives on the backend; we only
 * need the URL string (browsers handle the download via window.location or
 * an <a download>).
 */
export function exportURL(
  id: string,
  format: "json" | "csv" | "html" | "pdf",
  opts: { download?: boolean } = {},
): string {
  const params = new URLSearchParams({ format });
  if (opts.download) params.set("download", "true");
  return `${API_URL}/api/scans/${id}/export?${params}`;
}
