"use client";

import { useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowRight, Loader2 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SeverityBadge } from "@/components/severity-badge";
import { ScanStatusBadge } from "@/components/scan-status-badge";
import { useScanEvents } from "@/lib/use-scan-events";
import { Button } from "@/components/ui/button";

interface PageProps {
  params: { id: string };
}

/**
 * Live scan view — subscribes to /ws/scan/{id} via useScanEvents and renders
 * ports / vulns / web findings as they arrive. When the scan reaches a
 * terminal status the page bounces to the static detail view so the user
 * lands on the persistent record rather than a hub buffer that's about to
 * empty.
 */
export default function LiveScanPage({ params }: PageProps) {
  const { id } = params;
  const router = useRouter();
  const state = useScanEvents(id);

  useEffect(() => {
    // Small delay lets the final progress tick render before navigating.
    if (state.status === "completed" || state.status === "failed") {
      const t = setTimeout(() => router.replace(`/scans/${id}`), 800);
      return () => clearTimeout(t);
    }
  }, [state.status, id, router]);

  const pct = state.progress
    ? (state.progress.done / Math.max(1, state.progress.total)) * 100
    : state.status === "completed"
      ? 100
      : 0;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Live scan</h1>
          <p className="font-mono text-xs text-muted-foreground">
            {id}
            {state.resolvedIp ? ` · resolved → ${state.resolvedIp}` : null}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {state.status === "connecting" || state.status === "running" || state.status === "queued" ? (
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          ) : null}
          <ScanStatusBadge
            status={
              state.status === "connecting" || state.status === "disconnected"
                ? "queued"
                : state.status
            }
          />
          {state.status === "completed" || state.status === "failed" ? (
            <Button asChild size="sm" variant="outline">
              <Link href={`/scans/${id}`}>
                View results <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </Button>
          ) : null}
        </div>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">
            Progress
            {state.phase ? (
              <span className="ml-2 text-sm font-normal text-muted-foreground">
                ({state.phase})
              </span>
            ) : null}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          <Progress value={pct} />
          <div className="flex justify-between text-xs text-muted-foreground">
            <span>
              {state.progress
                ? `${state.progress.done} / ${state.progress.total}`
                : state.status === "completed"
                  ? "done"
                  : "waiting for backend…"}
            </span>
            <span>{pct.toFixed(0)}%</span>
          </div>
          {state.error ? (
            <p className="text-sm text-severity-critical">{state.error}</p>
          ) : null}
        </CardContent>
      </Card>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Open ports ({state.ports.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            {state.ports.length === 0 ? (
              <p className="py-6 text-center text-sm text-muted-foreground">
                Listening for open ports…
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Port</TableHead>
                    <TableHead>Service</TableHead>
                    <TableHead>Product</TableHead>
                    <TableHead>Version</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {state.ports.map((p, i) => (
                    <TableRow key={`${p.proto}-${p.port}-${i}`}>
                      <TableCell className="font-mono">
                        {p.port}/{p.proto}
                      </TableCell>
                      <TableCell>{p.service ?? "—"}</TableCell>
                      <TableCell>{p.product ?? "—"}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {p.version ?? "—"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Findings ({state.vulnerabilities.length + state.findings.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            {state.vulnerabilities.length === 0 && state.findings.length === 0 ? (
              <p className="py-6 text-center text-sm text-muted-foreground">
                None yet.
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Type</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Detail</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {state.vulnerabilities.map((v, i) => (
                    <TableRow key={`v-${v.cve_id}-${i}`}>
                      <TableCell className="font-mono text-xs">{v.cve_id}</TableCell>
                      <TableCell><SeverityBadge severity={v.severity} /></TableCell>
                      <TableCell className="text-xs">
                        {v.product ?? "?"} {v.version ?? ""} · port {v.port ?? "—"}
                        {v.cvss_score !== null ? (
                          <span className="ml-1 font-mono text-muted-foreground">
                            (CVSS {v.cvss_score})
                          </span>
                        ) : null}
                      </TableCell>
                    </TableRow>
                  ))}
                  {state.findings.map((w, i) => (
                    <TableRow key={`w-${w.finding_type}-${i}`}>
                      <TableCell>{w.finding_type}</TableCell>
                      <TableCell><SeverityBadge severity={w.severity} /></TableCell>
                      <TableCell className="break-all font-mono text-xs">
                        {w.url ?? "—"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
