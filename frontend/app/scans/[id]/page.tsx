"use client";

import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/severity-badge";
import { ScanStatusBadge } from "@/components/scan-status-badge";
import { ExportButtons } from "@/components/export-buttons";

interface PageProps {
  params: { id: string };
}

export default function ScanDetailPage({ params }: PageProps) {
  const { id } = params;
  const queryClient = useQueryClient();
  const router = useRouter();

  const { data, isLoading, error } = useQuery({
    queryKey: ["scan", id],
    queryFn: () => api.getScan(id),
  });

  const deleteMutation = useMutation({
    mutationFn: () => api.deleteScan(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      router.push("/");
    },
  });

  if (isLoading) {
    return <p className="text-sm text-muted-foreground">Loading scan…</p>;
  }
  if (error || !data) {
    return (
      <div className="space-y-3">
        <p className="text-sm text-severity-critical">
          {(error as Error | undefined)?.message ?? "Scan not found."}
        </p>
        <Button asChild variant="outline" size="sm">
          <Link href="/">
            <ArrowLeft className="h-4 w-4" /> Back to dashboard
          </Link>
        </Button>
      </div>
    );
  }

  const openPorts = data.ports.filter((p) => p.state === "open");

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <Link
            href="/"
            className="mb-1 inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="h-3.5 w-3.5" /> Dashboard
          </Link>
          <h1 className="text-2xl font-semibold">
            {data.target_hostname ?? data.target_ip}
          </h1>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
            <span className="font-mono">{data.target_ip}</span>
            <span className="capitalize">{data.scan_type} scan</span>
            <ScanStatusBadge status={data.status} />
            <span>started {new Date(data.started_at).toLocaleString()}</span>
            {data.completed_at ? (
              <span>· finished {new Date(data.completed_at).toLocaleString()}</span>
            ) : null}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <ExportButtons scanId={id} />
          <Button
            variant="ghost"
            size="icon"
            onClick={() => {
              if (confirm("Delete this scan? Child findings will cascade.")) {
                deleteMutation.mutate();
              }
            }}
            title="Delete scan"
          >
            <Trash2 className="h-4 w-4 text-severity-critical" />
          </Button>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Open ports ({openPorts.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            {openPorts.length === 0 ? (
              <p className="py-4 text-sm text-muted-foreground">
                No open ports recorded.
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
                  {openPorts.map((p) => (
                    <TableRow key={p.id}>
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
              Vulnerabilities ({data.vulnerabilities.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            {data.vulnerabilities.length === 0 ? (
              <p className="py-4 text-sm text-muted-foreground">
                No vulnerabilities identified.
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>CVE</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>CVSS</TableHead>
                    <TableHead>Product</TableHead>
                    <TableHead>Port</TableHead>
                    <TableHead>Source</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.vulnerabilities.map((v) => (
                    <TableRow key={v.id}>
                      <TableCell className="font-mono text-xs">{v.cve_id}</TableCell>
                      <TableCell><SeverityBadge severity={v.severity} /></TableCell>
                      <TableCell className="font-mono">
                        {v.cvss_score ?? "—"}
                      </TableCell>
                      <TableCell className="text-xs">
                        {v.product ?? "—"}{" "}
                        {v.version ? (
                          <span className="font-mono text-muted-foreground">
                            ({v.version})
                          </span>
                        ) : null}
                      </TableCell>
                      <TableCell className="font-mono">
                        {v.port ?? "—"}
                      </TableCell>
                      <TableCell className="text-xs uppercase">{v.source}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            Web findings ({data.web_findings.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {data.web_findings.length === 0 ? (
            <p className="py-4 text-sm text-muted-foreground">
              No web findings recorded.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Type</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>URL</TableHead>
                  <TableHead>Description</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.web_findings.map((w) => (
                  <TableRow key={w.id}>
                    <TableCell>{w.finding_type}</TableCell>
                    <TableCell><SeverityBadge severity={w.severity} /></TableCell>
                    <TableCell className="break-all font-mono text-xs">
                      {w.url ?? "—"}
                    </TableCell>
                    <TableCell className="max-w-md text-xs text-muted-foreground">
                      {w.description ?? "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
