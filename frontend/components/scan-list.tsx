"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ScanStatusBadge } from "@/components/scan-status-badge";

export function ScanList() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["scans", { limit: 20 }],
    queryFn: () => api.listScans(20, 0),
    // Refetch every 5s so a running scan visibly transitions to "completed"
    // without forcing the user to reload. Pausing on background tabs keeps
    // the polling polite.
    refetchInterval: 5_000,
    refetchIntervalInBackground: false,
  });

  if (isLoading) {
    return <p className="text-sm text-muted-foreground">Loading scans…</p>;
  }
  if (error) {
    return (
      <p className="text-sm text-severity-critical">
        Failed to load scans: {(error as Error).message}
      </p>
    );
  }
  if (!data || data.items.length === 0) {
    return (
      <div className="rounded-md border border-dashed py-10 text-center text-sm text-muted-foreground">
        No scans yet.{" "}
        <Link href="/scans/new" className="font-medium text-primary hover:underline">
          Start one
        </Link>
        .
      </div>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Target</TableHead>
          <TableHead>Type</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Started</TableHead>
          <TableHead className="text-right"></TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {data.items.map((scan) => (
          <TableRow key={scan.id}>
            <TableCell className="font-medium">
              <div>{scan.target_hostname ?? scan.target_ip}</div>
              {scan.target_hostname ? (
                <div className="font-mono text-xs text-muted-foreground">
                  {scan.target_ip}
                </div>
              ) : null}
            </TableCell>
            <TableCell className="capitalize">{scan.scan_type}</TableCell>
            <TableCell>
              <ScanStatusBadge status={scan.status} />
            </TableCell>
            <TableCell className="font-mono text-xs text-muted-foreground">
              {new Date(scan.started_at).toLocaleString()}
            </TableCell>
            <TableCell className="text-right">
              <Link
                href={
                  scan.status === "running" || scan.status === "queued"
                    ? `/scans/${scan.id}/live`
                    : `/scans/${scan.id}`
                }
                className="inline-flex items-center gap-1 text-sm font-medium text-primary hover:underline"
              >
                {scan.status === "running" || scan.status === "queued"
                  ? "Live"
                  : "View"}
                <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
