"use client";

import { useQuery, useQueries } from "@tanstack/react-query";
import { ShieldCheck, Network, Bug, Globe } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { api } from "@/lib/api";

/**
 * Headline cards on the dashboard home.
 *
 * The list endpoint only returns scan summaries (no ports/vulns/web counts),
 * so the cards hydrate by fetching detail for each scan in the latest page
 * and reducing client-side. That's deliberate: the alternative is a backend
 * `/api/stats` endpoint, which Phase 6 doesn't have yet, and the cost is
 * bounded by the list page size.
 */
export function RiskSummary() {
  const list = useQuery({
    queryKey: ["scans", { limit: 20 }],
    queryFn: () => api.listScans(20, 0),
    refetchInterval: 5_000,
    refetchIntervalInBackground: false,
  });

  const details = useQueries({
    queries: (list.data?.items ?? [])
      .filter((s) => s.status === "completed")
      .map((s) => ({
        queryKey: ["scan", s.id],
        queryFn: () => api.getScan(s.id),
        staleTime: 30_000,
      })),
  });

  const totals = details.reduce(
    (acc, q) => {
      const d = q.data;
      if (!d) return acc;
      acc.scans += 1;
      acc.openPorts += d.ports.filter((p) => p.state === "open").length;
      acc.vulns += d.vulnerabilities.length;
      acc.web += d.web_findings.length;
      const criticals =
        d.vulnerabilities.filter((v) => v.severity === "Critical").length +
        d.web_findings.filter((w) => w.severity === "Critical").length;
      acc.critical += criticals;
      return acc;
    },
    { scans: 0, openPorts: 0, vulns: 0, web: 0, critical: 0 },
  );

  const cards = [
    {
      label: "Scans",
      value: list.data?.total ?? 0,
      icon: <ShieldCheck className="h-4 w-4" />,
    },
    {
      label: "Open ports",
      value: totals.openPorts,
      icon: <Network className="h-4 w-4" />,
    },
    {
      label: "Vulnerabilities",
      value: totals.vulns,
      icon: <Bug className="h-4 w-4" />,
      // Tint red if any criticals are in the mix.
      accent: totals.critical > 0 ? "text-severity-critical" : undefined,
    },
    {
      label: "Web findings",
      value: totals.web,
      icon: <Globe className="h-4 w-4" />,
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      {cards.map((c) => (
        <Card key={c.label}>
          <CardContent className="flex items-center justify-between gap-4 p-4">
            <div>
              <div className="text-xs uppercase tracking-wide text-muted-foreground">
                {c.label}
              </div>
              <div className={`text-2xl font-semibold ${c.accent ?? ""}`}>
                {c.value}
              </div>
            </div>
            <div className="rounded-md bg-muted p-2 text-muted-foreground">
              {c.icon}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
