"use client";

import { useQueries, useQuery } from "@tanstack/react-query";
import {
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import { SEVERITY_ORDER, type Severity } from "@/lib/types";
import { SEVERITY_STYLES } from "@/lib/severity";

/**
 * Severity-mix donut across all completed scans on the latest list page.
 *
 * Hydration strategy mirrors RiskSummary — fetch the latest scan list, then
 * detail-fetch each completed scan and reduce client-side. When everything
 * is zero we show a stub so the chart doesn't render as one full ring of a
 * single color.
 */
export function RiskChart() {
  const list = useQuery({
    queryKey: ["scans", { limit: 20 }],
    queryFn: () => api.listScans(20, 0),
    refetchInterval: 10_000,
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

  const counts: Record<Severity, number> = {
    Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0, Unknown: 0,
  };
  for (const q of details) {
    const d = q.data;
    if (!d) continue;
    for (const v of d.vulnerabilities) counts[v.severity] = (counts[v.severity] ?? 0) + 1;
    for (const w of d.web_findings) counts[w.severity] = (counts[w.severity] ?? 0) + 1;
  }

  const data = SEVERITY_ORDER.map((sev) => ({
    name: sev,
    value: counts[sev],
    color: SEVERITY_STYLES[sev].hsl,
  })).filter((d) => d.value > 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Findings by severity</CardTitle>
      </CardHeader>
      <CardContent className="h-64">
        {data.length === 0 ? (
          <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
            No findings yet.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={90}
                paddingAngle={2}
              >
                {data.map((d) => (
                  <Cell key={d.name} fill={d.color} stroke="none" />
                ))}
              </Pie>
              <Tooltip />
              <Legend verticalAlign="bottom" height={24} iconType="circle" />
            </PieChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
