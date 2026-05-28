import Link from "next/link";
import { Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScanList } from "@/components/scan-list";
import { RiskSummary } from "@/components/risk-summary";
import { RiskChart } from "@/components/risk-chart";

export default function DashboardHome() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Dashboard</h1>
          <p className="text-sm text-muted-foreground">
            Recent scans and risk summary across your targets.
          </p>
        </div>
        <Button asChild>
          <Link href="/scans/new">
            <Plus className="h-4 w-4" /> New scan
          </Link>
        </Button>
      </div>

      <RiskSummary />

      <div className="grid gap-6 md:grid-cols-3">
        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Recent scans</CardTitle>
          </CardHeader>
          <CardContent>
            <ScanList />
          </CardContent>
        </Card>
        <RiskChart />
      </div>
    </div>
  );
}
