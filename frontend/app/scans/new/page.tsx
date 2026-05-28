"use client";

import { useMutation } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { api } from "@/lib/api";
import type { ScanCreateBody, ScanType } from "@/lib/types";

/**
 * New-scan form. Submits to POST /api/scans and navigates to the live view
 * as soon as the row is created (the background executor will flip the row
 * to running and start streaming events).
 */
export default function NewScanPage() {
  const router = useRouter();
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState<ScanType>("port");
  const [ports, setPorts] = useState("1-1024");
  const [timeout, setTimeoutValue] = useState("1.0");
  const [concurrency, setConcurrency] = useState("500");
  const [nvd, setNvd] = useState(false);

  const mutation = useMutation({
    mutationFn: (body: ScanCreateBody) => api.createScan(body),
    onSuccess: (scan) => {
      router.push(`/scans/${scan.id}/live`);
    },
  });

  const showPortFields = scanType !== "web";
  const showVulnFields = scanType === "vuln" || scanType === "full";

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const options: Record<string, unknown> = {};
    if (showPortFields) {
      options.ports = ports.trim() || undefined;
      options.timeout = Number(timeout);
      options.concurrency = Number(concurrency);
    }
    if (showVulnFields) {
      options.nvd = nvd;
    }
    mutation.mutate({
      target: target.trim(),
      scan_type: scanType,
      options: Object.keys(options).length ? options : undefined,
    });
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Start a new scan</h1>
        <p className="text-sm text-muted-foreground">
          Pick a target and a scan type. Live progress will stream once the
          backend picks it up.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Scan parameters</CardTitle>
          <CardDescription>
            Hostnames are resolved server-side before scanning.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="target">Target IP or hostname</Label>
              <Input
                id="target"
                placeholder="example.com or 192.0.2.10"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                required
              />
            </div>

            <div className="space-y-1.5">
              <Label>Scan type</Label>
              <Select
                value={scanType}
                onValueChange={(v) => setScanType(v as ScanType)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="port">Port scan</SelectItem>
                  <SelectItem value="vuln">Vulnerability scan</SelectItem>
                  <SelectItem value="web">Web security scan</SelectItem>
                  <SelectItem value="full">Full scan (port + vuln + web)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {showPortFields ? (
              <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                <div className="space-y-1.5">
                  <Label htmlFor="ports">Ports</Label>
                  <Input
                    id="ports"
                    placeholder="1-1024 or 80,443"
                    value={ports}
                    onChange={(e) => setPorts(e.target.value)}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="timeout">Timeout (s)</Label>
                  <Input
                    id="timeout"
                    type="number"
                    step="0.1"
                    min="0.1"
                    value={timeout}
                    onChange={(e) => setTimeoutValue(e.target.value)}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="concurrency">Concurrency</Label>
                  <Input
                    id="concurrency"
                    type="number"
                    min="1"
                    value={concurrency}
                    onChange={(e) => setConcurrency(e.target.value)}
                  />
                </div>
              </div>
            ) : null}

            {showVulnFields ? (
              <div className="flex items-center gap-2 rounded-md border bg-muted/30 p-3 text-sm">
                <input
                  id="nvd"
                  type="checkbox"
                  checked={nvd}
                  onChange={(e) => setNvd(e.target.checked)}
                  className="h-4 w-4 rounded border-input"
                />
                <Label htmlFor="nvd" className="cursor-pointer font-normal">
                  Also query the live NVD API (needs NVD_API_KEY on the backend
                  for sane rate limits).
                </Label>
              </div>
            ) : null}

            {mutation.error ? (
              <p className="text-sm text-severity-critical">
                {(mutation.error as Error).message}
              </p>
            ) : null}

            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" /> Queuing…
                </>
              ) : (
                "Start scan"
              )}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
