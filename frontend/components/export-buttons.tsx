"use client";

import { Download, FileJson, FileText, FileType, FileSpreadsheet } from "lucide-react";
import { Button } from "@/components/ui/button";
import { exportURL } from "@/lib/api";

const FORMATS: Array<{
  fmt: "json" | "csv" | "html" | "pdf";
  label: string;
  icon: React.ReactNode;
}> = [
  { fmt: "json", label: "JSON", icon: <FileJson className="h-4 w-4" /> },
  { fmt: "csv", label: "CSV", icon: <FileSpreadsheet className="h-4 w-4" /> },
  { fmt: "html", label: "HTML", icon: <FileText className="h-4 w-4" /> },
  { fmt: "pdf", label: "PDF", icon: <FileType className="h-4 w-4" /> },
];

/**
 * Per-scan report download buttons. Each is a plain anchor pointed at the
 * backend export endpoint so the browser handles the download natively —
 * no fetch + blob shuffling needed.
 *
 * HTML opens in a new tab (the backend serves it inline by default) while
 * JSON/CSV/PDF come back with Content-Disposition: attachment.
 */
export function ExportButtons({ scanId }: { scanId: string }) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="mr-1 inline-flex items-center gap-1 text-xs uppercase tracking-wide text-muted-foreground">
        <Download className="h-3.5 w-3.5" /> Report
      </span>
      {FORMATS.map((f) => (
        <Button
          key={f.fmt}
          asChild
          variant="outline"
          size="sm"
        >
          <a
            href={exportURL(scanId, f.fmt)}
            target={f.fmt === "html" ? "_blank" : undefined}
            rel={f.fmt === "html" ? "noopener noreferrer" : undefined}
          >
            {f.icon}
            {f.label}
          </a>
        </Button>
      ))}
    </div>
  );
}
