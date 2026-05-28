import { cn } from "@/lib/utils";
import type { ScanStatus } from "@/lib/types";

const STATUS_STYLES: Record<ScanStatus, string> = {
  queued: "bg-muted text-muted-foreground",
  running: "bg-primary/15 text-primary",
  completed: "bg-severity-low/15 text-severity-low",
  failed: "bg-severity-critical/15 text-severity-critical",
};

export function ScanStatusBadge({
  status,
  className,
}: {
  status: ScanStatus;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-semibold capitalize",
        STATUS_STYLES[status] ?? STATUS_STYLES.queued,
        className,
      )}
    >
      {status}
    </span>
  );
}
