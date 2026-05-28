import { cn } from "@/lib/utils";
import { SEVERITY_STYLES } from "@/lib/severity";
import type { Severity } from "@/lib/types";

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

/**
 * Renders a severity label as a solid pill matching the PDF report's
 * color scheme. Falls back to "Unknown" when the backend sends a label we
 * don't recognize — keeps the UI safe to point at a future backend that
 * adds a new severity tier.
 */
export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const style = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.Unknown;
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold",
        style.bg,
        className,
      )}
    >
      {severity}
    </span>
  );
}
