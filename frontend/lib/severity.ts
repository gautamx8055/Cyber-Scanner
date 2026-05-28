import type { Severity } from "./types";

/**
 * Per-severity Tailwind classes — central so a future palette tweak only
 * touches this file. `bg` is the solid background (badges, pie slices);
 * `text` is the foreground when used on neutral cards.
 */
export const SEVERITY_STYLES: Record<
  Severity,
  { bg: string; text: string; hsl: string }
> = {
  Critical: {
    bg: "bg-severity-critical text-white",
    text: "text-severity-critical",
    hsl: "hsl(var(--severity-critical))",
  },
  High: {
    bg: "bg-severity-high text-white",
    text: "text-severity-high",
    hsl: "hsl(var(--severity-high))",
  },
  Medium: {
    bg: "bg-severity-medium text-white",
    text: "text-severity-medium",
    hsl: "hsl(var(--severity-medium))",
  },
  Low: {
    bg: "bg-severity-low text-white",
    text: "text-severity-low",
    hsl: "hsl(var(--severity-low))",
  },
  Info: {
    bg: "bg-severity-info text-white",
    text: "text-severity-info",
    hsl: "hsl(var(--severity-info))",
  },
  Unknown: {
    bg: "bg-severity-unknown text-white",
    text: "text-severity-unknown",
    hsl: "hsl(var(--severity-unknown))",
  },
};
