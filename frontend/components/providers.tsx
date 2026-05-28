"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";

/**
 * TanStack Query provider. Kept as a separate client component so the root
 * layout can stay a server component — only the QueryClient hydration
 * boundary needs "use client".
 */
export function Providers({ children }: { children: React.ReactNode }) {
  // useState ensures a single QueryClient per browser tab, even across React
  // 18 strict-mode double renders.
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            // Scan history doesn't need millisecond freshness; default is too
            // aggressive (0ms). A 5s window is enough to dedupe a navigation
            // round-trip without showing stale data for long.
            staleTime: 5_000,
            refetchOnWindowFocus: false,
          },
        },
      }),
  );

  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}
