import type { QueryClient } from "@tanstack/react-query";
import { HeadContent, Outlet, createRootRouteWithContext } from "@tanstack/react-router";
import { ThemeProvider } from "next-themes";

import { Toaster } from "@ip-guard/ui/components/sonner";

interface RouterContext {
  queryClient: QueryClient;
}

const RootLayout = () => (
  <ThemeProvider attribute="class" defaultTheme="system" scriptProps={{ type: "application/json" }}>
    <HeadContent />
    <Outlet />
    <Toaster richColors />
  </ThemeProvider>
);

export const Route = createRootRouteWithContext<RouterContext>()({
  head: () => ({
    meta: [{ title: "IP Guard · 公网 IPv4 守卫" }],
  }),
  component: RootLayout,
});
