import { createFileRoute } from "@tanstack/react-router";

import { GuardApp } from "#src/components/guard-app.tsx";

export const Route = createFileRoute("/")({
  component: GuardApp,
});
