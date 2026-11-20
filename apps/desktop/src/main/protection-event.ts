import type { Snapshot } from "@ip-guard/electron";

export type ProtectionNotice = {
  kind: "paused" | "guard_offline" | "enforcement_failed" | "proxy_core_failed";
  apps: { id: string; name: string }[];
  mainRunning: boolean;
};
export function detectProtectionEvent(
  previous: Snapshot | undefined,
  current: Snapshot,
  stopping: boolean,
): ProtectionNotice | undefined {
  if (stopping || !current.rulesLocked) return;
  if (previous && current.commandBlockId && current.commandBlockId !== previous.commandBlockId) {
    const app = current.apps.find((item) => item.id === current.commandBlockAppId);
    if (app)
      return {
        kind: "enforcement_failed",
        apps: [{ id: app.id, name: app.name }],
        mainRunning: current.running.includes(app.id),
      };
  }
  if (
    previous?.running.length &&
    ((!current.online && previous.online) ||
      (current.networkIssue === "enforcement_failed" &&
        previous.networkIssue !== "enforcement_failed"))
  )
    return {
      kind: current.online ? "enforcement_failed" : "guard_offline",
      apps: previous.apps
        .filter((app) => previous.running.includes(app.id))
        .map(({ id, name }) => ({ id, name })),
      mainRunning: previous.running.some((id) => current.running.includes(id)),
    };
  if (!current.rulesLocked || !current.online || current.networkIssue === "enforcement_failed")
    return;
  const apps = current.apps
    .filter(
      (app) =>
        current.running.includes(app.id) &&
        (!current.ready || (app.enhanced && !current.enhancementReady)),
    )
    .map(({ id, name }) => ({ id, name }));
  if (!apps.length) return;
  return { kind: "paused", apps, mainRunning: true };
}
