import type { Snapshot } from "@ip-guard/electron";

export type ProtectionNotice = {
  kind: "ip_changed" | "ip_unavailable" | "guard_offline";
  apps: string[];
  currentIp: string;
  expectedIps: string[];
};
export function detectProtectionStop(
  previous: Snapshot | undefined,
  current: Snapshot,
  stopping: boolean,
): ProtectionNotice | undefined {
  if (
    stopping ||
    !previous?.running.length ||
    current.running.length ||
    current.ready ||
    !current.rulesLocked
  )
    return;
  const apps = previous.apps
    .filter((app) => previous.running.includes(app.id))
    .map((app) => app.name);
  if (!apps.length) return;
  return {
    kind: !current.online
      ? "guard_offline"
      : current.currentIp && !current.settings.expectedIps.includes(current.currentIp)
        ? "ip_changed"
        : "ip_unavailable",
    apps: [...new Set(apps)],
    currentIp: current.online ? current.currentIp : "",
    expectedIps: current.settings.expectedIps,
  };
}
