import type { Snapshot } from "@ip-guard/electron";

export type ProtectionNotice = {
  kind:
    | "ip_changed"
    | "ip_unavailable"
    | "network_restored"
    | "guard_offline"
    | "enforcement_failed";
  apps: string[];
  currentIp: string;
  expectedIps: string[];
};
export function detectProtectionEvent(
  previous: Snapshot | undefined,
  current: Snapshot,
  stopping: boolean,
): ProtectionNotice | undefined {
  if (stopping || !previous?.running.length || !current.rulesLocked) return;
  const stopped = !current.online || current.networkIssue === "enforcement_failed";
  const recovered =
    current.ready &&
    !previous.ready &&
    ["ip_changed", "ip_unavailable"].includes(previous.networkIssue);
  const blocked =
    !current.ready &&
    ["ip_changed", "ip_unavailable"].includes(current.networkIssue) &&
    previous.networkIssue !== current.networkIssue;
  if (!stopped && !recovered && !blocked) return;
  if (stopped && current.running.length) return;
  const apps = (stopped ? previous : current).apps
    .filter((app) => (stopped ? previous : current).running.includes(app.id))
    .map((app) => app.name);
  if (!apps.length) return;
  return {
    kind: !current.online
      ? "guard_offline"
      : current.networkIssue === "enforcement_failed"
        ? "enforcement_failed"
        : recovered
          ? "network_restored"
          : current.networkIssue === "ip_changed"
            ? "ip_changed"
            : "ip_unavailable",
    apps: [...new Set(apps)],
    currentIp: current.online ? current.currentIp : "",
    expectedIps: current.settings.expectedIps,
  };
}
