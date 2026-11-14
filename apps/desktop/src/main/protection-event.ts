import type { Snapshot } from "@ip-guard/electron";

export type ProtectionNotice = {
  kind:
    | "ip_changed"
    | "ip_unavailable"
    | "network_restored"
    | "guard_offline"
    | "enforcement_failed";
  detail?: string;
  apps: string[];
  currentIp: string;
  expectedIps: string[];
  probe: Snapshot["probe"];
};
export function detectProtectionEvent(
  previous: Snapshot | undefined,
  current: Snapshot,
  stopping: boolean,
): ProtectionNotice | undefined {
  if (!stopping && previous && current.online && current.rulesLocked) {
    const failed =
      ["blocked", "failed"].includes(current.enhancementPhase) &&
      current.enhancementPhase !== previous.enhancementPhase;
    const resumed =
      current.enhancementReady &&
      !previous.enhancementReady &&
      ["blocked", "failed"].includes(previous.enhancementPhase);
    const apps = current.apps
      .filter((app) => app.enhanced && current.running.includes(app.id))
      .map((app) => app.name);
    if (apps.length && (failed || resumed))
      return {
        kind: resumed
          ? "network_restored"
          : current.enhancementPhase === "blocked"
            ? "ip_changed"
            : "ip_unavailable",
        detail: current.enhancementReason,
        apps,
        currentIp: "",
        expectedIps: current.settings.expectedIps,
        probe: { round: 0, attempt: 0, phase: "idle" },
      };
  }
  if (
    !stopping &&
    previous &&
    current.commandBlockId &&
    current.commandBlockId !== previous.commandBlockId
  ) {
    const app = current.apps.find((item) => item.id === current.commandBlockAppId);
    if (app)
      return {
        kind: "enforcement_failed",
        detail: current.commandBlockReason,
        apps: [app.name],
        currentIp: current.currentIp,
        expectedIps: current.settings.expectedIps,
        probe: current.probe,
      };
  }
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
    probe: current.probe,
  };
}
