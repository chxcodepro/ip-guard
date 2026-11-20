import type { NotificationConstructorOptions } from "electron";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";

import {
  nativeVersion,
  claudeIpv4Endpoint,
  initialCommandProtection,
  initialStartupStatus,
} from "@ip-guard/electron";
import type { Snapshot } from "@ip-guard/electron";

import { ClaudeIPv4 } from "./claude-ip.ts";
import { Guardian } from "./guardian.ts";
import { ProtectionAlerts } from "./protection-alerts.ts";
import { detectProtectionEvent } from "./protection-event.ts";

type SystemNotice = {
  options: NotificationConstructorOptions;
  show: ReturnType<typeof vi.fn>;
  close: ReturnType<typeof vi.fn>;
  emit: (event: string) => boolean;
};
const notifications = vi.hoisted(() => {
  const items: SystemNotice[] = [];
  return { supported: true, items };
});
// Electron and the OS notification center are external; event detection and episode timing are real.
vi.mock("electron", async () => {
  const { EventEmitter } = await import("node:events");
  return {
    app: { isPackaged: false },
    Notification: class extends EventEmitter {
      static isSupported() {
        return notifications.supported;
      }
      options: NotificationConstructorOptions;
      show = vi.fn();
      close = vi.fn();
      constructor(options: NotificationConstructorOptions) {
        super();
        this.options = options;
        notifications.items.push(this);
      }
    },
  };
});

const running: Snapshot = {
  networkPolicy: {
    revision: "b0c7e969-e7e6-470f-9628-d9b82d8cc0ee",
    loopbackDirect: true,
    localPorts: [],
  },
  enhancementReady: false,
  enhancementReason: "等待增强出口复核",
  enhancementPhase: "idle",
  driver: initialCommandProtection,
  commandBlockId: "",
  commandBlockReason: "",
  commandBlockAppId: "",
  egress: null,
  online: true,
  admin: true,
  ready: true,
  checking: false,
  probe: { round: 1, attempt: 1, phase: "passed" },
  networkIssue: "idle",
  nativeVersion,
  ipSource: claudeIpv4Endpoint,
  currentIp: "8.8.8.8",
  adapter: "",
  lastChecked: "",
  reason: "",
  detection: "",
  running: ["2357f08c-f69f-4924-8fa0-8bf043019fd8"],
  otherModelRunning: [],
  autostart: false,
  startup: initialStartupStatus,
  rulesLocked: true,
  networkAdapters: [],
  watchedAdapter: { id: "", name: "", exists: false, up: false, ipv4: false, error: "" },
  networkAdapterId: "",
  settings: { expectedIps: ["8.8.8.8"], intervalSeconds: 2, ipv4Url: claudeIpv4Endpoint },
  logs: [],
  apps: [
    {
      id: "2357f08c-f69f-4924-8fa0-8bf043019fd8",
      name: "Claude",
      path: "C:\\Claude\\claude.exe",
      arguments: "",
      apiScope: "auto",
      enhanced: false,
      enabled: true,
      pathIssue: "",
      isClaudeCode: false,
    },
  ],
};
const paused: Snapshot = { ...running, ready: false, networkIssue: "ip_changed" };
const enhanced = (snapshot: Snapshot): Snapshot => ({
  ...snapshot,
  apps: snapshot.apps.map((app) => ({ ...app, enhanced: true })),
});
describe("quiet runtime protection alerts", () => {
  let guardian: Guardian;
  let alerts: ProtectionAlerts;
  const openMain = vi.fn();
  beforeEach(() => {
    vi.useFakeTimers();
    notifications.supported = true;
    notifications.items.length = 0;
    guardian = new Guardian(new ClaudeIPv4());
    alerts = new ProtectionAlerts(guardian, openMain);
    guardian.emit("snapshot", running);
  });
  afterEach(() => {
    alerts.stop();
    vi.useRealTimers();
    vi.clearAllMocks();
  });
  it("keeps a transient pause and its recovery silent, including basic sessions", () => {
    guardian.emit("snapshot", paused);
    vi.advanceTimersByTime(29999);
    guardian.emit("snapshot", running);
    vi.advanceTimersByTime(60000);
    expect(notifications.items).toHaveLength(0);
    expect(openMain).not.toHaveBeenCalled();
  });
  it("notifies once at thirty seconds across changing reasons, phases and retry rounds", () => {
    guardian.emit("snapshot", { ...paused, networkIssue: "checking" });
    vi.advanceTimersByTime(20000);
    guardian.emit("snapshot", {
      ...paused,
      networkIssue: "ip_unavailable",
      probe: { round: 2, attempt: 3, phase: "failed" },
    });
    vi.advanceTimersByTime(9999);
    expect(notifications.items).toHaveLength(0);
    vi.advanceTimersByTime(1);
    const notice = notifications.items[0];
    if (!notice) throw new Error("Missing prolonged-outage notification");
    expect(notice.options).toMatchObject({ silent: true });
    expect(notice.options.body).toContain("程序保持运行");
    expect(openMain).not.toHaveBeenCalled();
    notice.emit("close");
    guardian.emit("snapshot", { ...paused, networkIssue: "checking" });
    vi.advanceTimersByTime(120000);
    expect(notifications.items).toHaveLength(1);
    notice.emit("click");
    expect(openMain).toHaveBeenCalledTimes(1);
    guardian.emit("snapshot", running);
    expect(notice.close).toHaveBeenCalledTimes(1);
    guardian.emit("snapshot", paused);
    vi.advanceTimersByTime(30000);
    expect(notifications.items).toHaveLength(2);
  });
  it("treats an enhanced-only outage as one episode while the base IPv4 remains healthy", () => {
    guardian.emit("snapshot", enhanced({ ...running, enhancementReady: true }));
    guardian.emit("snapshot", enhanced(running));
    vi.advanceTimersByTime(20000);
    guardian.emit("snapshot", enhanced({ ...running, enhancementPhase: "failed" }));
    vi.advanceTimersByTime(10000);
    expect(notifications.items).toHaveLength(1);
    guardian.emit("snapshot", enhanced({ ...running, enhancementReady: true }));
    expect(notifications.items[0]?.close).toHaveBeenCalledTimes(1);
  });
  it("cancels the timer when affected sessions end, even if an unrelated session remains", () => {
    guardian.emit("snapshot", enhanced(running));
    vi.advanceTimersByTime(29999);
    const app = running.apps[0];
    if (!app) throw new Error("Missing app fixture");
    guardian.emit("snapshot", {
      ...running,
      apps: [...enhanced(running).apps, { ...app, id: "other" }],
      running: ["other"],
    });
    vi.advanceTimersByTime(60000);
    expect(notifications.items).toHaveLength(0);
  });
  it("prioritizes an immediate command failure and reports a surviving main program", () => {
    guardian.emit("snapshot", enhanced(running));
    const blocked = enhanced({
      ...running,
      commandBlockId: "event-1",
      commandBlockAppId: running.running[0] ?? "",
      commandBlockReason: "child metadata rejected",
    });
    guardian.emit("snapshot", blocked);
    expect(notifications.items).toHaveLength(1);
    expect(notifications.items[0]?.options.body).toContain("主程序仍在运行");
    guardian.emit("snapshot", { ...blocked, enhancementReady: true });
    vi.advanceTimersByTime(60000);
    expect(notifications.items).toHaveLength(1);
  });
  it("notifies once for a dedicated-core exit and re-arms only after route recovery", () => {
    guardian.snapshot = enhanced(running);
    guardian.emit("snapshot", guardian.snapshot);
    alerts.notifyProxyCoreFailure();
    alerts.notifyProxyCoreFailure();
    guardian.emit("snapshot", enhanced({ ...running, ready: false, enhancementReady: false }));
    vi.advanceTimersByTime(30000);
    expect(notifications.items).toHaveLength(1);
    expect(notifications.items[0]?.options.body).toContain("增强联网已暂停");
    alerts.resetProxyCoreFailure();
    alerts.notifyProxyCoreFailure();
    expect(notifications.items).toHaveLength(2);
  });
  it.each(["guard_offline", "enforcement_failed"] as const)(
    "reports %s immediately once and retains the critical notification after session cleanup",
    (kind) => {
      const stopped: Snapshot = {
        ...paused,
        online: kind !== "guard_offline",
        networkIssue: kind === "enforcement_failed" ? kind : "idle",
        running: [],
      };
      guardian.emit("snapshot", stopped);
      guardian.emit("snapshot", { ...stopped });
      vi.advanceTimersByTime(60000);
      expect(notifications.items).toHaveLength(1);
      expect(notifications.items[0]?.close).not.toHaveBeenCalled();
      expect(notifications.items[0]?.options.body).not.toContain("主程序仍在运行");
    },
  );
  it("suppresses manual operations, unsupported system notifications and late callbacks on quit", () => {
    expect(detectProtectionEvent(running, paused, true)).toBeUndefined();
    guardian.emit("snapshot", paused);
    guardian.emit("snapshot", { ...paused, rulesLocked: false });
    vi.advanceTimersByTime(30000);
    expect(notifications.items).toHaveLength(0);
    notifications.supported = false;
    const warning = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    guardian.emit("snapshot", paused);
    vi.advanceTimersByTime(30000);
    expect(notifications.items).toHaveLength(0);
    expect(warning).toHaveBeenCalledTimes(1);
    warning.mockRestore();
    notifications.supported = true;
    guardian.emit("snapshot", running);
    guardian.emit("snapshot", paused);
    alerts.stop();
    vi.advanceTimersByTime(60000);
    expect(notifications.items).toHaveLength(0);
    expect(guardian.listenerCount("snapshot")).toBe(0);
  });
});
