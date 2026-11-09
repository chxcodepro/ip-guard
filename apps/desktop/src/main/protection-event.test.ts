import { describe, expect, it } from "vite-plus/test";

import { nativeVersion, claudeIpv4Endpoint } from "@ip-guard/electron";
import type { Snapshot } from "@ip-guard/electron";

import { detectProtectionEvent } from "./protection-event.ts";

const running: Snapshot = {
  online: true,
  admin: true,
  ready: true,
  checking: false,
  networkIssue: "idle",
  nativeVersion,
  ipSource: claudeIpv4Endpoint,
  currentIp: "8.8.8.8",
  adapter: "",
  lastChecked: "",
  reason: "",
  detection: "",
  running: ["2357f08c-f69f-4924-8fa0-8bf043019fd8"],
  autostart: false,
  rulesLocked: true,
  networkAdapters: [],
  watchedAdapter: { id: "", name: "", exists: false, up: false, ipv4: false, error: "" },
  networkAdapterId: "",
  settings: { expectedIps: ["8.8.8.8"], intervalSeconds: 2 },
  logs: [],
  apps: [
    {
      id: "2357f08c-f69f-4924-8fa0-8bf043019fd8",
      name: "Claude",
      path: "C:\\Claude\\claude.exe",
      arguments: "",
      enabled: true,
      pathIssue: "",
    },
  ],
};
describe("network-only protection notices", () => {
  const paused: Snapshot = {
    ...running,
    ready: false,
    networkIssue: "ip_changed",
    currentIp: "1.1.1.1",
  };
  it("reports a blocked connection while the same process remains running", () => {
    expect(detectProtectionEvent(running, paused, false)?.kind).toBe("ip_changed");
    expect(detectProtectionEvent(paused, { ...paused, checking: true }, false)).toBeUndefined();
    expect(detectProtectionEvent(paused, { ...paused }, false)).toBeUndefined();
  });
  it("keeps transient rechecks quiet and reports recovery after a confirmed outage", () => {
    const checking: Snapshot = {
      ...running,
      ready: false,
      checking: true,
      networkIssue: "checking",
    };
    expect(detectProtectionEvent(running, checking, false)).toBeUndefined();
    expect(detectProtectionEvent(checking, running, false)).toBeUndefined();
    expect(detectProtectionEvent(paused, running, false)?.kind).toBe("network_restored");
  });
  it("distinguishes a guard failure and suppresses manual operations", () => {
    expect(
      detectProtectionEvent(running, { ...paused, online: false, running: [] }, false)?.kind,
    ).toBe("guard_offline");
    expect(
      detectProtectionEvent(
        running,
        { ...paused, networkIssue: "enforcement_failed", running: [] },
        false,
      )?.kind,
    ).toBe("enforcement_failed");
    expect(
      detectProtectionEvent(running, { ...paused, rulesLocked: false }, false),
    ).toBeUndefined();
    expect(detectProtectionEvent(running, paused, true)).toBeUndefined();
    expect(detectProtectionEvent(running, { ...running, running: [] }, false)).toBeUndefined();
  });
});
