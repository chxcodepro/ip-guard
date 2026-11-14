import { describe, expect, it } from "vite-plus/test";

import {
  nativeVersion,
  claudeIpv4Endpoint,
  initialCommandProtection,
  initialStartupStatus,
} from "@ip-guard/electron";
import type { Snapshot } from "@ip-guard/electron";

import { detectProtectionEvent } from "./protection-event.ts";

const running: Snapshot = {
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
  settings: { expectedIps: ["8.8.8.8"], intervalSeconds: 2 },
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
describe("network-only protection notices", () => {
  it("reports split egress only for enhanced sessions and keeps basic programs running", () => {
    const enhanced: Snapshot = {
      ...running,
      enhancementReady: true,
      enhancementPhase: "passed",
      apps: running.apps.map((app) => ({ ...app, enhanced: true })),
    };
    const blocked: Snapshot = {
      ...enhanced,
      enhancementReady: false,
      enhancementPhase: "blocked",
      enhancementReason: "国内查询出口未命中允许列表",
    };
    expect(detectProtectionEvent(enhanced, blocked, false)).toMatchObject({
      kind: "ip_changed",
      apps: ["Claude"],
      detail: "国内查询出口未命中允许列表",
    });
    expect(blocked.ready).toBe(true);
    expect(blocked.running).toEqual(enhanced.running);
    expect(detectProtectionEvent(blocked, enhanced, false)?.kind).toBe("network_restored");
    expect(
      detectProtectionEvent(enhanced, { ...blocked, apps: running.apps }, false),
    ).toBeUndefined();
  });
  it("reports a metadata-blocked child without claiming unrelated apps stopped", () => {
    const blocked = {
      ...running,
      commandBlockId: "first",
      commandBlockAppId: "2357f08c-f69f-4924-8fa0-8bf043019fd8",
      commandBlockReason: "子进程缺少可核验元数据",
    };
    expect(detectProtectionEvent(running, blocked, false)).toMatchObject({
      kind: "enforcement_failed",
      apps: ["Claude"],
      detail: "子进程缺少可核验元数据",
    });
    expect(detectProtectionEvent(blocked, { ...blocked }, false)).toBeUndefined();
  });
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
  it("opens after the failed third attempt and includes the exact batch counters", () => {
    const first: Snapshot = {
      ...running,
      ready: false,
      checking: true,
      networkIssue: "checking",
      probe: { round: 1, attempt: 1, phase: "checking" },
    };
    const second: Snapshot = { ...first, probe: { round: 1, attempt: 2, phase: "checking" } };
    const third: Snapshot = {
      ...first,
      checking: false,
      networkIssue: "ip_unavailable",
      probe: { round: 1, attempt: 3, phase: "failed" },
    };
    expect(detectProtectionEvent(running, first, false)).toBeUndefined();
    expect(detectProtectionEvent(first, second, false)).toBeUndefined();
    expect(detectProtectionEvent(second, third, false)?.probe).toEqual({
      round: 1,
      attempt: 3,
      phase: "failed",
    });
    expect(
      detectProtectionEvent(
        third,
        { ...third, checking: true, probe: { round: 2, attempt: 1, phase: "checking" } },
        false,
      ),
    ).toBeUndefined();
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
