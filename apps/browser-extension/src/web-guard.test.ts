import { readFileSync } from "node:fs";

import { afterEach, describe, expect, it, vi } from "vite-plus/test";

afterEach(() => {
  vi.clearAllTimers();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("Claude web-only protection", () => {
  it("limits its permissions and static rules to Claude webpages", () => {
    const manifest: unknown = JSON.parse(
      readFileSync(new URL("../manifest.json", import.meta.url), "utf8"),
    );
    expect(manifest).toHaveProperty("permissions", [
      "nativeMessaging",
      "declarativeNetRequest",
      "storage",
      "alarms",
    ]);
    expect(manifest).not.toHaveProperty("optional_permissions");
    expect(manifest).toHaveProperty("host_permissions", ["*://claude.ai/*", "*://*.claude.ai/*"]);
    const rules: unknown = JSON.parse(
      readFileSync(new URL("../public/rules.json", import.meta.url), "utf8"),
    );
    expect(rules).toEqual([
      {
        id: 1,
        priority: 10,
        action: { type: "block" },
        condition: { requestDomains: ["claude.ai"], initiatorDomains: ["claude.ai"] },
      },
      {
        id: 2,
        priority: 20,
        action: { type: "redirect", redirect: { extensionPath: "/blocked.html" } },
        condition: { requestDomains: ["claude.ai"], resourceTypes: ["main_frame"] },
      },
    ]);
  });

  it("blocks only Claude tabs, allows main-frame navigation after approval and revokes stale permission", async () => {
    vi.useFakeTimers();
    vi.resetModules();
    const listeners: { native?: (message: unknown) => void } = {};
    const updateRules = vi.fn(
      async (_options: chrome.declarativeNetRequest.UpdateRuleOptions) => undefined,
    );
    const updateTab = vi.fn(
      async (_id: number, _properties: chrome.tabs.UpdateProperties) => undefined,
    );
    const api = {
      runtime: {
        connectNative: vi.fn(() => ({
          onMessage: {
            addListener: (listener: (message: unknown) => void) => {
              listeners.native = listener;
            },
          },
          onDisconnect: { addListener: vi.fn() },
          disconnect: vi.fn(),
          postMessage: vi.fn(),
        })),
        onMessage: { addListener: vi.fn() },
        getManifest: () => ({ version: "0.13.4" }),
        getURL: (value: string) => `chrome-extension://fixture/${value}`,
      },
      // These Chrome APIs are external; no real profile, network or installed extension is touched.
      tabs: {
        query: vi.fn(async () => [
          { id: 1, url: "https://claude.ai/chat/example" },
          { id: 2, url: "https://example.org/" },
        ]),
        update: updateTab,
        onUpdated: { addListener: vi.fn() },
      },
      declarativeNetRequest: {
        updateSessionRules: updateRules,
        RuleActionType: { ALLOW: "allow" },
        ResourceType: {
          MAIN_FRAME: "main_frame",
          XMLHTTPREQUEST: "xmlhttprequest",
          WEBSOCKET: "websocket",
        },
      },
      storage: { session: { set: vi.fn(async () => undefined) } },
      action: {
        setBadgeText: vi.fn(async () => undefined),
        setBadgeBackgroundColor: vi.fn(async () => undefined),
        setTitle: vi.fn(async () => undefined),
      },
      alarms: { onAlarm: { addListener: vi.fn() }, create: vi.fn(async () => undefined) },
      get proxy() {
        throw new Error("web guard must leave browser proxy alone");
      },
      get management() {
        throw new Error("web guard must leave official extensions alone");
      },
      get privacy() {
        throw new Error("web guard must leave WebRTC alone");
      },
    };
    vi.stubGlobal("chrome", api);
    await import("./worker.ts");
    await vi.waitUntil(() => Boolean(listeners.native));
    expect(updateTab).toHaveBeenCalledWith(1, {
      url: "chrome-extension://fixture/blocked.html?target=https%3A%2F%2Fclaude.ai%2Fchat%2Fexample",
    });
    expect(updateTab.mock.calls.every(([id]) => id === 1)).toBe(true);
    const state = {
      protocol: 1,
      appVersion: "0.13.4",
      phase: "allowed",
      currentIp: "8.8.8.8",
      expectedIps: ["8.8.8.8"],
      checkedAt: new Date().toISOString(),
      reason: "IPv4 命中允许列表",
    };
    listeners.native?.(state);
    await vi.waitUntil(() =>
      updateRules.mock.calls.some(([rule]) => Boolean(rule?.addRules?.length)),
    );
    expect(updateRules).toHaveBeenLastCalledWith({
      removeRuleIds: [100],
      addRules: [
        {
          id: 100,
          priority: 1000,
          action: { type: "allow" },
          condition: {
            requestDomains: ["claude.ai"],
            resourceTypes: ["main_frame", "xmlhttprequest", "websocket"],
          },
        },
      ],
    });
    updateRules.mockClear();
    listeners.native?.({ ...state, phase: "blocked", currentIp: "1.1.1.1" });
    await vi.waitUntil(() => updateRules.mock.calls.some(([rule]) => rule?.addRules?.length === 0));
    expect(updateRules).toHaveBeenLastCalledWith({ removeRuleIds: [100], addRules: [] });
    listeners.native?.(state);
    await vi.waitUntil(() =>
      updateRules.mock.calls.some(([rule]) => Boolean(rule?.addRules?.length)),
    );
    updateRules.mockClear();
    await vi.advanceTimersByTimeAsync(4000);
    expect(updateRules).toHaveBeenLastCalledWith({ removeRuleIds: [100], addRules: [] });
  });
});
