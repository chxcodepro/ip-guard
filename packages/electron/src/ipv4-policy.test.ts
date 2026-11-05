import { describe, expect, it } from "vite-plus/test";

import { browserStateSchema, settingsSchema } from "./index.ts";

describe("IPv4 allowlist", () => {
  const settings = { expectedIps: ["8.8.8.8", "1.1.1.1"], intervalSeconds: 2 };
  it("locks multiple public addresses and rejects invalid rules", () => {
    expect(settingsSchema.parse(settings)).toEqual(settings);
    for (const expectedIps of [
      [],
      ["10.0.0.1"],
      ["::1"],
      ["invalid"],
      ["8.8.8.8", "8.8.8.8"],
      Array(33).fill("8.8.8.8"),
    ])
      expect(settingsSchema.safeParse({ ...settings, expectedIps }).success).toBe(false);
  });
  it("accepts any listed address, including the second, and rejects an unlisted one", () => {
    const state = {
      protocol: 1,
      appVersion: "0.9.7",
      phase: "allowed",
      checkedAt: "",
      reason: "",
      expectedIps: settings.expectedIps,
    };
    for (const currentIp of settings.expectedIps)
      expect(browserStateSchema.parse({ ...state, currentIp }).expectedIps).toEqual(
        settings.expectedIps,
      );
    expect(browserStateSchema.safeParse({ ...state, currentIp: "9.9.9.9" }).success).toBe(false);
    expect(browserStateSchema.safeParse({ ...state, currentIp: "" }).success).toBe(false);
  });
  it("reads deployed protocol-1 hosts without weakening a supplied list", () => {
    const state = {
      protocol: 1,
      appVersion: "0.9.6",
      phase: "allowed",
      checkedAt: "",
      reason: "",
      currentIp: "1.1.1.1",
      expectedIp: "1.1.1.1",
    };
    expect(browserStateSchema.parse(state).expectedIps).toEqual(["1.1.1.1"]);
    expect(browserStateSchema.safeParse({ ...state, expectedIps: ["8.8.8.8"] }).success).toBe(
      false,
    );
  });
});
