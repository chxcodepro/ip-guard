import { describe, expect, it, vi } from "vite-plus/test";

import { browserExtensionId, nativeVersion } from "@ip-guard/electron";

vi.mock("electron", () => ({ dialog: {} }));
import { hasLegacyBrowserGuard } from "./browser-recovery.ts";

describe("legacy browser recovery prompt", () => {
  it("identifies enabled protection versions and ignores removed, disabled and web-only installations", () => {
    const preferences = (state: number, version: string) => ({
      extensions: { settings: { [browserExtensionId]: { state, manifest: { version } } } },
    });
    expect(hasLegacyBrowserGuard(preferences(1, "0.13.2"))).toBe(true);
    expect(hasLegacyBrowserGuard(preferences(1, "0.11.0"))).toBe(true);
    expect(hasLegacyBrowserGuard(preferences(0, "0.13.2"))).toBe(false);
    expect(hasLegacyBrowserGuard(preferences(1, nativeVersion))).toBe(false);
    expect(hasLegacyBrowserGuard(preferences(1, "0.13.3"))).toBe(true);
    expect(hasLegacyBrowserGuard(preferences(1, "0.13.4"))).toBe(true);
    expect(hasLegacyBrowserGuard(preferences(1, "0.14.1"))).toBe(false);
    expect(hasLegacyBrowserGuard(preferences(1, "invalid"))).toBe(false);
    expect(
      hasLegacyBrowserGuard({ extensions: { settings: { [browserExtensionId]: { state: 1 } } } }),
    ).toBe(false);
    expect(
      hasLegacyBrowserGuard({
        extensions: {
          settings: {
            [browserExtensionId]: {
              state: 1,
              manifest: { version: nativeVersion, permissions: ["proxy"] },
            },
          },
        },
      }),
    ).toBe(true);
    expect(
      hasLegacyBrowserGuard({
        extensions: {
          settings: {
            [browserExtensionId]: { state: 1, manifest: { optional_permissions: ["management"] } },
          },
        },
      }),
    ).toBe(true);
    expect(
      hasLegacyBrowserGuard({ extensions: { settings: { "other-extension": { state: 1 } } } }),
    ).toBe(false);
    expect(hasLegacyBrowserGuard({})).toBe(false);
  });
  it("reports unreadable ownership records rather than treating them as a successful restoration", () => {
    expect(() =>
      hasLegacyBrowserGuard({ extensions: { settings: { [browserExtensionId]: "broken" } } }),
    ).toThrow();
  });
});
