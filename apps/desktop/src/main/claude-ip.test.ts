import { afterEach, describe, expect, it, vi } from "vite-plus/test";

import { claudeIpv4Endpoint } from "@ip-guard/electron";

import { ClaudeIPv4 } from "./claude-ip.ts";

// Electron and the remote services are external; the real producer, parser and per-source request ownership run here.
const fetches = vi.hoisted(() =>
  vi.fn(
    async (url: string) =>
      new Response(
        url === "https://api.ipify.org/?format=json"
          ? '{"ip":"8.8.8.8"}'
          : "h=claude.ai\nip=1.1.1.1\n",
      ),
  ),
);
vi.mock("electron", () => ({
  session: {
    fromPartition: () => ({
      fetch: fetches,
      setProxy: vi.fn().mockResolvedValue(undefined),
      closeAllConnections: vi.fn().mockResolvedValue(undefined),
      resolveProxy: vi.fn().mockResolvedValue("DIRECT"),
      resolveHost: vi.fn().mockResolvedValue({ endpoints: [{ address: "8.8.8.8" }] }),
    }),
  },
}));
afterEach(() => vi.clearAllMocks());

describe("selected IPv4 source", () => {
  it("merges concurrent requests only for the same source", async () => {
    const probe = new ClaudeIPv4("ip-guard-source-fixture");
    try {
      const first = probe.check("https://api.ipify.org/?format=json");
      expect(probe.check("https://api.ipify.org/?format=json")).toBe(first);
      const other = probe.check(claudeIpv4Endpoint);
      const [ipify, claude] = await Promise.all([first, other]);
      expect(ipify).toMatchObject({
        sourceUrl: "https://api.ipify.org/?format=json",
        ip: "8.8.8.8",
        error: "",
      });
      expect(claude).toMatchObject({ sourceUrl: claudeIpv4Endpoint, ip: "1.1.1.1", error: "" });
      expect(fetches).toHaveBeenCalledTimes(2);
      expect(probe.latest(claudeIpv4Endpoint)?.ip).toBe("1.1.1.1");
      expect(probe.latest("https://api.ipify.org/?format=json")?.ip).toBe("8.8.8.8");
      expect(
        probe.steps(claudeIpv4Endpoint).every((step) => step.sourceUrl === claudeIpv4Endpoint),
      ).toBe(true);
    } finally {
      probe.stop();
    }
  });
});
