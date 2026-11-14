import { afterEach, describe, expect, it, vi } from "vite-plus/test";

import { EnhancementExit, domesticExit, exitMatches } from "./enhancement-exit.ts";

// Electron owns the proxy transport; the external IP service response is supplied per case.
const transport = vi.hoisted(() => ({
  setProxy: vi.fn().mockResolvedValue(undefined),
  closeAllConnections: vi.fn().mockResolvedValue(undefined),
  fetch: vi.fn(),
}));
vi.mock("electron", () => ({ session: { fromPartition: () => transport } }));
afterEach(() => {
  vi.clearAllMocks();
});
describe("enhancement exit proof", () => {
  it("parses only the service IPv4 and checks the allowlist, independent of country", () => {
    expect(domesticExit("当前 IP：1.1.1.1  来自于：测试地区")).toBe("1.1.1.1");
    expect(exitMatches("1.1.1.1", ["8.8.8.8"])).toBe(false);
    expect(exitMatches("1.1.1.1", ["8.8.8.8", "1.1.1.1"])).toBe(true);
    expect(() => domesticExit("上游网关 1.1.1.1")).toThrow();
    expect(() => domesticExit("当前 IP：127.0.0.1")).toThrow();
    expect(() => domesticExit("x".repeat(4097))).toThrow();
  });
  it("rejects the observed split-route shape and resumes after the sample matches", async () => {
    const changed = vi.fn(),
      proof = new EnhancementExit(changed);
    transport.fetch.mockResolvedValueOnce(new Response("当前 IP：1.1.1.1 来自于：测试地区"));
    expect(await proof.check(["8.8.8.8"], "http://127.0.0.1:38401", true)).toBe(false);
    expect(proof.state).toMatchObject({ phase: "blocked", currentIp: "1.1.1.1" });
    expect(proof.ready).toBe(false);
    transport.fetch.mockResolvedValueOnce(new Response("当前 IP：8.8.8.8 来自于：测试地区"));
    expect(await proof.check(["8.8.8.8"], "http://127.0.0.1:38401", true)).toBe(true);
    expect(proof.ready).toBe(true);
    proof.invalidate();
    expect(proof.ready).toBe(false);
  });
  it("discards a proof completed after the route was invalidated", async () => {
    const proof = new EnhancementExit(() => undefined);
    let finish: ((value: Response) => void) | undefined;
    transport.fetch.mockImplementationOnce(
      () =>
        new Promise<Response>((resolve) => {
          finish = resolve;
        }),
    );
    const pending = proof.check(["8.8.8.8"], "http://127.0.0.1:38401", true);
    await vi.waitFor(() => expect(finish).toBeTypeOf("function"));
    proof.invalidate();
    if (!finish) throw new Error("Missing pending query");
    finish(new Response("当前 IP：8.8.8.8 来自于：测试地区"));
    expect(await pending).toBe(false);
    expect(proof.ready).toBe(false);
  });
});
