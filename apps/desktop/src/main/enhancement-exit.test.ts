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
  transport.fetch.mockReset();
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
    transport.fetch.mockResolvedValueOnce(new Response("当前 IP：8.8.8.8 来自于：测试地区"));
    expect(await proof.check(["8.8.8.8"], "http://127.0.0.1:38401", true)).toBe(true);
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
    expect(proof.ready).toBe(false);
    if (!finish) throw new Error("Missing pending query");
    finish(new Response("当前 IP：8.8.8.8 来自于：测试地区"));
    expect(await pending).toBe(false);
    expect(proof.ready).toBe(false);
  });
  it("keeps an unexpired same-route proof through a temporary lookup failure", async () => {
    const proof = new EnhancementExit(() => undefined);
    const clock = vi.spyOn(Date, "now");
    let pending: Promise<boolean> | undefined;
    try {
      transport.fetch.mockResolvedValueOnce(new Response("当前 IP：8.8.8.8 来自于：测试地区"));
      expect(await proof.check(["8.8.8.8"], "http://127.0.0.1:38401", true)).toBe(true);
      const checkedAt = proof.state.checkedAt;
      clock.mockReturnValue(Date.parse(checkedAt) + 5000);
      transport.fetch.mockRejectedValueOnce(new Error("Temporary IP service timeout"));
      transport.fetch.mockResolvedValueOnce(new Response("当前 IP：8.8.8.8 来自于：测试地区"));
      pending = proof.check(["8.8.8.8"], "http://127.0.0.1:38401", true);
      await vi.waitFor(() => expect(transport.fetch).toHaveBeenCalledTimes(2));
      expect(proof.ready).toBe(true);
      expect(proof.state).toMatchObject({ phase: "passed", checkedAt, currentIp: "8.8.8.8" });
      clock.mockRestore();
      expect(await pending).toBe(true);
    } finally {
      clock.mockRestore();
      proof.stop();
      await pending;
    }
  });
  it("does not extend the fifteen-second proof deadline while retrying", async () => {
    const proof = new EnhancementExit(() => undefined);
    const clock = vi.spyOn(Date, "now");
    let pending: Promise<boolean> | undefined;
    try {
      transport.fetch.mockResolvedValueOnce(new Response("当前 IP：8.8.8.8 来自于：测试地区"));
      expect(await proof.check(["8.8.8.8"], "http://127.0.0.1:38401", true)).toBe(true);
      const verifiedAt = Date.parse(proof.state.checkedAt);
      clock.mockReturnValue(verifiedAt + 5000);
      transport.fetch.mockRejectedValueOnce(new Error("Temporary IP service timeout"));
      pending = proof.check(["8.8.8.8"], "http://127.0.0.1:38401", true);
      await vi.waitFor(() => expect(transport.fetch).toHaveBeenCalledTimes(2));
      clock.mockReturnValue(verifiedAt + 14999);
      expect(proof.ready).toBe(true);
      clock.mockReturnValue(verifiedAt + 15000);
      expect(proof.ready).toBe(false);
    } finally {
      clock.mockRestore();
      proof.stop();
      await pending;
    }
  });
  it("expires a suspended source's proof at its original deadline and signals the connection gate", async () => {
    vi.useFakeTimers();
    const changed = vi.fn(),
      proof = new EnhancementExit(changed);
    try {
      transport.fetch.mockResolvedValueOnce(new Response("当前 IP：8.8.8.8 来自于：测试地区"));
      await proof.check(["8.8.8.8"], "http://127.0.0.1:38401", true);
      const checkedAt = proof.state.checkedAt;
      await vi.advanceTimersByTimeAsync(5000);
      proof.suspend();
      await vi.advanceTimersByTimeAsync(9999);
      expect(proof.ready).toBe(true);
      expect(proof.state.checkedAt).toBe(checkedAt);
      changed.mockClear();
      await vi.advanceTimersByTimeAsync(1);
      expect(proof.ready).toBe(false);
      expect(proof.state).toMatchObject({ phase: "failed", checkedAt });
      expect(changed).toHaveBeenCalledTimes(1);
    } finally {
      proof.stop();
      vi.useRealTimers();
    }
  });
  it("discards a query completed while source discovery is suspended", async () => {
    const proof = new EnhancementExit(() => undefined);
    const response = Promise.withResolvers<Response>();
    try {
      transport.fetch.mockResolvedValueOnce(new Response("当前 IP：8.8.8.8 来自于：测试地区"));
      await proof.check(["8.8.8.8"], "http://127.0.0.1:38401", true);
      const checkedAt = proof.state.checkedAt;
      transport.fetch.mockReturnValueOnce(response.promise);
      const pending = proof.check(["8.8.8.8"], "http://127.0.0.1:38401", true);
      await vi.waitFor(() => expect(transport.fetch).toHaveBeenCalledTimes(2));
      proof.suspend();
      response.resolve(new Response("当前 IP：8.8.8.8 来自于：测试地区"));
      expect(await pending).toBe(false);
      expect(proof.state.checkedAt).toBe(checkedAt);
      expect(proof.ready).toBe(true);
    } finally {
      proof.stop();
    }
  });
  it("revokes an existing proof immediately when the exit IP no longer matches", async () => {
    const proof = new EnhancementExit(() => undefined);
    transport.fetch.mockResolvedValueOnce(new Response("当前 IP：8.8.8.8 来自于：测试地区"));
    expect(await proof.check(["8.8.8.8"], "http://127.0.0.1:38401", true)).toBe(true);
    transport.fetch.mockResolvedValueOnce(new Response("当前 IP：1.1.1.1 来自于：测试地区"));
    expect(await proof.check(["8.8.8.8"], "http://127.0.0.1:38401", true)).toBe(false);
    expect(proof.ready).toBe(false);
    expect(proof.state.phase).toBe("blocked");
  });
  it("revokes the proof when all lookup attempts fail, even before its deadline", async () => {
    const proof = new EnhancementExit(() => undefined);
    transport.fetch.mockResolvedValueOnce(new Response("当前 IP：8.8.8.8 来自于：测试地区"));
    expect(await proof.check(["8.8.8.8"], "http://127.0.0.1:38401", true)).toBe(true);
    transport.fetch.mockRejectedValue(new Error("IP service unavailable"));
    expect(await proof.check(["8.8.8.8"], "http://127.0.0.1:38401", true)).toBe(false);
    expect(proof.ready).toBe(false);
    expect(proof.state.phase).toBe("failed");
  });
  it("waits five seconds after a slow query completes before polling again", async () => {
    const proof = new EnhancementExit(() => undefined);
    const clock = vi.spyOn(Date, "now").mockReturnValue(10000);
    try {
      transport.fetch.mockImplementationOnce(async () => {
        clock.mockReturnValue(16000);
        return new Response("当前 IP：8.8.8.8 来自于：测试地区");
      });
      transport.fetch.mockResolvedValueOnce(new Response("当前 IP：8.8.8.8 来自于：测试地区"));
      await proof.check(["8.8.8.8"], "http://127.0.0.1:38401");
      await proof.check(["8.8.8.8"], "http://127.0.0.1:38401");
      expect(transport.fetch).toHaveBeenCalledTimes(1);
      clock.mockReturnValue(20999);
      await proof.check(["8.8.8.8"], "http://127.0.0.1:38401");
      expect(transport.fetch).toHaveBeenCalledTimes(1);
      clock.mockReturnValue(21000);
      await proof.check(["8.8.8.8"], "http://127.0.0.1:38401");
      expect(transport.fetch).toHaveBeenCalledTimes(2);
    } finally {
      clock.mockRestore();
      proof.stop();
    }
  });
});
