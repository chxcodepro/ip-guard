import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vite-plus/test";
import { vi } from "vite-plus/test";

import {
  argumentWords,
  isPosixCli,
  shellArgument,
  posixAutostart,
  posixAutostartEnabled,
} from "./posix-platform.ts";

describe("POSIX launch arguments", () => {
  it("retains quoted empty values and passes shell operators as literal arguments", () => {
    expect(
      argumentWords(`--model 'claude-sonnet' --append-system-prompt "a b" '' a\\ b ; $(id)`),
    ).toEqual([
      "--model",
      "claude-sonnet",
      "--append-system-prompt",
      "a b",
      "",
      "a b",
      ";",
      "$(id)",
    ]);
    expect(() => argumentWords(`"unfinished`)).toThrow("未闭合");
    expect(() => argumentWords("trailing\\")).toThrow("未闭合");
  });
  it("quotes executable paths as a single POSIX shell word", () => {
    expect(shellArgument("/tmp/it's here")).toBe("'/tmp/it'\\''s here'");
    expect(isPosixCli("/Users/test/.local/bin/claude")).toBe(true);
    expect(isPosixCli("/Applications/Claude.app/Contents/MacOS/Claude")).toBe(false);
  });
  it.runIf(process.platform === "linux")("verifies and removes the user login entry", async () => {
    const folder = await mkdtemp(path.join(os.tmpdir(), "ipguard-login-"));
    vi.stubEnv("XDG_CONFIG_HOME", folder);
    try {
      const executable = "/opt/IP Guard/ip-guard";
      expect(await posixAutostartEnabled(executable)).toBe(false);
      await posixAutostart(true, executable);
      expect(await posixAutostartEnabled(executable)).toBe(true);
      await posixAutostart(false, executable);
      expect(await posixAutostartEnabled(executable)).toBe(false);
    } finally {
      vi.unstubAllEnvs();
      await rm(folder, { recursive: true, force: true });
    }
  });
});
