import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vite-plus/test";
import { vi } from "vite-plus/test";

import { providerHint } from "../posix/provider.ts";
import { macAdapters } from "./posix-network.ts";
import {
  argumentWords,
  isPosixCli,
  shellArgument,
  posixAutostart,
  posixAutostartEnabled,
} from "./posix-platform.ts";

describe("POSIX launch arguments", () => {
  it("keeps a disconnected macOS adapter present even when it has no address", () => {
    const adapters = macAdapters(
      "lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 16384\nen0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n status: inactive\nen1: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n status: active\n",
      {},
    );
    expect(adapters).toMatchObject([
      { id: "en0", exists: true, up: false, ipv4: false },
      { id: "en1", exists: true, up: true },
    ]);
  });
  it("distinguishes known DeepSeek sessions and keeps hidden gateway aliases protected", async () => {
    const folder = await mkdtemp(path.join(os.tmpdir(), "ipguard-model-"));
    try {
      const env = { CLAUDE_CONFIG_DIR: folder, ANTHROPIC_BASE_URL: "https://api.deepseek.com" };
      expect(await providerHint(["--model", "sonnet"], folder, env)).toBe("other");
      expect(await providerHint(["--model", "claude-sonnet-4"], folder, env)).toBe("claude");
      expect(
        await providerHint(["--model", "deepseek-chat"], folder, {
          CLAUDE_CONFIG_DIR: folder,
          ANTHROPIC_BASE_URL: "http://127.0.0.1:1234",
        }),
      ).toBe("other");
      expect(
        await providerHint(["--model", "hidden-alias"], folder, {
          CLAUDE_CONFIG_DIR: folder,
          ANTHROPIC_BASE_URL: "http://127.0.0.1:1234",
        }),
      ).toBe("unknown");
    } finally {
      await rm(folder, { recursive: true, force: true });
    }
  });
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
