import { describe, expect, it } from "vite-plus/test";

import { argumentWords, isPosixCli, shellArgument } from "./posix-platform.ts";

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
});
