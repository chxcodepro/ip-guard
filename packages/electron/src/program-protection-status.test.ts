import { describe, expect, it } from "vite-plus/test";

import { initialCommandProtection } from "./command-protection.ts";
import { programProtectionStatus } from "./program-protection-status.ts";

describe("effective program protection status", () => {
  const target = { id: "app", enabled: true };
  const base = {
    enhancementReady: true,
    enhancementReason: "",
    running: [],
    otherModelRunning: [],
    ready: true,
    driver: initialCommandProtection,
  };
  it("reports actual active protection instead of a next-launch hint", () => {
    expect(programProtectionStatus({ ...base, running: ["app"] }, target)).toBe("IP 防护已生效");
    expect(programProtectionStatus({ ...base, running: ["app"], ready: false }, target)).toBe(
      "联网已暂停",
    );
    expect(
      programProtectionStatus(
        {
          ...base,
          running: ["app"],
          driver: { ...initialCommandProtection, enabled: true, ready: true },
        },
        { ...target, enhanced: true },
      ),
    ).toBe("检测出口已通过 · 命令过滤已启用");
    expect(
      programProtectionStatus(
        {
          ...base,
          running: ["app"],
          driver: { ...initialCommandProtection, enabled: true, ready: true },
        },
        target,
      ),
    ).toBe("IP 防护已生效");
    expect(
      programProtectionStatus({ ...base, running: ["app"] }, { ...target, enhanced: true }),
    ).toBe("增强未生效 · 联网保持暂停");
  });
  it("distinguishes disabled, pending, unrestricted and mixed sessions", () => {
    expect(programProtectionStatus(base, { ...target, enabled: false })).toBe("程序防护未开启");
    expect(programProtectionStatus(base, target)).toBe("待启动");
    expect(programProtectionStatus({ ...base, otherModelRunning: ["app"] }, target)).toBe(
      "其他模型会话 · 原网络",
    );
    expect(
      programProtectionStatus({ ...base, running: ["app"], otherModelRunning: ["app"] }, target),
    ).toBe("部分会话使用原网络");
  });
});
