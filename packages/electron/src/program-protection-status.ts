import type { Snapshot } from "./index.ts";

export function programProtectionStatus(
  snapshot: Pick<Snapshot, "running" | "otherModelRunning" | "ready" | "driver"> &
    Partial<Pick<Snapshot, "enhancementReady" | "enhancementReason">>,
  target: Pick<Snapshot["apps"][number], "id" | "enabled"> & { enhanced?: boolean },
) {
  if (!target.enabled) return "程序防护未开启";
  const protectedRunning = snapshot.running.includes(target.id),
    unrestricted = snapshot.otherModelRunning.includes(target.id);
  if (protectedRunning && unrestricted) return "部分会话使用原网络";
  if (protectedRunning) {
    if (!snapshot.ready) return "联网已暂停";
    if (target.enhanced && !snapshot.driver.ready) return "增强未生效 · 联网保持暂停";
    if (target.enhanced && !snapshot.enhancementReady)
      return snapshot.enhancementReason || "增强出口待复核 · 联网已暂停";
    return target.enhanced && snapshot.driver.ready
      ? "检测出口已通过 · 命令过滤已启用"
      : "IP 防护已生效";
  }
  if (unrestricted) return "其他模型会话 · 原网络";
  return "待启动";
}
