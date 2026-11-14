import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";

import { dialog } from "electron";

import { ipv4Attempts } from "@ip-guard/electron";
import type { Snapshot } from "@ip-guard/electron";

import { nativePath } from "#src/main/guardian.ts";
import type { Guardian } from "#src/main/guardian.ts";
import { detectProtectionEvent } from "#src/main/protection-event.ts";
import type { ProtectionNotice } from "#src/main/protection-event.ts";

export class ProtectionAlerts {
  private previous: Snapshot | undefined;
  private viewer: { child: ChildProcess; notice: ProtectionNotice } | undefined;
  private stopped = false;
  private fallbackOpen = false;
  private fallbackFor: ProtectionNotice | undefined;
  private openMain: () => void;
  constructor(guardian: Guardian, openMain: () => void) {
    this.openMain = openMain;
    guardian.on("snapshot", (current: Snapshot) => {
      const previous = this.previous;
      this.previous = current;
      if (this.stopped) return;
      const notice = detectProtectionEvent(previous, current, guardian.isStopping);
      if (notice) this.show(notice);
      else {
        const viewer = this.viewer;
        if (
          viewer &&
          viewer.notice.probe.round === 0 &&
          ["ip_changed", "ip_unavailable"].includes(viewer.notice.kind) &&
          current.online &&
          current.ready &&
          !current.enhancementReady &&
          current.apps.some((app) => app.enhanced && current.running.includes(app.id))
        ) {
          if (viewer.notice.detail !== current.enhancementReason) {
            viewer.notice = { ...viewer.notice, detail: current.enhancementReason };
            this.writeNotice(true);
          }
          return;
        }
        if (
          !viewer ||
          viewer.child.exitCode !== null ||
          !viewer.child.stdin?.writable ||
          !["ip_changed", "ip_unavailable"].includes(viewer.notice.kind) ||
          !current.online ||
          !current.rulesLocked ||
          current.ready ||
          !current.running.length
        )
          return;
        const before = viewer.notice.probe;
        if (
          before.round === current.probe.round &&
          before.attempt === current.probe.attempt &&
          before.phase === current.probe.phase
        )
          return;
        viewer.notice = {
          ...viewer.notice,
          probe: current.probe,
          currentIp: current.currentIp,
          expectedIps: current.settings.expectedIps,
        };
        this.writeNotice(true);
      }
    });
  }
  private show(notice: ProtectionNotice) {
    let viewer = this.viewer;
    if (!viewer || viewer.child.exitCode !== null || !viewer.child.stdin?.writable) {
      const child = spawn(nativePath(), ["notice"], {
        windowsHide: true,
        stdio: ["pipe", "pipe", "pipe"],
      });
      viewer = { child, notice };
      this.viewer = viewer;
      const owned = viewer;
      if (child.stdout)
        createInterface({ input: child.stdout }).on("line", (line) => {
          if (!this.stopped && line === "open") this.openMain();
        });
      child.stderr?.setEncoding("utf8");
      child.stderr?.on("data", (message: string) =>
        console.error("防护提醒", message.slice(0, 500)),
      );
      child.stdin?.on("error", (error) => console.error("防护提醒通道", error.message));
      child.on("error", (error) => {
        if (this.viewer !== owned) return;
        this.viewer = undefined;
        console.error("防护提醒启动失败", error);
        void this.fallback(owned.notice);
      });
      child.on("exit", (code) => {
        if (this.viewer !== owned) return;
        this.viewer = undefined;
        if (code !== 0) void this.fallback(owned.notice);
      });
    }
    viewer.notice = notice;
    this.writeNotice(false);
  }
  private writeNotice(updateOnly: boolean) {
    const viewer = this.viewer;
    if (!viewer) return;
    viewer.child.stdin?.write(`${JSON.stringify({ ...viewer.notice, updateOnly })}\n`, (error) => {
      if (error && !updateOnly && this.viewer === viewer) void this.fallback(viewer.notice);
    });
  }
  private async fallback(notice: ProtectionNotice) {
    if (this.stopped || this.fallbackOpen || this.fallbackFor === notice) return;
    this.fallbackFor = notice;
    this.fallbackOpen = true;
    try {
      const result = await dialog.showMessageBox({
        type: notice.kind === "network_restored" ? "info" : "warning",
        title: "IP Guard · 防护提醒",
        message:
          notice.kind === "network_restored"
            ? "受保护程序已恢复联网"
            : ["guard_offline", "enforcement_failed"].includes(notice.kind)
              ? "受保护程序已停止"
              : "已暂停联网，程序保持运行",
        detail: notice.detail
          ? `${notice.apps.join("、")}\n${notice.detail}`
          : `${notice.apps.join("、")}\n${notice.probe.round ? `第 ${notice.probe.round} 轮 · ${notice.probe.attempt}/${ipv4Attempts} 次\n` : ""}${notice.kind === "network_restored" ? "IPv4 已命中允许列表。未完成的请求请重新发送。" : ["guard_offline", "enforcement_failed"].includes(notice.kind) ? "请先恢复 IP Guard 防护，再手动重新启动程序。" : "恢复允许的网络后自动恢复联网。"}`,
        buttons: ["知道了", "打开 IP Guard"],
        defaultId: 0,
        cancelId: 0,
      });
      if (result.response === 1) this.openMain();
    } finally {
      this.fallbackOpen = false;
    }
  }
  stop() {
    this.stopped = true;
    this.viewer?.child.stdin?.end();
  }
}
