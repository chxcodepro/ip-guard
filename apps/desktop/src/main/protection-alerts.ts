import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";

import { dialog } from "electron";

import type { Snapshot } from "@ip-guard/electron";

import { nativePath } from "#src/main/guardian.ts";
import type { Guardian } from "#src/main/guardian.ts";
import { detectProtectionStop } from "#src/main/protection-event.ts";
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
      const notice = detectProtectionStop(previous, current, guardian.isStopping);
      if (notice) this.show(notice);
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
      child.stdin?.on("error", () => {
        if (this.viewer === owned) void this.fallback(owned.notice);
      });
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
    const owned = viewer;
    viewer.child.stdin?.write(`${JSON.stringify(notice)}\n`, (error) => {
      if (error && this.viewer === owned) void this.fallback(owned.notice);
    });
  }
  private async fallback(notice: ProtectionNotice) {
    if (this.stopped || this.fallbackOpen || this.fallbackFor === notice) return;
    this.fallbackFor = notice;
    this.fallbackOpen = true;
    try {
      const result = await dialog.showMessageBox({
        type: "warning",
        title: "IP Guard · 防护提醒",
        message: "受保护程序已停止",
        detail: `${notice.apps.join("、")}\n检测到网络出口异常或守护连接中断。恢复允许的网络后，请手动重新启动程序。`,
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
