import { Notification } from "electron";

import type { Snapshot } from "@ip-guard/electron";

import type { Guardian } from "#src/main/guardian.ts";
import { detectProtectionEvent } from "#src/main/protection-event.ts";
import type { ProtectionNotice } from "#src/main/protection-event.ts";

export class ProtectionAlerts {
  private previous: Snapshot | undefined;
  private pause:
    | {
        notice: ProtectionNotice;
        timer?: ReturnType<typeof setTimeout>;
        notification?: Notification;
      }
    | undefined;
  private critical: Notification | undefined;
  private criticalKind: ProtectionNotice["kind"] | undefined;
  private proxyCoreFailureNotified = false;
  private stopped = false;
  private readonly guardian: Guardian;
  private readonly openMain: () => void;
  constructor(guardian: Guardian, openMain: () => void) {
    this.guardian = guardian;
    this.openMain = openMain;
    guardian.on("snapshot", this.observe);
  }
  private readonly observe = (current: Snapshot) => {
    const notice = detectProtectionEvent(this.previous, current, this.guardian.isStopping);
    this.previous = current;
    if (this.stopped) return;
    if (!notice) {
      this.clearPause();
      if (this.guardian.isStopping || !current.rulesLocked) {
        this.critical?.close();
        this.critical = undefined;
      }
      return;
    }
    if (notice.kind !== "paused") {
      const pause = this.pause;
      this.pause = undefined;
      clearTimeout(pause?.timer);
      pause?.notification?.close();
      this.critical?.close();
      this.critical = this.show(notice);
      this.criticalKind = notice.kind;
      return;
    }
    if (this.pause?.notice.apps.some(({ id }) => notice.apps.some((app) => app.id === id))) {
      this.pause.notice = notice;
      return;
    }
    this.clearPause();
    const pause: NonNullable<ProtectionAlerts["pause"]> = { notice };
    this.pause = pause;
    pause.timer = setTimeout(() => {
      pause.timer = undefined;
      if (!this.stopped && !this.proxyCoreFailureNotified && this.pause === pause)
        pause.notification = this.show(pause.notice);
    }, 30000);
    pause.timer.unref();
  };
  private show(notice: ProtectionNotice): Notification | undefined {
    if (!Notification.isSupported()) {
      console.warn("系统通知不可用，防护状态请查看 IP Guard 托盘与日志");
      return;
    }
    const names = [...new Set(notice.apps.map(({ name }) => name))].join("、");
    const title =
      notice.kind === "paused"
        ? "联网仍暂停，正在自动重试"
        : notice.kind === "proxy_core_failed"
          ? "专用代理通道发生故障"
          : notice.kind === "guard_offline"
            ? "守护连接已中断"
            : "连接防护发生故障";
    const status =
      notice.kind === "paused"
        ? "程序保持运行，校验通过后自动恢复联网。"
        : notice.kind === "proxy_core_failed"
          ? "增强联网已暂停，程序保持运行。恢复通道后自动复核。"
          : notice.kind === "guard_offline"
            ? "受控会话许可已撤销，请恢复防护后重新启动。"
            : notice.mainRunning
              ? "主程序仍在运行，相关连接或子进程已阻断。"
              : "受影响的受控会话已停止，请恢复防护后重新启动。";
    const notification = new Notification({
      title: `IP Guard · ${title}`,
      body: `${names}\n${status}点击查看。`,
      silent: true,
    });
    notification.on("click", () => {
      if (!this.stopped) this.openMain();
    });
    notification.on("failed", (_event, error) => console.error("防护系统通知发送失败", error));
    notification.show();
    return notification;
  }
  notifyProxyCoreFailure() {
    if (this.stopped || this.proxyCoreFailureNotified) return;
    const snapshot = this.guardian.snapshot;
    if (!snapshot?.online || !snapshot.rulesLocked) return;
    const apps = snapshot.apps
      .filter((app) => app.enhanced && snapshot.running.includes(app.id))
      .map(({ id, name }) => ({ id, name }));
    if (!apps.length) return;
    this.proxyCoreFailureNotified = true;
    this.clearPause();
    this.critical?.close();
    this.critical = this.show({ kind: "proxy_core_failed", apps, mainRunning: true });
    this.criticalKind = "proxy_core_failed";
  }
  resetProxyCoreFailure() {
    this.proxyCoreFailureNotified = false;
    if (this.criticalKind === "proxy_core_failed") {
      this.critical?.close();
      this.critical = undefined;
      this.criticalKind = undefined;
    }
  }
  private clearPause() {
    const pause = this.pause;
    this.pause = undefined;
    clearTimeout(pause?.timer);
    pause?.notification?.close();
  }
  stop() {
    this.stopped = true;
    this.guardian.off("snapshot", this.observe);
    this.clearPause();
    this.critical?.close();
    this.critical = undefined;
  }
}
