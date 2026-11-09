import { EventEmitter } from "node:events";
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, statSync } from "node:fs";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { app, dialog, shell } from "electron";
import updater from "electron-updater";
import { z } from "zod";

import type { UpdateState } from "@ip-guard/electron";

import { updateFailure } from "#src/main/update-error.ts";

const repositorySchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/);
const { autoUpdater } = updater;
export class ApplicationUpdates extends EventEmitter<{ update: [UpdateState] }> {
  state: UpdateState = {
    phase: "unconfigured",
    currentVersion: app.getVersion(),
    latestVersion: "",
    progress: 0,
    checkedAt: "",
    message: "GitHub 更新源未配置",
    repository: "",
  };
  private started = false;
  private downloadedVersion = "";
  private pendingCheck: Promise<UpdateState> | undefined;
  private onInstalling: () => void;
  private onInstallError: () => void;
  constructor(onInstalling: () => void, onInstallError: () => void) {
    super();
    this.onInstalling = onInstalling;
    this.onInstallError = onInstallError;
  }
  start() {
    if (this.started) return;
    this.started = true;
    const info = path.join(process.resourcesPath, "release-info.json");
    if (
      !app.isPackaged ||
      !existsSync(info) ||
      !existsSync(path.join(process.resourcesPath, "app-update.yml"))
    )
      return;
    try {
      const data: unknown = JSON.parse(readFileSync(info, "utf8"));
      const repository = z.object({ repository: repositorySchema }).parse(data).repository;
      this.state = { ...this.state, phase: "idle", repository, message: "" };
    } catch (error) {
      this.state.message =
        error instanceof Error ? `更新源配置无效：${error.message}` : "更新源配置无效";
      return;
    }
    autoUpdater.autoDownload = false;
    autoUpdater.autoInstallOnAppQuit = false;
    autoUpdater.allowDowngrade = false;
    autoUpdater.on("update-available", (info) =>
      this.set({
        phase: this.downloadedVersion === info.version ? "downloaded" : "available",
        latestVersion: info.version,
        checkedAt: new Date().toISOString(),
        message: this.downloadedVersion === info.version ? "更新已下载" : "发现新版本",
      }),
    );
    autoUpdater.on("update-not-available", (info) =>
      this.set({
        phase: "current",
        latestVersion: info.version,
        checkedAt: new Date().toISOString(),
        message: "已是最新版本",
      }),
    );
    autoUpdater.on("download-progress", (progress) =>
      this.set({
        phase: "downloading",
        progress: Math.max(0, Math.min(100, progress.percent)),
        message: "正在下载更新",
      }),
    );
    autoUpdater.on("update-downloaded", (info) => {
      this.downloadedVersion = info.version;
      this.set({
        phase: "downloaded",
        latestVersion: info.version,
        progress: 100,
        message: "更新已下载",
      });
    });
    autoUpdater.on("error", (error) => {
      if (this.pendingCheck && this.state.phase === "checking") return;
      if (this.state.phase === "installing") this.onInstallError();
      this.logError(error);
      this.set({
        phase: "error",
        checkedAt: new Date().toISOString(),
        message: updateFailure(error).message,
      });
    });
    void this.check();
  }
  private set(value: Partial<UpdateState>) {
    this.state = { ...this.state, ...value };
    this.emit("update", this.state);
  }
  private logError(error: unknown) {
    try {
      const folder = app.getPath("logs");
      mkdirSync(folder, { recursive: true });
      const file = path.join(folder, "updates.log");
      if (existsSync(file) && statSync(file).size > 1048576) renameSync(file, `${file}.1`);
      const detail = error instanceof Error ? error.stack || error.message : String(error);
      appendFileSync(file, `${new Date().toISOString()} ${detail.slice(0, 8192)}\n`, "utf8");
    } catch (logError) {
      console.error("更新日志写入失败", logError);
    }
  }
  check(): Promise<UpdateState> {
    if (this.pendingCheck) return this.pendingCheck;
    if (
      this.state.phase === "unconfigured" ||
      ["downloading", "installing"].includes(this.state.phase)
    )
      return Promise.resolve(this.state);
    this.pendingCheck = this.checkWithRetry().finally(() => {
      this.pendingCheck = undefined;
    });
    return this.pendingCheck;
  }
  private async checkWithRetry(): Promise<UpdateState> {
    for (let attempt = 1; attempt <= 3; attempt++) {
      this.set({ phase: "checking", message: `正在检查 GitHub Releases · 第 ${attempt}/3 次` });
      try {
        if (attempt > 1) {
          await autoUpdater.netSession.closeAllConnections();
          await autoUpdater.netSession.clearHostResolverCache();
          await autoUpdater.netSession.forceReloadProxyConfig();
        }
        await autoUpdater.checkForUpdates();
        return this.state;
      } catch (error) {
        this.logError(error);
        const failure = updateFailure(error);
        if (!failure.retryable || attempt === 3) {
          const downloaded =
            this.downloadedVersion === this.state.latestVersion ? this.downloadedVersion : "";
          this.set({
            phase: downloaded ? "downloaded" : "error",
            checkedAt: new Date().toISOString(),
            message: downloaded
              ? `${failure.message}已下载 ${downloaded}，可继续安装。`
              : failure.message,
          });
          return this.state;
        }
        this.set({ phase: "checking", message: `GitHub 连接暂时失败，正在重试 ${attempt + 1}/3` });
      }
      await delay(attempt * 1000);
    }
    return this.state;
  }
  async download() {
    if (this.state.phase !== "available") return this.state;
    this.set({ phase: "downloading", progress: 0, message: "正在下载更新" });
    try {
      await autoUpdater.downloadUpdate();
    } catch (error) {
      this.set({
        phase: "error",
        message: updateFailure(error).message,
      });
    }
    return this.state;
  }
  async install() {
    if (this.state.phase !== "downloaded") return this.state;
    const answer = await dialog.showMessageBox({
      type: "warning",
      title: "安装更新",
      message: `安装 IP Guard ${this.state.latestVersion}？`,
      detail: "将退出 IP Guard 并结束受保护程序，更新后重新校验。",
      buttons: ["取消", "安装并重启"],
      defaultId: 0,
      cancelId: 0,
    });
    if (answer.response !== 1) return this.state;
    this.set({ phase: "installing", message: "正在安装更新" });
    this.onInstalling();
    try {
      autoUpdater.quitAndInstall(false, true);
    } catch (error) {
      this.onInstallError();
      this.set({
        phase: "error",
        message: updateFailure(error).message,
      });
    }
    return this.state;
  }
  async releases() {
    if (this.state.repository)
      await shell.openExternal(`https://github.com/${this.state.repository}/releases`);
    return this.state;
  }
}
