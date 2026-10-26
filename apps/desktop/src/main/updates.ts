import { EventEmitter } from "node:events";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

import { app, dialog, shell } from "electron";
import updater from "electron-updater";
import { z } from "zod";

import type { UpdateState } from "@ip-guard/electron";

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
    autoUpdater.on("checking-for-update", () =>
      this.set({ phase: "checking", message: "正在检查 GitHub Releases" }),
    );
    autoUpdater.on("update-available", (info) =>
      this.set({
        phase: "available",
        latestVersion: info.version,
        checkedAt: new Date().toISOString(),
        message: "发现新版本",
      }),
    );
    autoUpdater.on("update-not-available", () =>
      this.set({ phase: "current", checkedAt: new Date().toISOString(), message: "已是最新版本" }),
    );
    autoUpdater.on("download-progress", (progress) =>
      this.set({
        phase: "downloading",
        progress: Math.max(0, Math.min(100, progress.percent)),
        message: "正在下载更新",
      }),
    );
    autoUpdater.on("update-downloaded", (info) =>
      this.set({
        phase: "downloaded",
        latestVersion: info.version,
        progress: 100,
        message: "更新已下载",
      }),
    );
    autoUpdater.on("error", (error) => {
      if (this.state.phase === "installing") this.onInstallError();
      this.set({ phase: "error", message: error.message.slice(0, 220) });
    });
    void this.check();
  }
  private set(value: Partial<UpdateState>) {
    this.state = { ...this.state, ...value };
    this.emit("update", this.state);
  }
  async check() {
    if (
      this.state.phase === "unconfigured" ||
      ["checking", "downloading", "installing"].includes(this.state.phase)
    )
      return this.state;
    try {
      await autoUpdater.checkForUpdates();
    } catch (error) {
      this.set({
        phase: "error",
        message: error instanceof Error ? error.message.slice(0, 220) : "更新检查失败",
      });
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
        message: error instanceof Error ? error.message.slice(0, 220) : "更新下载失败",
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
        message: error instanceof Error ? error.message : "更新安装失败",
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
