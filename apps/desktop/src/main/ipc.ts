import { spawn } from "node:child_process";
import path from "node:path";

import { app, BrowserWindow, dialog, ipcMain, shell } from "electron";

import { commandSchema, desktopChannels, isClaudeDesktopPath } from "@ip-guard/electron";
import type { Reply } from "@ip-guard/electron";

import type { BrowserBridge } from "#src/main/browser-bridge.ts";
import type { ClaudeIPv4 } from "#src/main/claude-ip.ts";
import { claudeStatus, stopClaudeTrees } from "#src/main/claude-processes.ts";
import type { CoffeeDiagnostics } from "#src/main/coffee.ts";
import type { Guardian } from "#src/main/guardian.ts";
import { NativeCommandError } from "#src/main/guardian.ts";
import { claudePresets } from "#src/main/presets.ts";
import { isTrustedUrl } from "#src/main/renderer-route.ts";
import type { ApplicationUpdates } from "#src/main/updates.ts";

export const setupIpc = (
  devOrigin: string | null,
  guardian: Guardian,
  coffee: CoffeeDiagnostics,
  claude: ClaudeIPv4,
  updates: ApplicationUpdates,
  browser: BrowserBridge,
) => {
  updates.on("update", (state) => {
    for (const window of BrowserWindow.getAllWindows())
      window.webContents.send(desktopChannels.appUpdate, state);
  });
  let stoppingClaude = false;
  coffee.on("update", (report) => {
    for (const window of BrowserWindow.getAllWindows())
      window.webContents.send(desktopChannels.coffee, report);
  });
  guardian.on("snapshot", (snapshot) => {
    for (const window of BrowserWindow.getAllWindows())
      window.webContents.send(desktopChannels.update, snapshot);
  });
  ipcMain.handle(desktopChannels.invoke, async (event, input: unknown): Promise<Reply> => {
    if (
      event.senderFrame !== event.sender.mainFrame ||
      !isTrustedUrl(event.senderFrame?.url ?? "", devOrigin)
    )
      throw new Error("Untrusted IPC sender");
    const command = commandSchema.parse(input);
    if (command.action === "extension:status") return { extension: await browser.status() };
    if (command.action === "extension:setup") {
      await guardian.request("browser:register");
      const directory = app.isPackaged
        ? path.join(process.resourcesPath, "browser-extension")
        : path.resolve(import.meta.dirname, "../../../browser-extension/dist");
      const error = await shell.openPath(directory);
      if (error) throw new Error(error);
      return {};
    }
    if (command.action === "update:status") return { appUpdate: updates.state };
    if (command.action === "update:check") return { appUpdate: await updates.check() };
    if (command.action === "update:download") return { appUpdate: await updates.download() };
    if (command.action === "update:install") return { appUpdate: await updates.install() };
    if (command.action === "update:releases") return { appUpdate: await updates.releases() };
    if (command.action === "unlock") {
      const snapshot = await guardian.request("status");
      if (!snapshot.rulesLocked) return { snapshot };
      if (!snapshot.admin) throw new Error("请以管理员身份重启 IP Guard");
      const answer = await dialog.showMessageBox({
        type: "warning",
        title: "取消 IP 锁定",
        message: "取消锁定并停止受保护程序？",
        detail: "将结束受保护进程树并封锁连接。未保存的内容可能丢失，重新锁定 IP 后才能再次启动。",
        buttons: ["保持锁定", "取消锁定并停止"],
        defaultId: 0,
        cancelId: 0,
      });
      if (answer.response !== 1)
        return { cancelled: true, snapshot: await guardian.request("status") };
      return { snapshot: await guardian.request("unlock") };
    }
    if (command.action === "claude:status") return { claude: await claudeStatus() };
    if (command.action === "claude:stop") {
      if (stoppingClaude) throw new Error("Claude 停止操作正在处理中");
      stoppingClaude = true;
      try {
        const current = await claudeStatus();
        if (current.phase === "stopped") return { claude: current };
        if (!current.canStop) throw new Error(current.message || "Claude 进程状态暂未确认");
        const answer = await dialog.showMessageBox({
          type: "warning",
          title: "停止 Claude",
          message: "停止 Claude 进程树？",
          detail:
            "将结束当前登录用户的 Claude CLI、Claude Desktop 及其子进程。未保存的会话可能丢失。",
          buttons: ["取消", "停止"],
          defaultId: 0,
          cancelId: 0,
        });
        if (answer.response !== 1) return { cancelled: true, claude: await claudeStatus() };
        return { claude: await stopClaudeTrees() };
      } finally {
        stoppingClaude = false;
      }
    }
    if (command.action === "ip:current") {
      const result = await claude.check();
      if (!result.ip) throw new Error(result.error);
      return { ipv4: result.ip };
    }
    if (command.action === "presets") return { presets: await claudePresets() };
    if (command.action === "desktop:relocate") {
      const snapshot = await guardian.request("status");
      const target = snapshot.apps.find((item) => item.id === command.id);
      if (!snapshot.admin || !target || !isClaudeDesktopPath(target.path))
        throw new Error("请以管理员身份选择已添加的 Claude Desktop。");
      const latest = (await claudePresets()).find((item) => item.id === "claude-desktop");
      if (!latest || latest.status !== "ready" || !isClaudeDesktopPath(latest.path))
        throw new Error(latest?.message || "未找到已注册的 Claude Desktop，请确认安装已完成。");
      if (target.path.toLowerCase() !== latest.path.toLowerCase()) {
        const answer = await dialog.showMessageBox({
          type: "warning",
          title: "更新 Claude Desktop 路径",
          message: `更新 ${target.name} 的安装路径？`,
          detail: `${target.path}\n→ ${latest.path}\n\n保留名称、启动参数和防护开关。${target.enabled ? "将结束原受控进程，请先关闭新版 Claude。" : "防护继续保持关闭。"}`,
          buttons: ["取消", "更新路径"],
          defaultId: 0,
          cancelId: 0,
        });
        if (answer.response !== 1) return { cancelled: true };
      }
      return {
        snapshot: await guardian.request("relocate", { targetId: target.id, path: latest.path }),
      };
    }
    if (command.action === "coffee:status") return { diagnostics: coffee.report };
    if (command.action === "coffee:refresh") return { diagnostics: coffee.refresh() };
    if (command.action === "restart") {
      app.relaunch();
      app.quit();
      return {};
    }
    if (command.action === "pick") {
      const result = await dialog.showOpenDialog({
        title: "选择受保护程序",
        properties: ["openFile"],
        filters: [{ name: "Windows 程序", extensions: ["exe"] }],
      });
      return result.canceled ? { cancelled: true } : { selectedPath: result.filePaths[0] };
    }
    if (command.action === "logs") {
      const error = await shell.openPath(
        path.join(
          process.env.LOCALAPPDATA ?? path.join(app.getPath("home"), "AppData/Local"),
          "IPGuard",
        ),
      );
      if (error) throw new Error(error);
      return {};
    }
    if (command.action === "elevate") {
      if (!app.isPackaged) throw new Error("开发模式请从管理员终端启动。");
      await guardian.stop();
      app.releaseSingleInstanceLock();
      const escaped = process.execPath.replaceAll("'", "''");
      try {
        await new Promise<void>((resolve, reject) => {
          const child = spawn(
            "powershell.exe",
            [
              "-NoProfile",
              "-NonInteractive",
              "-Command",
              `Start-Process -FilePath '${escaped}' -Verb RunAs -ErrorAction Stop`,
            ],
            { windowsHide: true, stdio: "ignore" },
          );
          child.on("error", reject);
          child.on("exit", (code) =>
            code === 0 ? resolve() : reject(new Error("管理员授权已取消。")),
          );
        });
        app.quit();
        return {};
      } catch (error) {
        if (!app.requestSingleInstanceLock()) {
          app.quit();
          throw error;
        }
        guardian.start();
        throw error;
      }
    }
    if ((command.action === "protect" && !command.enabled) || command.action === "remove") {
      const result = await dialog.showMessageBox({
        type: "warning",
        title: "IP Guard",
        message: "解除防护后，该程序将恢复普通启动和联网。",
        buttons: ["取消", "继续"],
        defaultId: 0,
        cancelId: 0,
      });
      if (result.response !== 1) return { cancelled: true };
    }
    if (command.action === "autostart" && !app.isPackaged)
      throw new Error("请安装打包版本后开启开机启动。");
    const { action, ...payload } = command;
    const nativePayload: Record<string, unknown> = { ...payload };
    if ("id" in payload) {
      nativePayload.targetId = payload.id;
      delete nativePayload.id;
    }
    if (action === "autostart") nativePayload.executable = process.execPath;
    try {
      return { snapshot: await guardian.request(action, nativePayload) };
    } catch (error) {
      if (!(error instanceof NativeCommandError) || error.code !== "firewall_disabled") throw error;
      const answer = await dialog.showMessageBox({
        type: "warning",
        title: "开启 Windows 防火墙",
        message: error.message,
        detail: error.help,
        buttons: ["打开 Windows 防火墙", "稍后"],
        defaultId: 0,
        cancelId: 1,
      });
      if (answer.response === 0) {
        const windows = process.env.SystemRoot;
        if (!windows || !path.isAbsolute(windows))
          throw new Error("请按 Win+R，输入 wf.msc 打开防火墙管理界面");
        const openError = await shell.openPath(path.join(windows, "System32/wf.msc"));
        if (openError)
          throw new Error(`打开防火墙管理界面失败：${openError}。请按 Win+R，输入 wf.msc`);
      }
      return { cancelled: true, snapshot: await guardian.request("status") };
    }
  });
};
