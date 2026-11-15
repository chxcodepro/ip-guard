import { spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";

import {
  app,
  BrowserWindow,
  dialog,
  ipcMain,
  Menu,
  nativeImage,
  session,
  shell,
  Tray,
} from "electron";

import { commandSchema, desktopChannels, rendererOrigin } from "@ip-guard/electron";
import type { Command, Reply } from "@ip-guard/electron";

import { BrowserBridge } from "./browser-bridge.ts";
import { ClaudeIPv4 } from "./claude-ip.ts";
import { CoffeeDiagnostics } from "./coffee.ts";
import { NetworkPolicies } from "./network-policies.ts";
import { setupPosixBrowser } from "./posix-browser.ts";
import { PosixGuard } from "./posix-guard.ts";
import {
  launcherPath,
  openPosixTerminal,
  preparePosixBroker,
  refreshLaunchers,
} from "./posix-launch.ts";
import { executablePath, isPosixCli, posixAutostart } from "./posix-platform.ts";
import { isTrustedUrl, parseLoopbackOrigin } from "./renderer-route.ts";
import { serveRenderer } from "./renderer.ts";
import { ApplicationUpdates } from "./updates.ts";
import { createMainWindow } from "./window.ts";

const origin = process.env.ELECTRON_RENDERER_URL;
const devOrigin = origin ? parseLoopbackOrigin(origin) : null;
if (origin && !devOrigin) throw new Error("Invalid renderer origin");
const policies = new NetworkPolicies(),
  probe = new ClaudeIPv4(),
  transport = () => session.fromPartition("ipguard-posix-upstream", { cache: false });
const guard = new PosixGuard(probe, policies, (url) => transport().resolveProxy(url));
const coffee = new CoffeeDiagnostics(probe),
  updates = new ApplicationUpdates(
    () => app.quit(),
    () => {},
  );
const client = app.isPackaged
  ? path.join(process.resourcesPath, "posix/client.cjs")
  : path.join(import.meta.dirname, "../posix/client.cjs");
const browser = new BrowserBridge(guard, updates);
let quitting = false,
  tray: Tray | undefined;
let window: BrowserWindow | undefined;
let broker: Awaited<ReturnType<typeof preparePosixBroker>> | undefined;
const send = (channel: string, value: unknown) => {
  for (const target of BrowserWindow.getAllWindows()) target.webContents.send(channel, value);
};
const confirm = async (message: string, detail = "") =>
  (
    await dialog.showMessageBox({
      type: "warning",
      message,
      detail,
      buttons: ["取消", "确认"],
      defaultId: 0,
      cancelId: 0,
    })
  ).response === 1;
const policyState = () => {
  const programs = guard.snapshot.apps.filter((a) => a.enabled).map((a) => a.name);
  return {
    ...policies.status(guard.snapshot, guard.snapshot.ready),
    scope: "managed_proxy" as const,
    programs,
    phase: policies.error
      ? ("failed" as const)
      : !programs.length
        ? ("inactive" as const)
        : guard.snapshot.ready
          ? ("active" as const)
          : ("paused" as const),
    localPorts: policies.kernelPolicy.localPorts,
  };
};
async function action(command: Command): Promise<Reply> {
  switch (command.action) {
    case "status":
    case "logs":
      return { snapshot: guard.snapshot };
    case "check":
      return { snapshot: await guard.check() };
    case "ip:current": {
      const result = await probe.check(command.sourceUrl);
      if (result.error || !result.ip) throw new Error(result.error || "未取得 IPv4");
      return { ipv4: result.ip };
    }
    case "lock":
      return { snapshot: await guard.lock(command.settings) };
    case "unlock":
      if (!(await confirm("取消锁定并结束受管会话？"))) return { cancelled: true };
      return { snapshot: await guard.unlock() };
    case "add":
      await guard.add(command.app);
      break;
    case "edit":
      await guard.edit(command.id, command.name, command.arguments);
      break;
    case "protect":
      if (
        !(await confirm(
          command.enabled ? "启用受管启动？" : "关闭受管启动并结束会话？",
          command.enabled
            ? "此开发版保护从 IP Guard 或受管终端命令启动的 Claude，以及经过受管代理的连接。系统级直连与子进程网络增强正在移植。"
            : "",
        ))
      )
        return { cancelled: true };
      await guard.protect(command.id, command.enabled);
      break;
    case "remove":
      if (!(await confirm("移除此程序并结束受管会话？"))) return { cancelled: true };
      await guard.remove(command.id);
      break;
    case "start": {
      const target = guard.target(command.id);
      await guard.check();
      if (!guard.snapshot.ready) throw new Error(guard.snapshot.reason);
      if (isPosixCli(target.path)) await openPosixTerminal(target.id);
      else {
        const child = spawn(launcherPath(target.id), [], {
          stdio: "ignore",
          detached: true,
          cwd: os.homedir(),
        });
        await new Promise<void>((resolve, reject) => {
          child.once("spawn", resolve);
          child.once("error", reject);
        });
        child.unref();
      }
      return { snapshot: guard.snapshot };
    }
    case "stop":
      guard.stopSessions(command.id);
      break;
    case "adapter:set":
      await guard.setAdapter(command.adapterId);
      break;
    case "autostart":
      if (process.platform === "darwin")
        app.setLoginItemSettings({
          openAtLogin: command.enabled,
          args: ["--background"],
        });
      else await posixAutostart(command.enabled, process.env.APPIMAGE || process.execPath);
      await guard.setAutostart(command.enabled);
      break;
    case "pick": {
      const result = await dialog.showOpenDialog({
        properties: [
          "openFile",
          ...(process.platform === "darwin" ? ["openDirectory" as const] : []),
        ],
      });
      if (result.canceled || !result.filePaths[0]) return { cancelled: true };
      return { selectedPath: await executablePath(result.filePaths[0]) };
    }
    case "presets":
      return { presets: await (await import("./posix-platform.ts")).posixPresets() };
    case "claude:status":
      return {
        claude: {
          phase: guard.snapshot.running.length ? "running" : "stopped",
          count: guard.snapshot.running.length,
          canStop: Boolean(guard.snapshot.running.length),
          message: "受管会话",
          checkedAt: new Date().toISOString(),
        },
      };
    case "claude:stop":
      if (!(await confirm("结束所有受管 Claude 会话？"))) return { cancelled: true };
      guard.stopSessions();
      break;
    case "network:status":
      return { networkPolicy: policyState() };
    case "network:save": {
      const record = policies.prepare(command.settings);
      if (
        command.settings.rules.some((r) => r.enabled && r.action === "direct") &&
        !(await confirm("允许这些目标直连？", "直连例外可能暴露本机出口，仅添加可信目标。"))
      )
        return { cancelled: true, networkPolicy: policyState() };
      guard.pause("正在应用拦截策略");
      await policies.write(record);
      policies.commit(record);
      await guard.check();
      return { networkPolicy: policyState() };
    }
    case "proxy:status":
      return {
        proxyEnhancement: {
          settings: guard.proxy,
          phase: "ready",
          endpoint: "受管代理 · 跟随当前网络",
          error: "",
        },
      };
    case "proxy:configure":
      await guard.setProxy(command.settings);
      return {
        proxyEnhancement: {
          settings: guard.proxy,
          phase: "ready",
          endpoint: guard.proxy.mode === "manual" ? guard.proxy.address : "跟随系统代理",
          error: "",
        },
      };
    case "coffee:status":
      return { diagnostics: coffee.report };
    case "coffee:refresh":
      await coffee.refresh();
      return { diagnostics: coffee.report };
    case "extension:status":
      return { extension: await browser.status() };
    case "extension:setup":
      await setupPosixBrowser(process.execPath, path.join(path.dirname(client), "native-host.cjs"));
      await shell.openPath(
        app.isPackaged
          ? path.join(process.resourcesPath, "browser-extension")
          : path.resolve(import.meta.dirname, "../../../browser-extension/dist"),
      );
      return { extension: await browser.status() };
    case "update:status":
      return { appUpdate: updates.state };
    case "update:check":
      return { appUpdate: await updates.check() };
    case "update:download":
      return { appUpdate: await updates.download() };
    case "update:install":
      await updates.install();
      return { appUpdate: updates.state };
    case "update:releases":
      await shell.openExternal("https://github.com/chxcodepro/ip-guard/releases");
      return {};
    case "restart":
      app.relaunch();
      app.quit();
      return {};
    default:
      throw new Error("此平台的系统级防护组件正在移植，当前为受管代理开发版");
  }
  await refreshLaunchers(guard, process.execPath, client);
  return { snapshot: guard.snapshot };
}
async function start() {
  await policies.initialize();
  broker = await preparePosixBroker(guard, process.execPath, client);
  guard.on("snapshot", (snapshot) => send(desktopChannels.update, snapshot));
  coffee.on("update", (report) => send(desktopChannels.coffee, report));
  updates.on("update", (state) => send(desktopChannels.appUpdate, state));
  await guard.initialize();
  await refreshLaunchers(guard, process.execPath, client);
  let pending = Promise.resolve();
  ipcMain.handle(desktopChannels.invoke, async (event, input: unknown) => {
    if (
      event.senderFrame !== event.sender.mainFrame ||
      !isTrustedUrl(event.senderFrame?.url ?? "", devOrigin)
    )
      throw new Error("Untrusted IPC sender");
    const command = commandSchema.parse(input);
    if (
      [
        "status",
        "logs",
        "network:status",
        "proxy:status",
        "claude:status",
        "coffee:status",
        "update:status",
      ].includes(command.action)
    )
      return action(command);
    const work = pending.then(() => action(command));
    pending = work.then(
      () => undefined,
      () => undefined,
    );
    return work;
  });
  if (!devOrigin)
    serveRenderer({
      apiOrigin: "https://api.localhost",
      rendererRoot: path.join(import.meta.dirname, "../renderer"),
    });
  window = createMainWindow({
    devOrigin,
    preload: path.join(import.meta.dirname, "../preload/index.cjs"),
    url: devOrigin ?? rendererOrigin,
    background:
      process.argv.includes("--background") ||
      (process.platform === "darwin" && app.getLoginItemSettings().wasOpenedAtLogin),
  });
  const loaded = new Promise<void>((resolve) =>
    window?.webContents.once("did-finish-load", () => resolve()),
  );
  window.on("close", (event) => {
    if (!quitting) {
      event.preventDefault();
      window?.hide();
    }
  });
  const show = () => {
    window?.show();
    window?.focus();
  };
  const assetRoot = app.isPackaged
    ? process.resourcesPath
    : path.join(import.meta.dirname, "../..");
  tray = new Tray(nativeImage.createFromPath(path.join(assetRoot, "assets/tray.png")));
  tray.setToolTip("IP Guard · 受管代理开发版");
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: "打开 IP Guard", click: show },
      { label: "退出并结束受管会话", click: () => app.quit() },
    ]),
  );
  tray.on("click", show);
  coffee.start();
  updates.start();
  if (process.argv.includes("--posix-smoke")) {
    if (process.env.GITHUB_ACTIONS !== "true")
      throw new Error("Smoke verification is restricted to CI");
    await loaded;
    await new Promise((resolve) => setTimeout(resolve, 1200));
    const image = await window.webContents.capturePage();
    const { mkdir, writeFile } = await import("node:fs/promises");
    const folder = path.resolve("artifacts/posix-smoke");
    await mkdir(folder, { recursive: true });
    await writeFile(path.join(folder, process.platform + ".png"), image.toPNG());
    await writeFile(path.join(folder, process.platform + ".json"), JSON.stringify(guard.snapshot));
    app.quit();
  }
}
if (app.requestSingleInstanceLock()) {
  app.on(
    "ready",
    () =>
      void start().catch((error) => {
        dialog.showErrorBox(
          "IP Guard 启动失败",
          error instanceof Error ? error.message : "启动失败",
        );
        app.exit(1);
      }),
  );
  app.on("activate", () => {
    window?.show();
    window?.focus();
  });
  app.on("second-instance", () => {
    window?.show();
    window?.focus();
  });
  app.on("window-all-closed", () => {});
  app.on("before-quit", () => {
    quitting = true;
    guard.stop();
    browser.close();
    coffee.stop();
    broker?.close();
    tray?.destroy();
  });
} else app.quit();
