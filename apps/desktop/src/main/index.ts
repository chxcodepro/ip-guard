import path from "node:path";

import { app, BrowserWindow, dialog, Menu, nativeImage, Notification, Tray } from "electron";

import { rendererOrigin } from "@ip-guard/electron";

import { ClaudeIPv4 } from "#src/main/claude-ip.ts";
import { CoffeeDiagnostics } from "#src/main/coffee.ts";
import { defaultApiOrigin } from "#src/main/config.ts";
import { Guardian } from "#src/main/guardian.ts";
import { setupIpc } from "#src/main/ipc.ts";
import { parseHttpOrigin, parseLoopbackOrigin } from "#src/main/renderer-route.ts";
import { serveRenderer } from "#src/main/renderer.ts";
import { ApplicationUpdates } from "#src/main/updates.ts";
import { createMainWindow } from "#src/main/window.ts";

const origin = (name: string, parse: (value: string) => string | null) => {
  const value = process.env[name];

  if (value === undefined || value === "") {
    return null;
  }

  const parsed = parse(value);

  if (parsed === null) {
    throw new Error(`${name} is not a valid origin: ${value}`);
  }

  return parsed;
};

const devOrigin = origin("ELECTRON_RENDERER_URL", parseLoopbackOrigin);

const apiOrigin = origin("API_ORIGIN", parseHttpOrigin) ?? parseHttpOrigin(defaultApiOrigin);

if (apiOrigin === null) {
  throw new Error(`defaultApiOrigin is not an origin: ${defaultApiOrigin}`);
}

const claude = new ClaudeIPv4();
const guardian = new Guardian(claude);
const coffee = new CoffeeDiagnostics(claude);
let quitting = false;
let quittingNative = false;
let quittingForUpdate = false;
const updates = new ApplicationUpdates(
  () => {
    quittingForUpdate = true;
  },
  () => {
    quittingForUpdate = false;
  },
);
let tray: Tray | undefined;
const background = process.argv.includes("--background");

const open = () =>
  createMainWindow({
    devOrigin,
    preload: path.join(import.meta.dirname, "../preload/index.cjs"),
    url: devOrigin ?? `${rendererOrigin}/`,
    background,
  });

const start = () => {
  setupIpc(devOrigin, guardian, coffee, claude, updates);
  guardian.start();
  coffee.start();
  updates.start();

  if (devOrigin === null) {
    serveRenderer({
      apiOrigin,
      rendererRoot: path.join(import.meta.dirname, "../renderer"),
    });
  }

  const win = open();
  win.on("close", (event) => {
    if (!quitting && !quittingForUpdate) {
      event.preventDefault();
      win.hide();
    }
  });
  const show = () => {
    win.show();
    if (win.isMinimized()) win.restore();
    win.focus();
  };
  tray = new Tray(
    nativeImage.createFromPath(
      path.join(
        app.isPackaged ? process.resourcesPath : path.join(import.meta.dirname, "../.."),
        "assets/tray.png",
      ),
    ),
  );
  tray.setToolTip("IP Guard · 公网 IPv4 守卫");
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: "打开 IP Guard", click: show },
      { type: "separator" },
      {
        label: "退出并结束受保护程序",
        click: async () => {
          if ((guardian.snapshot?.running.length ?? 0) > 0) {
            const choice = await dialog.showMessageBox({
              type: "warning",
              message: "退出将结束所有受保护程序，启动拦截会继续保留。",
              buttons: ["取消", "退出"],
              defaultId: 0,
              cancelId: 0,
            });
            if (choice.response !== 1) return;
          }
          app.quit();
        },
      },
    ]),
  );
  tray.on("double-click", show);
  let prior = "";
  guardian.on("snapshot", (snapshot) => {
    tray?.setToolTip(`IP Guard · ${snapshot.ready ? "IPv4 匹配" : snapshot.reason}`.slice(0, 120));
    if (
      snapshot.reason &&
      snapshot.reason !== prior &&
      snapshot.apps.some((target: { enabled: boolean }) => target.enabled)
    ) {
      new Notification({ title: "IP Guard · 已阻断", body: snapshot.reason }).show();
    }
    prior = snapshot.reason;
  });
};

if (app.requestSingleInstanceLock()) {
  app.on("ready", start);
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      open();
    }
  });
  app.on("second-instance", () => {
    const [win] = BrowserWindow.getAllWindows();
    win?.show();
    win?.focus();
  });
  app.on("window-all-closed", () => {
    if (quitting) app.quit();
  });
  app.on("before-quit", (event) => {
    if (quittingNative) return;
    event.preventDefault();
    if (quitting) return;
    quitting = true;
    coffee.stop();
    void guardian.stop().finally(() => {
      claude.stop();
      quittingNative = true;
      tray?.destroy();
      app.quit();
    });
  });
} else {
  app.quit();
}
