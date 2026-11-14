import path from "node:path";

import { app, BrowserWindow, dialog, Menu, nativeImage, Tray } from "electron";

import { rendererOrigin } from "@ip-guard/electron";

import { BrowserBridge } from "#src/main/browser-bridge.ts";
import { notifyBrowserRecovery } from "#src/main/browser-recovery.ts";
import { ClaudeIPv4 } from "#src/main/claude-ip.ts";
import { CoffeeDiagnostics } from "#src/main/coffee.ts";
import { defaultApiOrigin } from "#src/main/config.ts";
import { FixedEgress } from "#src/main/fixed-egress.ts";
import { Guardian } from "#src/main/guardian.ts";
import { setupIpc } from "#src/main/ipc.ts";
import { ProtectionAlerts } from "#src/main/protection-alerts.ts";
import { ProxyEnhancement } from "#src/main/proxy-enhancement.ts";
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
const fixedEgress = new FixedEgress(claude);
const proxyEnhancement = new ProxyEnhancement();
const coffee = new CoffeeDiagnostics(claude);
const protectionAlerts = new ProtectionAlerts(guardian, () => {
  const [win] = BrowserWindow.getAllWindows();
  if (win) {
    win.show();
    if (win.isMinimized()) win.restore();
    win.focus();
  }
});
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
const browserBridge = new BrowserBridge(guardian, updates);
let tray: Tray | undefined;
const background = process.argv.includes("--background");

const open = () =>
  createMainWindow({
    devOrigin,
    preload: path.join(import.meta.dirname, "../preload/index.cjs"),
    url: devOrigin ?? `${rendererOrigin}/`,
    background,
  });

const start = async () => {
  await fixedEgress.initialize();
  await proxyEnhancement.initialize();
  guardian.enhancementPolicy = proxyEnhancement.policy;
  setupIpc(
    devOrigin,
    guardian,
    coffee,
    claude,
    updates,
    fixedEgress,
    proxyEnhancement,
    browserBridge,
  );
  let proxySelected = false;
  let proxyRechecking = false;
  let routeDeclined = false;
  const updateProxyCore = async () => {
    let snapshot = guardian.snapshot;
    const needed = Boolean(snapshot?.apps.some((app) => app.enabled && app.enhanced));
    if (needed && !snapshot?.egress && proxyEnhancement.needsApproval && !routeDeclined) {
      const answer = await dialog.showMessageBox({
        type: "warning",
        title: "Claude 专用代理路由",
        message: "为已开启增强的程序建立专用代理通道？",
        detail:
          "将自动读取本机 Xray / sing-box 当前节点，创建仅供受控 Claude 使用的强制代理路由，并跟随节点切换。普通应用继续沿用现有分流；原代理配置保持。实验性命令过滤驱动的实机恢复验收仍未完成。",
        buttons: ["暂不开启", "确认建立专用通道"],
        defaultId: 0,
        cancelId: 0,
      });
      if (answer.response === 1) proxyEnhancement.approve();
      else routeDeclined = true;
    }
    await proxyEnhancement.setNeeded(needed && !snapshot?.egress);
    snapshot = guardian.snapshot;
    const selected =
      !snapshot?.egress && proxyEnhancement.routeActive && (needed || proxyEnhancement.routeHeld);
    if (snapshot && (!snapshot.ready || !snapshot.rulesLocked))
      proxyEnhancement.exit.invalidate("等待基础 IPv4 校验通过后复核增强出口");
    if (snapshot?.ready && needed && (snapshot.egress || proxyEnhancement.routeActive))
      void proxyEnhancement.exit
        .check(
          snapshot.settings.expectedIps,
          snapshot.egress ? fixedEgress.probeAddress : proxyEnhancement.probeAddress,
        )
        .catch((error) => console.error("增强出口复核", error));
    proxyEnhancement.setAllowed(Boolean(snapshot?.ready) && !proxyRechecking && !snapshot?.egress);
    fixedEgress.setAllowed(
      Boolean(snapshot?.egress) &&
        Boolean(snapshot?.ready) &&
        (!snapshot?.apps.some((target) => target.enabled && target.enhanced) ||
          proxyEnhancement.exit.ready),
    );
    if (snapshot?.online) {
      const routeMissing = needed && !snapshot.egress && !proxyEnhancement.routeActive;
      const ready = snapshot.ready && !routeMissing && proxyEnhancement.exit.ready;
      const reason = routeMissing
        ? proxyEnhancement.state.error || "等待确认 Claude 专用代理通道"
        : proxyEnhancement.exit.state.reason;
      const phase = routeMissing ? "failed" : proxyEnhancement.exit.state.phase;
      if (
        snapshot.enhancementReady !== ready ||
        snapshot.enhancementReason !== reason ||
        snapshot.enhancementPhase !== phase
      )
        await guardian.request("enhancement:state", { ready, reason, phase });
    }
    if (selected !== proxySelected) {
      proxySelected = selected;
      if (selected) await claude.useFixedProxy(proxyEnhancement.probeAddress);
      else if (!snapshot?.egress) await claude.useSystemProxy();
    }
  };
  let updatingProxy: Promise<void> | undefined;
  let proxyUpdateRequested = false;
  const updateProxy = (): Promise<void> => {
    proxyUpdateRequested = true;
    if (updatingProxy) return updatingProxy;
    const work = (async () => {
      while (proxyUpdateRequested) {
        proxyUpdateRequested = false;
        await updateProxyCore();
      }
    })();
    updatingProxy = work;
    void work
      .finally(() => {
        if (updatingProxy === work) updatingProxy = undefined;
      })
      .catch(() => undefined);
    return work;
  };
  guardian.on(
    "snapshot",
    () => void updateProxy().catch((error) => console.error("增强检测通道", error)),
  );
  proxyEnhancement.onChange = () => {
    proxyRechecking = true;
    proxyEnhancement.setAllowed(false);
    void updateProxy()
      .then(() => (guardian.snapshot?.online ? guardian.request("proxy:changed") : undefined))
      .catch((error) => console.error("代理变化复核", error))
      .finally(() => {
        proxyRechecking = false;
        void updateProxy().catch((error) => console.error("代理状态恢复", error));
      });
  };
  proxyEnhancement.onVerificationChange = () => {
    queueMicrotask(() => {
      void updateProxy().catch((error) => console.error("增强出口状态", error));
    });
  };
  await updateProxy();
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
  void notifyBrowserRecovery(win).catch((error) => console.error("旧浏览器扩展恢复提示", error));
  win.on("close", (event) => {
    if (!quitting && !quittingForUpdate) {
      event.preventDefault();
      win.hide();
    }
  });
  const show = () => {
    void updates.check();
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
          if (
            (guardian.snapshot?.running.length ?? 0) +
              (guardian.snapshot?.otherModelRunning.length ?? 0) >
            0
          ) {
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
  guardian.on("snapshot", (snapshot) => {
    tray?.setToolTip(`IP Guard · ${snapshot.ready ? "IPv4 匹配" : snapshot.reason}`.slice(0, 120));
  });
};

if (app.requestSingleInstanceLock()) {
  app.on("ready", start);
  app.on("activate", () => {
    void updates.check();
    if (BrowserWindow.getAllWindows().length === 0) {
      open();
    }
  });
  app.on("second-instance", () => {
    void updates.check();
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
    protectionAlerts.stop();
    browserBridge.close();
    coffee.stop();
    void guardian.stop().finally(async () => {
      try {
        await fixedEgress.stop();
        await proxyEnhancement.stop();
      } finally {
        claude.stop();
        quittingNative = true;
        tray?.destroy();
        app.quit();
      }
    });
  });
} else {
  app.quit();
}
