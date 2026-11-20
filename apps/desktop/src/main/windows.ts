import path from "node:path";

import { app, BrowserWindow, dialog, Menu, nativeImage, Tray } from "electron";

import { rendererOrigin, claudeIpv4Endpoint, nativeVersion } from "@ip-guard/electron";
import type { Snapshot } from "@ip-guard/electron";

import { BrowserBridge } from "#src/main/browser-bridge.ts";
import { notifyBrowserRecovery } from "#src/main/browser-recovery.ts";
import { ClaudeIPv4 } from "#src/main/claude-ip.ts";
import { CoffeeDiagnostics } from "#src/main/coffee.ts";
import { defaultApiOrigin } from "#src/main/config.ts";
import { FixedEgress } from "#src/main/fixed-egress.ts";
import { Guardian } from "#src/main/guardian.ts";
import { setupIpc } from "#src/main/ipc.ts";
import { NetworkPolicies } from "#src/main/network-policies.ts";
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
if (process.platform === "win32") {
  app.setAppUserModelId("com.ip-guard.desktop");
  app.setToastActivatorCLSID("3B1AB47E-04D1-4A2F-969D-3127D6908544");
}
const guardian = new Guardian(claude);
const networkPolicies = new NetworkPolicies();
const fixedEgress = new FixedEgress(claude, networkPolicies);
const proxyEnhancement = new ProxyEnhancement(networkPolicies);
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
const smoke = process.argv.includes("--windows-smoke");
if (smoke && process.env.GITHUB_ACTIONS !== "true")
  throw new Error("Windows smoke verification is restricted to CI");

const open = () =>
  createMainWindow({
    devOrigin,
    preload: path.join(import.meta.dirname, "../preload/index.cjs"),
    url: devOrigin ?? `${rendererOrigin}/`,
    background,
  });

const start = async () => {
  const initialSnapshot = smoke
    ? new Promise<Snapshot>((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error(guardian.error || "Native handshake timed out")),
          25000,
        );
        guardian.once("snapshot", (snapshot) => {
          clearTimeout(timer);
          resolve(snapshot);
        });
      })
    : undefined;
  void initialSnapshot?.catch(() => undefined);
  await networkPolicies.initialize();
  await fixedEgress.initialize();
  await proxyEnhancement.initialize();
  guardian.enhancementPolicy = proxyEnhancement.policy;
  guardian.networkPolicy = networkPolicies.kernelPolicy;
  setupIpc(
    devOrigin,
    guardian,
    coffee,
    claude,
    updates,
    fixedEgress,
    proxyEnhancement,
    browserBridge,
    networkPolicies,
  );
  let proxySelected = false;
  let proxyRechecking = false;
  let routeDeclined = false;
  let policyConflict = "";
  const updateProxyCore = async () => {
    let snapshot = guardian.snapshot;
    if (snapshot) networkPolicies.observeKernel(snapshot.networkPolicy.revision);
    proxyEnhancement.setProbeSource(snapshot?.settings.ipv4Url ?? claudeIpv4Endpoint);
    const conflict =
      networkPolicies.error ||
      (snapshot?.online && !networkPolicies.applying && !networkPolicies.confirmed
        ? "策略尚未获得原生确认，请重新应用。"
        : "");
    if (snapshot?.online && conflict && conflict !== policyConflict) {
      policyConflict = conflict;
      await guardian.request("network:invalidate", { reason: conflict });
    } else if (!conflict) policyConflict = "";
    const needed = Boolean(snapshot?.apps.some((app) => app.enabled && app.enhanced));
    if (needed && !snapshot?.egress && proxyEnhancement.needsApproval && !routeDeclined) {
      const answer = await dialog.showMessageBox({
        type: "warning",
        title: "Claude 专用代理路由",
        message: "为已开启增强的程序建立专用代理通道？",
        detail:
          "将自动读取本机 Xray / sing-box / Mihomo 当前节点，创建仅供受控 Claude 使用的强制代理路由，并跟随节点切换。普通应用继续沿用现有分流；原代理配置保持。实验性命令过滤驱动的实机恢复验收仍未完成。",
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
    if (
      !networkPolicies.applying &&
      snapshot?.ready &&
      needed &&
      (snapshot.egress || (proxyEnhancement.routeActive && proxyEnhancement.sourceReady))
    )
      void proxyEnhancement.exit
        .check(
          snapshot.settings.expectedIps,
          snapshot.egress ? fixedEgress.probeAddress : proxyEnhancement.probeAddress,
        )
        .catch((error) => console.error("增强出口复核", error));
    const enforcerReady = !needed || Boolean(snapshot?.driver.ready);
    proxyEnhancement.setAllowed(
      Boolean(snapshot?.ready) && enforcerReady && !proxyRechecking && !snapshot?.egress,
    );
    fixedEgress.setAllowed(
      Boolean(snapshot?.egress) &&
        Boolean(snapshot?.ready) &&
        enforcerReady &&
        (!snapshot?.apps.some((target) => target.enabled && target.enhanced) ||
          proxyEnhancement.exit.ready),
    );
    if (snapshot?.online) {
      const routeMissing =
        Boolean(conflict) || (needed && !snapshot.egress && !proxyEnhancement.routeActive);
      const ready =
        !networkPolicies.applying &&
        enforcerReady &&
        snapshot.ready &&
        !routeMissing &&
        proxyEnhancement.exit.ready;
      const reason = networkPolicies.applying
        ? "正在应用拦截策略"
        : routeMissing
          ? conflict || proxyEnhancement.state.error || "等待确认 Claude 专用代理通道"
          : !enforcerReady
            ? snapshot.driver.error || "等待内核过滤配置就绪"
            : proxyEnhancement.state.error
              ? `${proxyEnhancement.state.error}；${proxyEnhancement.exit.state.reason}`
              : proxyEnhancement.exit.state.reason;
      const phase = networkPolicies.applying
        ? "checking"
        : routeMissing
          ? "failed"
          : !enforcerReady
            ? snapshot.driver.error
              ? "failed"
              : "checking"
            : proxyEnhancement.exit.state.phase;
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
  proxyEnhancement.onDiagnostic = (level, message) => {
    if (level === "warning" && message.startsWith("专用核心"))
      protectionAlerts.notifyProxyCoreFailure();
    else if (level === "info") protectionAlerts.resetProxyCoreFailure();
    if (guardian.snapshot?.online)
      void guardian
        .request("proxy:diagnostic", { level, message })
        .catch((error) => console.error("代理诊断记录", error));
    else console.warn(message);
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
  const loaded = smoke
    ? new Promise<void>((resolve) => win.webContents.once("did-finish-load", () => resolve()))
    : undefined;
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
  guardian.on("snapshot", (snapshot: Snapshot) => {
    const enhancedRunning = snapshot.apps.some(
      (target) => target.enhanced && snapshot.running.includes(target.id),
    );
    const status = !snapshot.online
      ? "守护连接已中断"
      : !snapshot.ready
        ? `联网已暂停 · ${snapshot.reason}`
        : enhancedRunning && !snapshot.enhancementReady
          ? `增强联网已暂停 · ${snapshot.enhancementReason}`
          : enhancedRunning && proxyEnhancement.state.error
            ? "增强出口已验证 · 代理来源复核中"
            : "IPv4 匹配";
    tray?.setToolTip(`IP Guard · ${status}`.slice(0, 120));
  });
  if (smoke) {
    try {
      const snapshot = await initialSnapshot;
      if (
        !snapshot?.online ||
        snapshot.nativeVersion !== nativeVersion ||
        snapshot.apps.length ||
        snapshot.driver.enabled
      )
        throw new Error("Fresh native smoke state did not match the packaged version");
      await loaded;
      await win.webContents.executeJavaScript("document.fonts.ready.then(() => true)");
      const { mkdir, writeFile } = await import("node:fs/promises");
      const folder = path.resolve("artifacts/windows-release-smoke");
      await mkdir(folder, { recursive: true });
      await writeFile(
        path.join(folder, "windows.png"),
        (await win.webContents.capturePage()).toPNG(),
      );
      await writeFile(path.join(folder, "windows.json"), JSON.stringify(snapshot));
      app.quit();
    } catch (error) {
      console.error(error);
      app.exit(1);
    }
  }
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
