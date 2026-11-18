import { spawn } from "node:child_process";
import path from "node:path";

import { app, BrowserWindow, dialog, ipcMain, shell } from "electron";

import {
  commandSchema,
  desktopChannels,
  isClaudeDesktopPath,
  localExceptionPorts,
} from "@ip-guard/electron";
import type { Reply, Snapshot } from "@ip-guard/electron";

import type { BrowserBridge } from "#src/main/browser-bridge.ts";
import type { ClaudeIPv4 } from "#src/main/claude-ip.ts";
import { claudeStatus, stopClaudeTrees } from "#src/main/claude-processes.ts";
import type { CoffeeDiagnostics } from "#src/main/coffee.ts";
import type { FixedEgress } from "#src/main/fixed-egress.ts";
import { guardDataDirectory } from "#src/main/guard-data.ts";
import type { Guardian } from "#src/main/guardian.ts";
import { NativeCommandError, nativePath } from "#src/main/guardian.ts";
import type { NetworkPolicies } from "#src/main/network-policies.ts";
import { claudePresets } from "#src/main/presets.ts";
import type { ProxyEnhancement } from "#src/main/proxy-enhancement.ts";
import { isTrustedUrl } from "#src/main/renderer-route.ts";
import type { ApplicationUpdates } from "#src/main/updates.ts";

export const setupIpc = (
  devOrigin: string | null,
  guardian: Guardian,
  coffee: CoffeeDiagnostics,
  claude: ClaudeIPv4,
  updates: ApplicationUpdates,
  fixedEgress: FixedEgress,
  proxyEnhancement: ProxyEnhancement,
  browser: BrowserBridge,
  networkPolicies: NetworkPolicies,
) => {
  updates.on("update", (state) => {
    for (const window of BrowserWindow.getAllWindows())
      window.webContents.send(desktopChannels.appUpdate, state);
  });
  let stoppingClaude = false;
  let configuringEgress = false;
  let configuringKernel = false;
  let configuringPolicy = false;
  const reconcileEgressFailure = async (error: unknown): Promise<Reply> => {
    let snapshot: Snapshot;
    try {
      snapshot = await guardian.request("status");
    } catch {
      fixedEgress.fail("固定出口设置尚未确认，已保持断网；请恢复守护连接后重试");
      throw error;
    }
    if (!snapshot.egress) {
      await fixedEgress.disable();
      return { snapshot, egress: fixedEgress.state };
    } else fixedEgress.fail("固定出口设置未确认，已保持断网；请重新配置或重启通道");
    throw error;
  };
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
    const policyState = () =>
      networkPolicies.status(
        guardian.snapshot,
        fixedEgress.forwardingAllowed || proxyEnhancement.forwardingAllowed,
      );
    if (command.action === "network:status") return { networkPolicy: policyState() };
    if (command.action === "network:save") {
      if (configuringPolicy || configuringKernel || configuringEgress)
        throw new Error("过滤配置正在处理中，请稍后重试。");
      configuringPolicy = true;
      let started = false,
        committed = false;
      try {
        const snapshot = await guardian.request("status");
        if (!snapshot.admin) throw new Error("请以管理员身份管理拦截策略。");
        const next = networkPolicies.prepare(command.settings),
          previous = networkPolicies.record;
        const ports = localExceptionPorts(next.settings);
        const loopbackOpened = !previous.settings.loopbackDirect && next.settings.loopbackDirect;
        const reload =
          snapshot.apps.some((app) => app.enabled && app.enhanced) && !snapshot.driver.ready;
        const direct = next.settings.rules.filter(
          (rule) =>
            rule.enabled &&
            rule.action === "direct" &&
            !previous.settings.rules.some(
              (old) =>
                old.enabled &&
                old.action === "direct" &&
                old.host === rule.host &&
                old.port === rule.port,
            ),
        );
        if (reload || loopbackOpened || direct.length) {
          const affected = snapshot.apps
            .filter((app) => app.enabled && app.enhanced)
            .map((app) => app.name);
          const answer = await dialog.showMessageBox({
            type: "warning",
            title: "应用拦截策略",
            message: reload
              ? "结束增强会话并重载过滤器？"
              : loopbackOpened
                ? "默认放行全部本机回环？"
                : direct.every((rule) => rule.host === "localhost")
                  ? "放行本机开发端口？"
                  : "允许这些目标直连？",
            detail: [
              reload
                ? "受影响：" +
                  affected.join("、") +
                  "。请先保存工作。过滤器重载可能短暂影响联网，驱动仍处于实验阶段。"
                : "",
              loopbackOpened
                ? "localhost、127.* 和 ::1 的所有端口将直连本机服务，也可连接其他本地代理并绕开固定出口。"
                : "",
              direct.length
                ? "新增直连：" +
                  direct.map((rule) => rule.host + ":" + rule.port).join("、") +
                  "。" +
                  (direct.some((rule) => rule.host !== "localhost")
                    ? "公网直连可能暴露原公网 IP。"
                    : "") +
                  (direct.some((rule) => rule.host === "localhost")
                    ? "本机代理或转发服务可能绕过固定出口。"
                    : "")
                : "",
            ]
              .filter(Boolean)
              .join("\n"),
            buttons: ["取消", "保存并应用"],
            defaultId: 0,
            cancelId: 0,
          });
          if (answer.response !== 1) return { cancelled: true, networkPolicy: policyState() };
        }
        started = true;
        networkPolicies.applying = true;
        fixedEgress.setAllowed(false);
        proxyEnhancement.setAllowed(false);
        await networkPolicies.write(next);
        let applied: Snapshot;
        try {
          applied = await guardian.request("network:apply", {
            policy: {
              revision: next.revision,
              loopbackDirect: next.settings.loopbackDirect,
              localPorts: ports,
            },
          });
        } catch (error) {
          let nativeRestoreError: unknown;
          try {
            const observed = await guardian.request("status");
            if (observed.networkPolicy.revision === next.revision)
              await guardian.request("network:apply", {
                policy: {
                  revision: previous.revision,
                  loopbackDirect: previous.settings.loopbackDirect,
                  localPorts: localExceptionPorts(previous.settings),
                },
              });
          } catch (restoreError) {
            nativeRestoreError = restoreError;
          }
          guardian.networkPolicy = {
            revision: previous.revision,
            loopbackDirect: previous.settings.loopbackDirect,
            localPorts: localExceptionPorts(previous.settings),
          };
          try {
            await networkPolicies.write(previous, false);
          } catch (restoreError) {
            const detail =
              "策略应用失败，恢复原文件也未完成；连接保持暂停，请恢复 network-policy.json.bak。";
            networkPolicies.fail(detail);
            throw new AggregateError([error, restoreError], detail);
          }
          if (nativeRestoreError) {
            const detail = "策略应用失败，原生过滤状态尚未确认；连接保持暂停，请重新应用。";
            networkPolicies.fail(detail);
            throw new AggregateError([error, nativeRestoreError], detail);
          }
          throw error;
        }
        guardian.networkPolicy = {
          revision: next.revision,
          loopbackDirect: next.settings.loopbackDirect,
          localPorts: ports,
        };
        networkPolicies.commit(next);
        committed = true;
        fixedEgress.policyChanged();
        proxyEnhancement.policyChanged();
        void proxyEnhancement.refresh();
        return { snapshot: applied, networkPolicy: policyState() };
      } finally {
        networkPolicies.applying = false;
        configuringPolicy = false;
        if (started && !committed) {
          fixedEgress.policyChanged();
          proxyEnhancement.policyChanged();
          void proxyEnhancement.refresh();
        }
      }
    }
    const verifyEnhancement = async () => {
      const snapshot = await guardian.request("status");
      if (!snapshot.rulesLocked) throw new Error("请先锁定允许的公网 IPv4");
      if (snapshot.egress) throw new Error("请先关闭历史独立出口，再使用当前代理增强");
      await claude.useFixedProxy(proxyEnhancement.probeAddress);
      const checked = await guardian.request("check");
      if (!checked.ready) throw new Error(checked.reason || "公网 IPv4 尚未通过校验");
      if (
        !(await proxyEnhancement.exit.check(
          checked.settings.expectedIps,
          proxyEnhancement.probeAddress,
          true,
        ))
      )
        throw new Error(proxyEnhancement.exit.state.reason);
      return guardian.request("enhancement:state", {
        ready: true,
        reason: proxyEnhancement.exit.state.reason,
        phase: "passed",
      });
    };
    if (command.action === "proxy:status") return { proxyEnhancement: proxyEnhancement.state };
    if (command.action === "proxy:configure") {
      const snapshot = await guardian.request("status");
      if (snapshot.apps.some((target) => target.enabled && target.enhanced))
        throw new Error("请先关闭各程序的增强，再修改上游代理");
      await proxyEnhancement.configure(command.settings);
      return { proxyEnhancement: proxyEnhancement.state };
    }
    if (command.action === "enhance") {
      const snapshot = await guardian.request("status");
      const target = snapshot.apps.find((item) => item.id === command.id);
      if (!target) throw new Error("程序不存在");
      if (target.pathIssue) throw new Error(`${target.name} · ${target.pathIssue}`);
      if (command.enabled) {
        await proxyEnhancement.refresh();
        if (proxyEnhancement.state.phase !== "ready") throw new Error(proxyEnhancement.state.error);
        if (!snapshot.driver.supported)
          throw new Error(
            snapshot.driver.hvci
              ? "请先在命令过滤器中关闭内存完整性，重启后再开启增强"
              : snapshot.driver.error || "此设备的命令过滤器尚未就绪",
          );
      }
      const answer = await dialog.showMessageBox({
        type: "warning",
        title: "本机 IP 防泄露增强",
        message: `${command.enabled ? "开启" : "关闭"} ${target.name} 的增强？`,
        detail: command.enabled
          ? "将停止此程序，自动读取当前 Xray / sing-box / Mihomo 节点并建立仅供受控 Claude 使用的强制代理通道，跟随节点切换；普通应用分流和原代理配置保持。按需安装并加载实验性过滤驱动，封锁此进程树的绕行连接。驱动实机验收尚未完成，曾发生全机断网，建议在隔离测试机使用。"
          : "将停止此程序以调整过滤范围；基础程序防护保留。其他增强会话需先停止。",
        buttons: ["取消", command.enabled ? "确认开启" : "关闭增强"],
        defaultId: 0,
        cancelId: 0,
      });
      if (answer.response !== 1) return { cancelled: true, snapshot };
      const release = command.enabled ? await proxyEnhancement.acquire() : undefined;
      try {
        if (command.enabled) {
          await verifyEnhancement();
          if (!snapshot.driver.installed) await guardian.request("kernel:install");
        }
        return {
          snapshot: await guardian.request("enhance", {
            targetId: command.id,
            enabled: command.enabled,
          }),
        };
      } finally {
        await proxyEnhancement.setNeeded(
          Boolean(guardian.snapshot?.apps.some((app) => app.enabled && app.enhanced)) &&
            !guardian.snapshot?.egress,
        );
        await release?.();
        if (!proxyEnhancement.routeActive && !guardian.snapshot?.egress)
          await claude.useSystemProxy();
      }
    }
    if (command.action.startsWith("kernel:")) {
      if (configuringKernel) throw new Error("命令进程树防护正在处理中");
      configuringKernel = true;
      try {
        const snapshot = await guardian.request("status");
        if (!snapshot.admin) throw new Error("请以管理员身份重启 IP Guard");
        const installing = command.action === "kernel:install";
        const rescuing = command.action === "kernel:rescue";
        if (command.action === "kernel:repair") {
          const stale = snapshot.apps.find(
            (item) => item.enabled && item.enhanced && item.pathIssue,
          );
          if (stale) throw new Error(`${stale.name} · ${stale.pathIssue}`);
        }
        if (snapshot.driver.hvci && !rescuing) {
          const answer = await dialog.showMessageBox({
            type: "warning",
            title: "关闭 Windows 内存完整性",
            message: "关闭内存完整性并在重启后继续？",
            detail:
              "这会降低 Windows 内核防护，卸载 IP Guard 后也会保持关闭。仅修改本机 HVCI 开关；组织策略、UEFI 锁与 Secure Boot 保持原样。当前不会安装或加载驱动。",
            buttons: ["保持开启", "确认关闭"],
            defaultId: 0,
            cancelId: 0,
          });
          if (answer.response !== 1) return { cancelled: true, snapshot };
          const next = await guardian.request("kernel:hvci:disable");
          await dialog.showMessageBox({
            type: "info",
            title: "等待重启",
            message: "关闭请求已保存",
            detail: installing
              ? "保存工作并重启 Windows，之后回到命令过滤器安装驱动。"
              : "保存工作并重启 Windows；IP Guard 启动后会重新检查过滤器。",
            buttons: ["知道了"],
          });
          return { snapshot: next };
        }
        if (!snapshot.driver.supported && !rescuing)
          throw new Error(snapshot.driver.error || "此设备的命令过滤器尚未就绪");
        const answer = await dialog.showMessageBox({
          type: "warning",
          title: installing ? "安装命令防护驱动" : "命令进程树防护",
          message: installing
            ? "安装原版 Fort 签名驱动？"
            : rescuing
              ? "停止受控进程并执行独立恢复？"
              : "加载驱动并启用命令进程树防护？",
          detail: installing
            ? "实验功能，实机验证尚未完成。此次仅复制文件、注册按需服务和自动恢复任务，不加载驱动。"
            : rescuing
              ? "受控进程树将结束，未保存内容可能丢失。恢复只清理 IP Guard 持有的驱动与规则。"
              : "实验功能，实机验证尚未完成，曾发生全机断网。建议仅在独立测试机启用。请先保存并关闭受控程序；加载可能影响全机联网，驱动异常有蓝屏风险。HVCI 开启时拒绝加载，系统安全设置保持原样。",
          buttons: ["取消", installing ? "安装驱动" : rescuing ? "执行恢复" : "加载并启用"],
          defaultId: 0,
          cancelId: 0,
        });
        if (answer.response !== 1) return { cancelled: true, snapshot };
        if (rescuing) {
          fixedEgress.setAllowed(false);
          await new Promise<void>((resolve, reject) => {
            const child = spawn(
              path.join(path.dirname(nativePath()), "IpGuard.Recovery.exe"),
              ["--repair"],
              { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] },
            );
            let failure = "";
            child.stderr?.setEncoding("utf8");
            child.stderr?.on("data", (text: string) => {
              failure = `${failure}${text}`.slice(-4000);
            });
            child.on("error", reject);
            child.on("exit", (code) =>
              code === 0
                ? resolve()
                : reject(new Error(failure || "恢复未完成，请查看独立恢复日志")),
            );
          });
          guardian.start();
          return { snapshot: await guardian.request("status") };
        }
        return { snapshot: await guardian.request(command.action) };
      } finally {
        configuringKernel = false;
      }
    }
    if (command.action === "egress:status") return { egress: fixedEgress.state };
    if (command.action === "egress:disable" || command.action === "egress:retry") {
      if (configuringEgress) throw new Error("固定出口配置正在处理中");
      configuringEgress = true;
      try {
        const snapshot = await guardian.request("status");
        if (command.action === "egress:retry") {
          if (!snapshot.admin || !snapshot.egress) throw new Error("请先启用独立固定出口");
          await guardian.request("egress:pause");
          await fixedEgress.retry(snapshot.egress);
          return { egress: fixedEgress.state };
        }
        if (!snapshot.admin || snapshot.rulesLocked)
          throw new Error("请先以管理员运行并取消 IP 锁定，再配置固定出口");
        if (command.action === "egress:disable") {
          fixedEgress.fail("正在关闭固定出口");
          let next: Snapshot;
          try {
            next = await guardian.request("egress:set", { egress: null });
          } catch (error) {
            return await reconcileEgressFailure(error);
          }
          await fixedEgress.disable();
          return { snapshot: next, egress: fixedEgress.state };
        }
      } finally {
        configuringEgress = false;
      }
    }
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
      const result = await claude.check(command.sourceUrl);
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
      const error = await shell.openPath(guardDataDirectory());
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
        detail: "将结束对应受控进程树，未保存的内容可能丢失。",
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
