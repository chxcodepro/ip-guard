import { Download, LoaderCircle, Power, RotateCw, ShieldCheck } from "lucide-react";

import type { Command, Reply, Snapshot } from "@ip-guard/electron";

export function CommandProtectionPanel({
  snapshot,
  busy,
  available,
  onAction,
}: {
  snapshot: Snapshot;
  busy: boolean;
  available: boolean;
  onAction: (command: Command) => Promise<Reply | undefined>;
}) {
  const driver = snapshot.driver;
  const waiting = busy || driver.phase === "starting";
  const status = !snapshot.online
    ? "等待守护连接"
    : driver.error ||
      (!snapshot.admin
        ? "以管理员身份重启后管理驱动"
        : driver.phase === "starting"
          ? "正在建立内核进程树防护"
          : driver.ready
            ? snapshot.ready
              ? "程序及常规子进程已通过固定出口联网"
              : "进程树已保护 · 联网等待 IP 校验"
            : driver.installed && !snapshot.apps.some((item) => item.enabled)
              ? "先选择并启用受保护程序"
              : driver.installed
                ? "驱动已安装，可在程序列表选择防泄露增强项"
                : "驱动尚未安装");
  return (
    <div className="settings-group" role="group" aria-labelledby="command-protection-title">
      <div className="setting-row">
        <span className="setting-icon">
          <ShieldCheck size={19} />
        </span>
        <div className="setting-info">
          <strong id="command-protection-title">命令过滤器</strong>
        </div>
        <span className={`small-status ${driver.ready ? "good" : ""}`}>
          {driver.ready
            ? "已启用"
            : driver.loaded
              ? "已加载"
              : driver.installed
                ? "已安装"
                : "未安装"}
        </span>
        <div className="update-actions">
          {!driver.installed ? (
            <button
              type="button"
              className="btn primary"
              disabled={!available || !driver.supported || waiting}
              onClick={() => void onAction({ action: "kernel:install" })}
            >
              {waiting ? <LoaderCircle size={14} className="spin" /> : <Download size={14} />}
              安装驱动
            </button>
          ) : (
            <>
              {driver.error && (
                <button
                  type="button"
                  className="btn"
                  disabled={!available || waiting}
                  onClick={() => void onAction({ action: "kernel:rescue" })}
                >
                  <RotateCw size={14} />
                  独立恢复
                </button>
              )}
              {driver.enabled && !driver.ready && (
                <button
                  type="button"
                  className="btn primary"
                  disabled={!available || waiting}
                  onClick={() => void onAction({ action: "kernel:repair" })}
                >
                  {waiting ? <LoaderCircle size={14} className="spin" /> : <Power size={14} />}
                  修复过滤器
                </button>
              )}
            </>
          )}
        </div>
      </div>
      <div
        className={`update-state ${driver.error ? "error" : ""}`}
        role="status"
        aria-live="polite"
      >
        {status}
      </div>
    </div>
  );
}
