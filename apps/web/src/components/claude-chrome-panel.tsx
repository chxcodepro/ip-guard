import { Globe, Download, ExternalLink, LoaderCircle, RefreshCw, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";

import { isClaudeChromePath } from "@ip-guard/electron";
import type { ClaudeChromeState, Command, Reply, Snapshot } from "@ip-guard/electron";

export function ClaudeChromePanel({
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
  const bridge = window.desktop;
  const [state, setState] = useState<ClaudeChromeState>({
    prepared: false,
    path: "",
    version: "",
    sourceVersion: "",
    extensionInstalled: false,
    error: "",
  });
  const [preparing, setPreparing] = useState(false);
  useEffect(() => {
    if (!bridge) return;
    let alive = true,
      pending = false;
    const refresh = async () => {
      if (pending || document.hidden) return;
      pending = true;
      try {
        const reply = await bridge.invoke({ action: "chrome:status" });
        if (alive && reply.chrome) setState(reply.chrome);
      } catch {
        if (alive) setState((previous) => ({ ...previous, error: "专用 Chrome 状态读取失败" }));
      } finally {
        pending = false;
      }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5000);
    const focus = () => void refresh();
    window.addEventListener("focus", focus);
    document.addEventListener("visibilitychange", focus);
    return () => {
      alive = false;
      window.clearInterval(timer);
      window.removeEventListener("focus", focus);
      document.removeEventListener("visibilitychange", focus);
    };
  }, [bridge]);
  const target = snapshot.apps.find((item) => isClaudeChromePath(item.path));
  const running = Boolean(target && snapshot.running.includes(target.id));
  const perform = async (command: Command) => {
    if (command.action === "chrome:prepare") setPreparing(true);
    try {
      const reply = await onAction(command);
      if (reply?.chrome) setState(reply.chrome);
    } finally {
      setPreparing(false);
    }
  };
  const disabled = busy || preparing || !available;
  const canStart = Boolean(target?.enabled && snapshot.egress && snapshot.rulesLocked);
  const reason =
    (state.error ? "状态异常" : "") ||
    (!snapshot.online
      ? "守护未连接"
      : !snapshot.admin
        ? "需要管理员权限"
        : !state.prepared
          ? "未准备"
          : !snapshot.egress
            ? "固定出口未启用"
            : !snapshot.rulesLocked
              ? "IP 未锁定"
              : !target?.enabled
                ? "程序防护未开启"
                : running
                  ? "正在运行"
                  : "已就绪");
  const newer = Boolean(
    state.sourceVersion &&
    state.sourceVersion.localeCompare(state.version, "en", { numeric: true }) > 0,
  );
  return (
    <section
      className="panel settings-panel claude-chrome-panel"
      aria-labelledby="claude-chrome-heading"
    >
      <div className="panel-heading">
        <h2 id="claude-chrome-heading">Claude in Chrome</h2>
        <span
          className={`small-status ${running && !state.error && snapshot.online ? "good" : ""}`}
          role="status"
        >
          {reason}
        </span>
      </div>
      <div className="setting-row">
        <span className="setting-icon">
          <Globe size={19} />
        </span>
        <div>
          {state.prepared ? (
            <>
              <strong>Chrome {state.version}</strong>
              <span className="small-status">
                {state.error
                  ? "插件状态未知"
                  : state.extensionInstalled
                    ? "Claude 插件已安装"
                    : "Claude 插件未安装"}
              </span>
            </>
          ) : (
            <strong>专用 Chrome 窗口</strong>
          )}
        </div>
        <div className="update-actions">
          {!state.prepared || !target ? (
            <button
              type="button"
              className="btn primary"
              disabled={disabled}
              onClick={() => void perform({ action: "chrome:prepare" })}
            >
              {preparing ? <LoaderCircle size={14} className="spin" /> : <Download size={14} />}
              {preparing ? "正在准备" : state.prepared ? "添加防护程序" : "准备专用窗口"}
            </button>
          ) : (
            <>
              {newer && (
                <button
                  type="button"
                  className="btn"
                  disabled={disabled || target.enabled}
                  title={target.enabled ? "先解除专用 Chrome 的防护后更新" : undefined}
                  onClick={() => void perform({ action: "chrome:prepare" })}
                >
                  <RefreshCw size={14} />
                  更新 Chrome
                </button>
              )}
              {!target.enabled ? (
                <button
                  type="button"
                  className="btn primary"
                  disabled={disabled || !snapshot.egress || !snapshot.rulesLocked}
                  onClick={() => void perform({ action: "protect", id: target.id, enabled: true })}
                >
                  <ShieldCheck size={14} />
                  开启防护
                </button>
              ) : (
                <button
                  type="button"
                  className="btn primary"
                  disabled={disabled || !canStart}
                  onClick={() =>
                    void perform({
                      action: "chrome:open",
                      install: !state.extensionInstalled && !state.error,
                    })
                  }
                >
                  <ExternalLink size={14} />
                  {state.extensionInstalled || state.error ? "打开专用窗口" : "安装 Claude 插件"}
                </button>
              )}
            </>
          )}
        </div>
      </div>
      {state.error && (
        <div className="update-state error" role="alert">
          {state.error}
        </div>
      )}
    </section>
  );
}
