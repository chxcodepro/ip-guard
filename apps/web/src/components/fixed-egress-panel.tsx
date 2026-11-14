import { Cable, Power, RotateCw } from "lucide-react";
import { useEffect, useState } from "react";

import type { Command, EgressState, Reply, Snapshot } from "@ip-guard/electron";

export function FixedEgressPanel({
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
  const [state, setState] = useState<EgressState>({ profile: null, phase: "disabled", error: "" });
  const [failure, setFailure] = useState("");
  useEffect(() => {
    if (!bridge) return;
    let alive = true;
    let pending = false;
    const refresh = async () => {
      if (pending) return;
      pending = true;
      try {
        const reply = await bridge.invoke({ action: "egress:status" });
        if (alive && reply.egress) {
          setState(reply.egress);
          setFailure("");
        }
      } catch {
        if (alive) setFailure("固定出口状态读取失败");
      } finally {
        pending = false;
      }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 2000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [bridge]);
  const perform = async (command: Command) => {
    const reply = await onAction(command);
    if (reply?.egress) setState(reply.egress);
  };
  const enabled = Boolean(snapshot.egress);
  const waiting = busy || state.phase === "starting";
  const editable = available && !snapshot.rulesLocked && !waiting && !snapshot.driver.enabled;
  const status =
    failure ||
    state.error ||
    (!bridge
      ? "请在 Windows 桌面版配置"
      : !snapshot.online
        ? "等待守护连接"
        : state.phase === "starting"
          ? "正在建立固定通道"
          : enabled
            ? snapshot.rulesLocked
              ? snapshot.ready
                ? "固定通道已连接"
                : "联网已暂停 · 正在复核出口"
              : "节点已固定 · 待锁定 IP"
            : state.profile
              ? "节点已导入 · 待启用"
              : "跟随当前网络");
  return (
    <div
      className="settings-group fixed-egress-panel"
      role="group"
      aria-labelledby="fixed-egress-title"
    >
      <div className="setting-row">
        <span className="setting-icon">
          <Cable size={19} />
        </span>
        <div className="setting-info">
          <strong id="fixed-egress-title">历史独立出口</strong>
          {(snapshot.egress?.label || state.profile?.label) && (
            <span className="setting-detail">{snapshot.egress?.label ?? state.profile?.label}</span>
          )}
        </div>
        <span className={`small-status ${enabled && snapshot.ready ? "good" : ""}`}>
          {enabled ? "已启用" : "未启用"}
        </span>
        <div className="update-actions">
          <>
            {state.phase === "failed" && (
              <button
                type="button"
                className="btn"
                disabled={!available || waiting}
                onClick={() => void perform({ action: "egress:retry" })}
              >
                <RotateCw size={14} />
                重启通道
              </button>
            )}
            <button
              type="button"
              className="btn"
              disabled={!editable}
              title={!editable ? "先关闭命令进程树保护并取消 IP 锁定，再切换联网方式" : undefined}
              onClick={() => void perform({ action: "egress:disable" })}
            >
              <Power size={14} />
              改为跟随当前网络
            </button>
          </>
        </div>
      </div>
      <div
        className={`update-state ${failure || state.error ? "error" : ""}`}
        role="status"
        aria-live="polite"
      >
        {status}
      </div>
    </div>
  );
}
