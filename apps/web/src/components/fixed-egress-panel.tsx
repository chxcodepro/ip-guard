import { Cable, FolderInput, LoaderCircle, Power, RotateCw } from "lucide-react";
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
  const [label, setLabel] = useState("我的固定节点");
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
  const editable = available && !snapshot.rulesLocked && !waiting;
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
              : "未配置");
  return (
    <section
      className="panel settings-panel fixed-egress-panel"
      aria-labelledby="fixed-egress-title"
    >
      <div className="panel-heading">
        <h2 id="fixed-egress-title">Claude 固定出口</h2>
        <span className={`small-status ${enabled && snapshot.ready ? "good" : ""}`}>
          {enabled ? "已启用" : "未启用"}
        </span>
      </div>
      <div className="setting-row">
        <span className="setting-icon">
          <Cable size={19} />
        </span>
        <div>
          <strong>{snapshot.egress?.label ?? state.profile?.label ?? "独立节点"}</strong>
          <span>Desktop · npm · 原生 Claude Code</span>
        </div>
        <div className="update-actions">
          {enabled ? (
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
                onClick={() => void perform({ action: "egress:disable" })}
              >
                <Power size={14} />
                关闭固定出口
              </button>
            </>
          ) : (
            <button
              type="button"
              className="btn primary"
              disabled={!editable || !state.profile}
              onClick={() => void perform({ action: "egress:enable" })}
            >
              {waiting ? <LoaderCircle size={14} className="spin" /> : <Power size={14} />}
              启用固定出口
            </button>
          )}
        </div>
      </div>
      {!enabled && (
        <div className="egress-import">
          <label htmlFor="fixed-node-label">节点名称</label>
          <div className="egress-import-controls">
            <input
              id="fixed-node-label"
              value={label}
              onChange={(event) => setLabel(event.target.value)}
              maxLength={100}
              disabled={!editable}
            />
            <button
              type="button"
              className="btn"
              disabled={!editable || !label.trim()}
              onClick={() => void perform({ action: "egress:import", label: label.trim() })}
            >
              <FolderInput size={14} />
              导入 v2rayN 当前节点
            </button>
          </div>
        </div>
      )}
      <div
        className={`update-state ${failure || state.error ? "error" : ""}`}
        role="status"
        aria-live="polite"
      >
        {status}
      </div>
      {(snapshot.rulesLocked || !enabled) && (
        <div className="egress-hint">
          {snapshot.rulesLocked
            ? "先取消 IP 锁定，再修改固定出口"
            : "在 v2rayN 选定节点后导入，后续切换主节点不影响此通道"}
        </div>
      )}
    </section>
  );
}
