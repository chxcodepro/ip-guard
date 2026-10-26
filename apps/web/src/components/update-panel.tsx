import { ArrowDownToLine, ExternalLink, LoaderCircle, RefreshCw } from "lucide-react";
import { useEffect, useState } from "react";

import { nativeVersion } from "@ip-guard/electron";
import type { Command, UpdateState } from "@ip-guard/electron";

export function UpdatePanel() {
  const bridge = window.desktop;
  const [state, setState] = useState<UpdateState>({
    phase: "unconfigured",
    currentVersion: nativeVersion,
    latestVersion: "",
    progress: 0,
    checkedAt: "",
    message: "GitHub 更新源未配置",
    repository: "",
  });
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!bridge) return;
    let alive = true;
    const unsubscribe = bridge.subscribeAppUpdate((value) => {
      if (alive) setState(value);
    });
    void bridge
      .invoke({ action: "update:status" })
      .then((reply) => {
        if (alive && reply.appUpdate) setState(reply.appUpdate);
      })
      .catch((error) => {
        if (alive)
          setState((value) => ({
            ...value,
            phase: "error",
            message: error instanceof Error ? error.message : "读取更新状态失败",
          }));
      });
    return () => {
      alive = false;
      unsubscribe();
    };
  }, [bridge]);
  const invoke = async (action: Command) => {
    if (!bridge) return;
    setBusy(true);
    try {
      const reply = await bridge.invoke(action);
      if (reply.appUpdate) setState(reply.appUpdate);
    } catch (error) {
      setState((value) => ({
        ...value,
        phase: "error",
        message: error instanceof Error ? error.message : "更新操作失败",
      }));
    } finally {
      setBusy(false);
    }
  };
  const waiting = busy || ["checking", "downloading", "installing"].includes(state.phase);
  return (
    <section className="panel settings-panel update-panel">
      <div className="panel-heading">
        <h2>软件更新</h2>
        <span className="subtle-label">GITHUB RELEASES</span>
      </div>
      <div className="setting-row">
        <span className="setting-icon">
          <ArrowDownToLine size={19} />
        </span>
        <div>
          <strong>当前版本 {state.currentVersion}</strong>
          {state.latestVersion && <span>最新版本 {state.latestVersion}</span>}
        </div>
        <div className="update-actions">
          {state.repository && (
            <button className="btn" onClick={() => void invoke({ action: "update:releases" })}>
              <ExternalLink size={14} />
              Releases
            </button>
          )}
          <button
            className="btn"
            disabled={!bridge || waiting || state.phase === "unconfigured"}
            onClick={() => void invoke({ action: "update:check" })}
          >
            {waiting ? <LoaderCircle className="spin" size={14} /> : <RefreshCw size={14} />}
            检查更新
          </button>
          {state.phase === "available" && (
            <button
              className="btn primary"
              disabled={waiting}
              onClick={() => void invoke({ action: "update:download" })}
            >
              <ArrowDownToLine size={14} />
              下载更新
            </button>
          )}
          {state.phase === "downloaded" && (
            <button
              className="btn primary"
              disabled={waiting}
              onClick={() => void invoke({ action: "update:install" })}
            >
              安装并重启
            </button>
          )}
        </div>
      </div>
      {state.phase === "downloading" && (
        <div
          className="update-progress"
          role="progressbar"
          aria-label="更新下载进度"
          aria-valuenow={Math.round(state.progress)}
          aria-valuemin={0}
          aria-valuemax={100}
        >
          <span style={{ width: `${state.progress}%` }} />
        </div>
      )}
      <div className={`update-state ${state.phase === "error" ? "error" : ""}`} role="status">
        {state.message || "等待检查"}
        {state.checkedAt && (
          <time>{new Date(state.checkedAt).toLocaleTimeString("zh-CN", { hour12: false })}</time>
        )}
      </div>
    </section>
  );
}
