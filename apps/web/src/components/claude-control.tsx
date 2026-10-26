import { LoaderCircle, Square } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";

import type { ClaudeState } from "@ip-guard/electron";

export function ClaudeControl() {
  const bridge = window.desktop;
  const [state, setState] = useState<ClaudeState>({
    phase: "unknown",
    count: 0,
    canStop: false,
    message: "",
    checkedAt: "",
  });
  const [loading, setLoading] = useState(Boolean(bridge));
  const [stopping, setStopping] = useState(false);
  const stoppingRef = useRef(false);
  const version = useRef(0);
  useEffect(() => {
    if (!bridge) return;
    let alive = true,
      pending = false;
    const refresh = async () => {
      if (pending || stoppingRef.current) return;
      pending = true;
      const current = ++version.current;
      try {
        const reply = await bridge.invoke({ action: "claude:status" });
        if (alive && current === version.current && reply.claude) setState(reply.claude);
      } catch {
        if (alive && current === version.current)
          setState({
            phase: "unknown",
            count: 0,
            canStop: false,
            message: "进程状态读取失败",
            checkedAt: "",
          });
      } finally {
        pending = false;
        if (alive) setLoading(false);
      }
    };
    void refresh();
    const visible = () => {
      if (document.visibilityState === "visible") void refresh();
    };
    const timer = setInterval(visible, 3000);
    document.addEventListener("visibilitychange", visible);
    return () => {
      alive = false;
      clearInterval(timer);
      document.removeEventListener("visibilitychange", visible);
    };
  }, [bridge]);
  const stop = async () => {
    if (!bridge || stoppingRef.current) return;
    stoppingRef.current = true;
    version.current++;
    setStopping(true);
    try {
      const reply = await bridge.invoke({ action: "claude:stop" });
      if (reply.claude) setState(reply.claude);
      if (!reply.cancelled && reply.claude?.phase === "stopped")
        toast.success("Claude 进程树已停止");
    } catch (error) {
      toast.error(
        (error instanceof Error ? error.message : "停止失败").replace(
          /^Error invoking remote method '[^']+': Error: /,
          "",
        ),
      );
      try {
        const reply = await bridge.invoke({ action: "claude:status" });
        if (reply.claude) setState(reply.claude);
      } catch {
        setState({
          phase: "unknown",
          count: 0,
          canStop: false,
          message: "进程状态暂未确认",
          checkedAt: "",
        });
      }
    } finally {
      stoppingRef.current = false;
      setStopping(false);
    }
  };
  const label = stopping
    ? "正在停止"
    : loading
      ? "检测中"
      : state.phase === "running"
        ? "运行中"
        : state.phase === "stopped"
          ? "未运行"
          : "状态未知";
  return (
    <div className="claude-control" aria-label="Claude 进程控制">
      <button
        type="button"
        className="btn claude-stop"
        disabled={!bridge || !state.canStop || stopping || loading}
        title={state.message || "停止当前用户的 Claude CLI 和 Desktop 进程树"}
        onClick={() => void stop()}
      >
        {stopping ? <LoaderCircle size={14} className="spin" /> : <Square size={13} />}停止 Claude
        进程树
      </button>
      <span
        className={`claude-run-state ${state.phase}`}
        role="status"
        title={
          state.message ||
          (state.checkedAt
            ? `最近检测 ${new Date(state.checkedAt).toLocaleTimeString("zh-CN", { hour12: false })}`
            : "")
        }
      >
        <span className="tiny-dot" />
        {label}
      </span>
    </div>
  );
}
