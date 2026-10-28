import { LoaderCircle, RefreshCw, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { isNewerExtensionVersion, nativeVersion } from "@ip-guard/electron";
import type { ExtensionStatus } from "@ip-guard/electron";

const labels = { running: "正在运行", installed: "已安装", missing: "未安装", unknown: "状态未知" };
export function BrowserExtensionPanel({
  busy,
  available,
  onSetup,
}: {
  busy: boolean;
  available: boolean;
  onSetup: () => Promise<boolean>;
}) {
  const bridge = window.desktop;
  const [status, setStatus] = useState<ExtensionStatus>({
    phase: "unknown",
    installedBrowsers: [],
    outdatedBrowsers: [],
    outdatedConnections: 0,
    latestVersion: nativeVersion,
    connections: 0,
    error: "正在读取扩展状态",
  });
  const [revision, setRevision] = useState(0);
  const [guide, setGuide] = useState(false);
  useEffect(() => {
    if (!bridge) return;
    let alive = true;
    let pending = false;
    const refresh = async () => {
      if (pending || document.hidden) return;
      pending = true;
      try {
        const reply = await bridge.invoke({ action: "extension:status" });
        if (alive && reply.extension) setStatus(reply.extension);
      } catch (error) {
        if (alive)
          setStatus({
            phase: "unknown",
            installedBrowsers: [],
            outdatedBrowsers: [],
            outdatedConnections: 0,
            latestVersion: nativeVersion,
            connections: 0,
            error:
              error instanceof Error
                ? error.message.replace(/^Error invoking remote method '[^']+': Error: /, "")
                : "扩展状态读取失败",
          });
      } finally {
        pending = false;
      }
    };
    const tick = () => void refresh();
    tick();
    const timer = setInterval(tick, 5000);
    document.addEventListener("visibilitychange", tick);
    window.addEventListener("focus", tick);
    return () => {
      alive = false;
      clearInterval(timer);
      document.removeEventListener("visibilitychange", tick);
      window.removeEventListener("focus", tick);
    };
  }, [bridge, revision]);
  const updateAvailable = status.outdatedBrowsers.length > 0 || status.outdatedConnections > 0;
  return (
    <section className="panel settings-panel">
      <div className="panel-heading">
        <h2>浏览器防护</h2>
        <span
          className={`small-status ${updateAvailable ? "warning" : status.phase === "running" ? "good" : ""}`}
          role="status"
        >
          {labels[status.phase]}
          {updateAvailable ? " · 插件待更新" : ""}
        </span>
      </div>
      <div className="setting-row">
        <span className="setting-icon">
          <ShieldCheck size={19} />
        </span>
        <div>
          <strong>Claude 网页扩展</strong>
          <span>
            {status.phase === "running"
              ? `${status.connections} 个浏览器连接`
              : status.phase === "installed"
                ? `${status.installedBrowsers.join(" / ")} · 打开浏览器并启用扩展`
                : status.phase === "missing"
                  ? "Chrome / Edge"
                  : status.error}
          </span>
        </div>
        <div className="update-actions">
          {updateAvailable && (
            <button
              className="btn"
              disabled={!bridge}
              onClick={async () => {
                try {
                  await bridge?.invoke({ action: "update:releases" });
                } catch {
                  toast.error("打开更新页失败，请在 GitHub Releases 下载插件");
                }
              }}
            >
              下载插件
            </button>
          )}
          <button
            className="icon-btn"
            aria-label="刷新扩展状态"
            disabled={!bridge}
            onClick={() => setRevision((value) => value + 1)}
          >
            <RefreshCw size={15} />
          </button>
          <button
            className="btn"
            disabled={busy || !available}
            onClick={async () => {
              if (await onSetup()) {
                setGuide(true);
                setRevision((value) => value + 1);
              }
            }}
          >
            {busy ? <LoaderCircle size={14} className="spin" /> : null}
            {status.phase === "missing" ? "准备安装扩展" : "打开扩展文件夹"}
          </button>
        </div>
      </div>
      {updateAvailable && (
        <div className="extension-guide extension-update-guide" role="status">
          <strong>
            {status.outdatedBrowsers.join(" / ") || "已连接的浏览器"} · 插件可更新至 v
            {status.latestVersion}
          </strong>
          <ol>
            <li>
              {isNewerExtensionVersion(status.latestVersion, nativeVersion)
                ? "从 IP Guard 目录加载的扩展：先更新桌面程序，再到扩展管理页点击「重新加载」。"
                : "从 IP Guard 目录加载的扩展：在扩展管理页点击「重新加载」。"}
            </li>
            <li>独立 ZIP：从 Releases 下载新版，解压覆盖原目录，再点击「重新加载」。</li>
          </ol>
        </div>
      )}
      {!updateAvailable && (status.phase === "missing" || guide) && (
        <div className="extension-guide">
          <ol>
            <li>
              点击「{status.phase === "missing" ? "准备安装扩展" : "打开扩展文件夹"}
              」，打开扩展目录。
            </li>
            <li>
              Chrome 打开 <code>chrome://extensions</code>；Edge 打开 <code>edge://extensions</code>
              。
            </li>
            <li>开启「开发者模式」→「加载已解压的扩展」，选择刚打开的文件夹。</li>
          </ol>
        </div>
      )}
    </section>
  );
}
