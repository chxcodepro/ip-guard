import {
  ArrowDownToLine,
  ArrowRight,
  Check,
  ChevronRight,
  FileClock,
  FolderOpen,
  Eye,
  EyeOff,
  LayoutDashboard,
  LoaderCircle,
  Lock,
  Monitor,
  Moon,
  Network,
  Play,
  Pencil,
  Plus,
  RefreshCw,
  ScanLine,
  Settings2,
  Shield,
  ShieldCheck,
  ShieldOff,
  Square,
  Sun,
  TerminalSquare,
  Trash2,
  Unlock,
  Wifi,
  X,
} from "lucide-react";
import { useTheme } from "next-themes";
import { useEffect, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { toast } from "sonner";

import type {
  AppPreset,
  CoffeeMetric,
  Command,
  ProtectedApp,
  Settings,
  Snapshot,
} from "@ip-guard/electron";
import {
  claudeIpv4Endpoint,
  formatIPText,
  isClaudeDesktopPath,
  nativeVersion,
  settingsSchema,
} from "@ip-guard/electron";

import { BrowserExtensionPanel } from "#src/components/browser-extension-panel.tsx";
import { ClaudeControl } from "#src/components/claude-control.tsx";
import { CoffeePage } from "#src/components/coffee-page.tsx";
import { EditAppDialog } from "#src/components/edit-app-dialog.tsx";
import { UpdatePanel } from "#src/components/update-panel.tsx";

import "#src/guard.css";

const initial: Snapshot = {
  online: false,
  admin: false,
  ready: false,
  checking: false,
  nativeVersion,
  ipSource: claudeIpv4Endpoint,
  currentIp: "",
  adapter: "",
  lastChecked: "",
  reason: "",
  detection: "",
  running: [],
  autostart: false,
  networkAdapters: [],
  watchedAdapter: {
    id: "",
    name: "正在检测网卡",
    exists: false,
    up: false,
    ipv4: false,
    error: "",
  },
  networkAdapterId: "",
  rulesLocked: false,
  settings: { expectedIp: "", intervalSeconds: 2 },
  apps: [],
  logs: [],
};
type Page = "overview" | "apps" | "coffee" | "settings" | "logs";
const nav: { id: Page; label: string; icon: typeof Shield }[] = [
  { id: "overview", label: "防护总览", icon: LayoutDashboard },
  { id: "apps", label: "受保护程序", icon: ShieldCheck },
  { id: "coffee", label: "Claude 检测", icon: ScanLine },
  { id: "settings", label: "防护设置", icon: Settings2 },
  { id: "logs", label: "事件日志", icon: FileClock },
];
const time = (value: string) =>
  value ? new Date(value).toLocaleTimeString("zh-CN", { hour12: false }) : "—";
const errorText = (error: unknown, fallback: string) =>
  (error instanceof Error ? error.message : fallback).replace(
    /^Error invoking remote method '[^']+': Error: /,
    "",
  );

function Toggle({
  checked,
  onChange,
  label,
  disabled = false,
}: {
  checked: boolean;
  onChange: () => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      className="guard-switch"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={onChange}
    >
      <span />
    </button>
  );
}
function Empty({ icon, title, action }: { icon: ReactNode; title: string; action?: ReactNode }) {
  return (
    <div className="guard-empty">
      <div className="empty-icon">{icon}</div>
      <span>{title}</span>
      {action}
    </div>
  );
}
function ThemeControl() {
  const { theme, setTheme } = useTheme();
  return (
    <div className="theme-control" role="group" aria-label="界面主题">
      {[
        { id: "light", label: "浅色", icon: Sun },
        { id: "dark", label: "深色", icon: Moon },
        { id: "system", label: "跟随系统", icon: Monitor },
      ].map(({ id, label, icon: Icon }) => (
        <button
          type="button"
          key={id}
          title={label}
          aria-label={label}
          aria-pressed={theme === id}
          onClick={() => setTheme(id)}
        >
          <Icon size={16} />
        </button>
      ))}
    </div>
  );
}
function RuleForm({
  ipsVisible,
  settings,
  locked,
  busy,
  available,
  onLock,
  onUnlock,
  onFetch,
}: {
  ipsVisible: boolean;
  settings: Settings;
  locked: boolean;
  busy: boolean;
  available: boolean;
  onLock: (settings: Settings) => Promise<void>;
  onUnlock: () => Promise<void>;
  onFetch?: () => Promise<string>;
}) {
  const [draft, setDraft] = useState(settings);
  const [error, setError] = useState("");
  const [fetching, setFetching] = useState(false);
  useEffect(() => setDraft(settings), [locked, settings.expectedIp, settings.intervalSeconds]);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (locked || fetching || busy || !available) return;
    const parsed = settingsSchema.safeParse(draft);
    if (!parsed.success) {
      setError("请填写有效的公网 IPv4 和 1–60 秒检测间隔。");
      return;
    }
    setError("");
    await onLock(parsed.data);
  };
  const fetchAddress = async () => {
    if (!onFetch || locked || busy || fetching) return;
    setError("");
    setFetching(true);
    try {
      const ip = await onFetch();
      setDraft((current) => ({ ...current, expectedIp: ip }));
    } catch (error) {
      setError(errorText(error, "获取失败"));
    } finally {
      setFetching(false);
    }
  };
  return (
    <form onSubmit={(event) => void submit(event)} className="rule-form">
      <div className="form-row">
        <label htmlFor="expected-ip">允许的公网 IPv4</label>
        <div className="ipv4-fill-row">
          <input
            id="expected-ip"
            type="text"
            autoComplete="off"
            spellCheck={false}
            inputMode="decimal"
            className="mono"
            readOnly={locked || busy || fetching || !ipsVisible}
            placeholder={ipsVisible ? "填写你的固定公网 IPv4" : "显示 IP 后可手动填写"}
            value={formatIPText(draft.expectedIp, ipsVisible)}
            onChange={(e) => {
              if (ipsVisible) setDraft({ ...draft, expectedIp: e.target.value.trim() });
            }}
            required
          />
          <button
            type="button"
            className="btn"
            disabled={locked || !onFetch || busy || fetching}
            onClick={() => void fetchAddress()}
          >
            {fetching ? <LoaderCircle size={15} className="spin" /> : <RefreshCw size={15} />}
            {fetching ? "获取中…" : "获取当前 IPv4"}
          </button>
        </div>
      </div>
      <div className="form-row">
        <label htmlFor="ip-source">IPv4 来源 · Claude AI 出口</label>
        <input id="ip-source" spellCheck={false} readOnly value={claudeIpv4Endpoint} />
      </div>
      <div className="form-row">
        <label htmlFor="interval">检测间隔</label>
        <div className="input-unit">
          <input
            id="interval"
            type="number"
            min={1}
            max={60}
            readOnly={locked || busy || fetching}
            value={draft.intervalSeconds}
            onChange={(e) => setDraft({ ...draft, intervalSeconds: Number(e.target.value) })}
            required
          />
          <span>秒</span>
        </div>
      </div>
      {error && (
        <div role="alert" className="form-error">
          {formatIPText(error, ipsVisible)}
        </div>
      )}
      <div className="form-footer">
        <span className={`rule-lock-state ${locked ? "locked" : ""}`} role="status">
          {locked ? <Lock size={14} /> : <Unlock size={14} />}
          {locked ? "IP 已锁定" : "IP 未锁定"}
        </span>
        {locked ? (
          <button
            className="btn"
            type="button"
            disabled={busy || !available}
            onClick={() => void onUnlock()}
          >
            {busy ? <LoaderCircle className="spin" size={15} /> : <Unlock size={15} />}取消锁定
          </button>
        ) : (
          <button className="btn primary" type="submit" disabled={busy || fetching || !available}>
            {busy ? <LoaderCircle className="spin" size={15} /> : <Lock size={15} />}锁定
          </button>
        )}
      </div>
    </form>
  );
}
function AddDialog({
  apps,
  busy,
  canAdd,
  onClose,
  onAdd,
  onPick,
}: {
  apps: ProtectedApp[];
  busy: boolean;
  canAdd: boolean;
  onClose: () => void;
  onAdd: (app: ProtectedApp) => Promise<void>;
  onPick: () => Promise<string | undefined>;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const [path, setPath] = useState("");
  const [name, setName] = useState("");
  const [args, setArgs] = useState("");
  const [presets, setPresets] = useState<AppPreset[]>([]);
  const [finding, setFinding] = useState(true);
  const [presetError, setPresetError] = useState("");
  const [selected, setSelected] = useState("");
  const alreadyAdded = (value: string) =>
    Boolean(value) &&
    apps.some(
      (app) =>
        app.path.replaceAll("/", "\\").toLowerCase() === value.replaceAll("/", "\\").toLowerCase(),
    );
  const duplicate = alreadyAdded(path);
  useEffect(() => {
    ref.current?.showModal();
    let alive = true;
    if (!window.desktop) {
      setFinding(false);
      return;
    }
    void window.desktop
      .invoke({ action: "presets" })
      .then((reply) => {
        if (alive) setPresets(reply.presets ?? []);
      })
      .catch((error: unknown) => {
        if (alive) setPresetError(error instanceof Error ? error.message : "安装路径读取失败");
      })
      .finally(() => {
        if (alive) setFinding(false);
      });
    return () => {
      alive = false;
    };
  }, []);
  const pick = async () => {
    const selected = await onPick();
    if (selected) {
      setPath(selected);
      setSelected("");
      setName(
        selected
          .split(/[\\/]/)
          .at(-1)
          ?.replace(/\.exe$/i, "") ?? "",
      );
    }
  };
  return (
    <dialog
      ref={ref}
      className="guard-dialog"
      onCancel={onClose}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <form
        onSubmit={(event) => {
          event.preventDefault();
          if (!canAdd || busy || duplicate) return;
          void onAdd({ id: crypto.randomUUID(), name, path, arguments: args, enabled: false });
        }}
      >
        <header>
          <h2>添加程序</h2>
          <button type="button" className="icon-btn" aria-label="关闭" onClick={onClose}>
            <X size={18} />
          </button>
        </header>
        <div className="dialog-fields">
          <div className="preset-options" aria-label="Claude 程序预设">
            {finding ? (
              <div className="preset-loading" role="status">
                <LoaderCircle size={15} className="spin" />
                正在查找 Claude…
              </div>
            ) : (
              presets.map((preset) => (
                <button
                  type="button"
                  key={preset.id}
                  className="preset-button"
                  aria-pressed={selected === preset.id}
                  disabled={busy || preset.status !== "ready" || alreadyAdded(preset.path)}
                  title={preset.path || preset.message}
                  onClick={() => {
                    setPath(preset.path);
                    setName(preset.name);
                    setArgs("");
                    setSelected(preset.id);
                  }}
                >
                  {preset.id !== "claude-desktop" ? (
                    <TerminalSquare size={18} />
                  ) : (
                    <Monitor size={18} />
                  )}
                  <span>
                    {preset.name}
                    <small>
                      {alreadyAdded(preset.path)
                        ? "已添加"
                        : preset.status === "ready"
                          ? preset.version
                            ? `v${preset.version}`
                            : "已定位"
                          : preset.status === "error"
                            ? "定位失败"
                            : "未找到"}
                    </small>
                  </span>
                </button>
              ))
            )}
            {presetError && (
              <div className="form-error" role="alert">
                {presetError}
              </div>
            )}
          </div>
          <div className="form-row">
            <label htmlFor="exe-path">程序路径</label>
            <div className="path-input">
              <input
                id="exe-path"
                value={path}
                title={path}
                readOnly
                placeholder="选择 .exe 文件"
                required
              />
              <button type="button" className="btn" onClick={() => void pick()} disabled={busy}>
                <FolderOpen size={16} />
                浏览
              </button>
            </div>
          </div>
          <div className="form-row">
            <label htmlFor="app-name">显示名称</label>
            <input
              id="app-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={100}
              required
            />
          </div>
          <div className="form-row">
            <label htmlFor="app-args">
              启动参数 <span className="muted">可选</span>
            </label>
            <input
              id="app-args"
              value={args}
              onChange={(e) => setArgs(e.target.value)}
              maxLength={4096}
            />
          </div>
        </div>
        <footer>
          <button type="button" className="btn" onClick={onClose}>
            取消
          </button>
          <button
            type="submit"
            className="btn primary"
            title={canAdd ? undefined : "需要管理员守护"}
            disabled={!path || !name || busy || !canAdd || duplicate}
          >
            {busy ? <LoaderCircle size={15} className="spin" /> : <Plus size={15} />}
            {duplicate ? "已添加" : "添加"}
          </button>
        </footer>
      </form>
    </dialog>
  );
}

export function GuardApp() {
  const [ipsVisible, setIpsVisible] = useState(false);
  useEffect(() => {
    const conceal = () => {
      if (document.hidden) setIpsVisible(false);
    };
    document.addEventListener("visibilitychange", conceal);
    return () => document.removeEventListener("visibilitychange", conceal);
  }, []);
  const [snapshot, setSnapshot] = useState<Snapshot>(initial);
  const [page, setPage] = useState<Page>("overview");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(Boolean(window.desktop));
  const [failure, setFailure] = useState("");
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<ProtectedApp | null>(null);
  const [filter, setFilter] = useState("");
  const [ipv6, setIpv6] = useState<CoffeeMetric>();
  const bridge = window.desktop;
  useEffect(() => {
    if (!bridge) return;
    let alive = true;
    const update = (report: { groups: { id: string; items: CoffeeMetric[] }[] }) => {
      if (alive)
        setIpv6(
          report.groups
            .find((group) => group.id === "ipv6")
            ?.items.find((item) => item.id === "public"),
        );
    };
    const unsubscribe = bridge.subscribeCoffee(update);
    void bridge
      .invoke({ action: "coffee:status" })
      .then((reply) => {
        if (reply.diagnostics) update(reply.diagnostics);
      })
      .catch(() => {
        if (alive)
          setIpv6({
            id: "public",
            label: "公网 IPv6",
            value: "未取得结果",
            detail: "诊断服务未响应",
            status: "unknown",
          });
      });
    return () => {
      alive = false;
      unsubscribe();
    };
  }, [bridge]);
  useEffect(() => {
    if (!bridge) return;
    let alive = true;
    const unsubscribe = bridge.subscribe((value) => {
      if (alive) {
        setSnapshot(value);
        setLoading(false);
      }
    });
    void bridge
      .invoke({ action: "status" })
      .then((reply) => {
        if (alive && reply.snapshot) setSnapshot(reply.snapshot);
      })
      .catch((error: unknown) => {
        if (alive) setFailure(errorText(error, "守护程序连接失败"));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
      unsubscribe();
    };
  }, [bridge]);
  const invoke = async (command: Command) => {
    if (!bridge) {
      toast.error("请在 Windows 桌面版中执行此操作");
      return undefined;
    }
    setBusy(true);
    try {
      const reply = await bridge.invoke(command);
      if (reply.snapshot) {
        setSnapshot(reply.snapshot);
        setFailure("");
      }
      return reply;
    } catch (error) {
      toast.error(formatIPText(errorText(error, "操作失败")));
      return undefined;
    } finally {
      setBusy(false);
    }
  };
  const locked = snapshot.rulesLocked;
  const offline = Boolean(bridge && !loading && (!snapshot.online || failure));
  const available = Boolean(bridge && snapshot.online && snapshot.admin && !failure);
  const enabledCount = snapshot.apps.filter((a) => a.enabled && !a.pathIssue).length;
  const status = loading
    ? "连接守护程序"
    : offline
      ? "守护离线"
      : !bridge
        ? "桌面版专用"
        : !locked
          ? "待锁定"
          : snapshot.ready
            ? "IPv4 匹配"
            : "已阻断";
  const lock = async (settings: Settings) => {
    const result = await invoke({ action: "lock", settings });
    if (result?.snapshot) {
      if (result.snapshot.ready) toast.success("公网 IPv4 已锁定，校验通过");
      else toast.warning(formatIPText(`IP 已锁定 · ${result.snapshot.reason || "等待校验"}`));
    }
  };
  const unlock = async () => {
    const result = await invoke({ action: "unlock" });
    if (result?.snapshot && !result.cancelled) toast.success("已取消锁定，受保护程序已停止");
  };
  const fetchIPv4 = bridge
    ? async () => {
        const reply = await bridge.invoke({ action: "ip:current" });
        if (!reply.ipv4) throw new Error("未取得有效的公网 IPv4");
        return reply.ipv4;
      }
    : undefined;
  const title = nav.find((item) => item.id === page)?.label ?? "防护总览";
  const addAction = (
    <button
      className="btn primary"
      type="button"
      disabled={busy || !bridge}
      onClick={() => setAdding(true)}
    >
      <Plus size={16} />
      添加程序
    </button>
  );
  const appList = (
    <section className="panel app-panel">
      <div className="panel-heading">
        <div>
          <h2>
            受保护程序 <span className="count">{snapshot.apps.length}</span>
          </h2>
        </div>
        {page === "overview" ? (
          <button className="text-btn" onClick={() => setPage("apps")}>
            管理程序
            <ChevronRight size={15} />
          </button>
        ) : (
          addAction
        )}
      </div>
      {snapshot.apps.length === 0 ? (
        <Empty
          icon={<Shield size={26} />}
          title="还没有添加程序"
          action={page === "overview" ? addAction : undefined}
        />
      ) : (
        <div className="app-list">
          {snapshot.apps.map((target) => {
            const running = snapshot.running.includes(target.id);
            const actionReason = !bridge
              ? "请在 Windows 桌面版操作"
              : loading
                ? "等待守护程序连接"
                : offline
                  ? "请重启守护程序"
                  : !snapshot.admin
                    ? "请以管理员身份重启"
                    : !running && target.pathIssue
                      ? target.pathIssue
                      : !running && !locked
                        ? "先锁定允许的公网 IPv4"
                        : !running && !target.enabled
                          ? "先开启右侧防护开关"
                          : "";
            return (
              <article className="app-row" key={target.id}>
                <div className={`app-glyph ${running ? "running" : ""}`}>
                  <Monitor size={22} />
                </div>
                <div className="app-info">
                  <h3>
                    {target.name}
                    <span
                      className={`small-status ${target.pathIssue ? "warning" : running ? "good" : ""}`}
                    >
                      {running
                        ? "运行中"
                        : target.pathIssue
                          ? "路径待更新"
                          : target.enabled
                            ? locked
                              ? "待启动"
                              : "待锁定"
                            : "未启用"}
                    </span>
                  </h3>
                  <div title={target.path} className="app-path mono">
                    {target.path}
                  </div>
                  {(target.pathIssue || actionReason) && (
                    <div
                      className={`app-action-reason ${target.pathIssue ? "path-warning" : ""}`}
                      id={`app-reason-${target.id}`}
                    >
                      {target.pathIssue || actionReason}
                    </div>
                  )}
                </div>
                <div className="app-actions">
                  {isClaudeDesktopPath(target.path) && (
                    <button
                      className="btn"
                      disabled={busy || !available}
                      onClick={() => void invoke({ action: "desktop:relocate", id: target.id })}
                    >
                      <RefreshCw size={14} />
                      更新路径
                    </button>
                  )}
                  <Toggle
                    checked={target.enabled}
                    label={`${target.enabled ? "解除" : "启用"} ${target.name} 防护`}
                    disabled={
                      busy ||
                      !available ||
                      (!target.enabled && (!locked || Boolean(target.pathIssue)))
                    }
                    onChange={() =>
                      void invoke({ action: "protect", id: target.id, enabled: !target.enabled })
                    }
                  />
                  <button
                    type="button"
                    className={`btn ${running ? "" : "launch"}`}
                    disabled={busy || Boolean(actionReason)}
                    title={
                      busy
                        ? "操作处理中"
                        : actionReason || (running ? "停止受保护进程树" : "校验 IP 并启动")
                    }
                    aria-describedby={actionReason ? `app-reason-${target.id}` : undefined}
                    onClick={() =>
                      void invoke({ action: running ? "stop" : "start", id: target.id })
                    }
                  >
                    {running ? <Square size={13} /> : <Play size={14} />}
                    {running ? "停止" : "启动"}
                  </button>
                  <button
                    type="button"
                    className="icon-btn"
                    title="编辑启动参数"
                    aria-label={`编辑 ${target.name}`}
                    disabled={busy || !available}
                    onClick={() => setEditing(target)}
                  >
                    <Pencil size={16} />
                  </button>
                  <button
                    type="button"
                    className="icon-btn delete-btn"
                    title="移除程序"
                    aria-label={`移除 ${target.name}`}
                    disabled={busy || !available}
                    onClick={() => void invoke({ action: "remove", id: target.id })}
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
  const logEntries = snapshot.logs.filter((entry) => !filter || entry.level === filter);
  const logList = (limit?: number) =>
    logEntries.length ? (
      <div className="event-list">
        {logEntries.slice(0, limit).map((entry, index) => (
          <div className="event-row" key={`${entry.time}-${index}`}>
            <span className={`event-dot ${entry.level}`} />
            <time title={new Date(entry.time).toLocaleString()} className="mono">
              {time(entry.time)}
            </time>
            <span>{formatIPText(entry.message, ipsVisible)}</span>
          </div>
        ))}
      </div>
    ) : (
      <Empty icon={<FileClock size={24} />} title="暂无事件" />
    );
  return (
    <div className="guard-shell">
      <aside className="guard-sidebar">
        <a
          className="brand"
          href="#"
          onClick={(event) => {
            event.preventDefault();
            setPage("overview");
          }}
        >
          <span className="brand-icon">
            <ShieldCheck size={23} />
          </span>
          <span>IP Guard</span>
        </a>
        <nav aria-label="主导航">
          {nav.map(({ id, label, icon: Icon }) => (
            <button
              type="button"
              className={page === id ? "active" : ""}
              aria-current={page === id ? "page" : undefined}
              title={label}
              key={id}
              onClick={() => setPage(id)}
            >
              <Icon size={18} />
              <span>{label}</span>
              {id === "apps" && snapshot.apps.length > 0 && <small>{snapshot.apps.length}</small>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-divider" />
          <div className="sidebar-footer">
            <span className={`tiny-dot ${available ? "good" : ""}`} />
            <span>{bridge ? (snapshot.admin ? "管理员模式" : "普通权限") : "浏览器预览"}</span>
            <span
              className="version"
              title={`原生组件 ${snapshot.online ? snapshot.nativeVersion : "未连接"}`}
            >
              v{nativeVersion}
            </span>
          </div>
        </div>
      </aside>
      <div className="guard-workspace">
        <header className="topbar">
          <div className="breadcrumb">
            <span>{title}</span>
          </div>
          <div className="topbar-actions">
            <ClaudeControl />
            <button
              type="button"
              className="btn ip-visibility"
              aria-label={ipsVisible ? "隐藏 IP 地址" : "显示 IP 地址"}
              title={ipsVisible ? "隐藏 IP 地址" : "显示 IP 地址"}
              aria-pressed={ipsVisible}
              onClick={() => setIpsVisible((value) => !value)}
            >
              {ipsVisible ? <EyeOff size={16} /> : <Eye size={16} />}
              {ipsVisible ? "隐藏 IP" : "显示 IP"}
            </button>
            <ThemeControl />
          </div>
        </header>
        <main className="guard-main">
          <div className="page-heading">
            <div className="title-group">
              <h1>{title}</h1>
            </div>
            <div
              className={`status-pill ${snapshot.ready ? "good" : locked ? "danger" : ""}`}
              role="status"
            >
              <span className="tiny-dot" />
              {status}
            </div>
          </div>
          {(!bridge || offline || (bridge && !snapshot.admin && !loading)) && (
            <div className="notice" role="alert">
              <ShieldOff size={18} />
              <span>
                {formatIPText(
                  failure ||
                    (offline ? snapshot.reason || "守护程序离线，请重启 IP Guard。" : "") ||
                    (!bridge
                      ? "请打开 Windows 桌面版以配置启动拦截与后台防护。"
                      : "管理启动拦截与防火墙需要管理员权限。"),
                  ipsVisible,
                )}
              </span>
              {bridge && offline ? (
                <button
                  className="text-btn"
                  disabled={busy}
                  onClick={() => void invoke({ action: "restart" })}
                >
                  重启 IP Guard
                  <ArrowRight size={14} />
                </button>
              ) : (
                bridge &&
                !snapshot.admin && (
                  <button
                    className="text-btn"
                    disabled={busy}
                    onClick={() => void invoke({ action: "elevate" })}
                  >
                    以管理员身份重启
                    <ArrowRight size={14} />
                  </button>
                )
              )}
            </div>
          )}
          <div key={page} className="page-content">
            {page === "coffee" && <CoffeePage ipsVisible={ipsVisible} />}
            {page === "overview" && (
              <>
                <section className={`network-panel ${snapshot.ready ? "matched" : ""}`}>
                  <div className="network-main">
                    <div className="network-label">
                      <span className="network-icon">
                        <Network size={20} />
                      </span>
                      Claude AI 出口 IPv4
                      <button
                        type="button"
                        className="icon-btn"
                        title="立即检测"
                        aria-label="立即检测"
                        disabled={busy || !bridge || !locked}
                        onClick={() => void invoke({ action: "check" })}
                      >
                        <RefreshCw size={15} className={busy || snapshot.checking ? "spin" : ""} />
                      </button>
                    </div>
                    <div className="public-ip mono">
                      {formatIPText(snapshot.currentIp || "— . — . — . —", ipsVisible)}
                    </div>
                    <div className="allowed-ip">
                      <span>允许地址</span>
                      <span className="mono">
                        {formatIPText(snapshot.settings.expectedIp || "尚未设置", ipsVisible)}
                      </span>
                      {snapshot.ready && <Check size={14} />}
                    </div>
                  </div>
                  <div className="network-aside">
                    <div className="network-detail">
                      <Wifi size={15} />
                      <span>{formatIPText(snapshot.adapter || "等待网络检测", ipsVisible)}</span>
                    </div>
                    <div
                      className={`network-detail adapter-monitor ${snapshot.watchedAdapter.exists && snapshot.watchedAdapter.up ? "online" : "warning"}`}
                    >
                      <Network size={15} />
                      <span>
                        {!snapshot.online
                          ? "等待网卡检测"
                          : snapshot.watchedAdapter.error
                            ? "网卡检测失败"
                            : `${snapshot.watchedAdapter.name} · ${snapshot.watchedAdapter.exists ? (snapshot.watchedAdapter.up ? (snapshot.watchedAdapter.ipv4 ? "在线" : "无 IPv4") : "断开") : "不存在"}`}
                      </span>
                    </div>
                    <div className="network-detail">
                      <RefreshCw size={14} />
                      <span>
                        {snapshot.checking
                          ? "正在获取 Claude AI IPv4"
                          : `每 ${snapshot.settings.intervalSeconds} 秒检测`}
                      </span>
                    </div>
                    <div className="last-check">
                      最近检测 <span className="mono">{time(snapshot.lastChecked)}</span>
                    </div>
                  </div>
                  <div className={`network-ipv6 ${ipv6?.status ?? "unknown"}`}>
                    <span>公网 IPv6</span>
                    <strong className="mono" title={formatIPText(ipv6?.detail ?? "", ipsVisible)}>
                      {formatIPText(ipv6?.value ?? "等待检测", ipsVisible)}
                    </strong>
                    <button type="button" className="text-btn" onClick={() => setPage("coffee")}>
                      检测详情
                      <ChevronRight size={14} />
                    </button>
                  </div>
                  <div className="network-footer">
                    <span className={`tiny-dot ${snapshot.ready ? "good" : ""}`} />
                    <span>
                      {loading
                        ? "正在连接本机守护程序…"
                        : !locked
                          ? "锁定允许地址后开始校验"
                          : formatIPText(
                              snapshot.reason || "地址匹配 · 启动时仍会重新校验",
                              ipsVisible,
                            )}
                    </span>
                    <button className="text-btn" onClick={() => setPage("settings")}>
                      编辑规则
                      <ArrowRight size={14} />
                    </button>
                  </div>
                  {snapshot.detection && (
                    <div className="network-observation">
                      最近网络事件 · {formatIPText(snapshot.detection, ipsVisible)}
                    </div>
                  )}
                </section>
                {!locked && (
                  <section className="panel setup-panel">
                    <div className="panel-heading">
                      <h2>设置你的允许地址</h2>
                    </div>
                    <RuleForm
                      ipsVisible={ipsVisible}
                      settings={snapshot.settings}
                      locked={locked}
                      busy={busy}
                      available={available}
                      onLock={lock}
                      onUnlock={unlock}
                      onFetch={fetchIPv4}
                    />
                  </section>
                )}
                {appList}
                <section className="panel events-panel">
                  <div className="panel-heading">
                    <h2>最近事件</h2>
                    <button className="text-btn" onClick={() => setPage("logs")}>
                      全部日志
                      <ChevronRight size={15} />
                    </button>
                  </div>
                  {logList(4)}
                </section>
              </>
            )}
            {page === "apps" && (
              <>
                {!locked && (
                  <div className="notice">
                    <Settings2 size={17} />
                    <span>先锁定允许地址，再开启程序防护。</span>
                    <button className="text-btn" onClick={() => setPage("settings")}>
                      设置地址
                      <ArrowRight size={14} />
                    </button>
                  </div>
                )}
                {appList}
                <div className="footnote">
                  <Shield size={14} />
                  启用后，双击 EXE 和原快捷方式均先经过 IPv4 校验。
                </div>
              </>
            )}
            {page === "settings" && (
              <>
                <section className="panel">
                  <div className="panel-heading">
                    <h2>网络规则</h2>
                    <span className="subtle-label">公网 IPv4</span>
                  </div>
                  <RuleForm
                    ipsVisible={ipsVisible}
                    settings={snapshot.settings}
                    locked={locked}
                    busy={busy}
                    available={available}
                    onLock={lock}
                    onUnlock={unlock}
                    onFetch={fetchIPv4}
                  />
                </section>
                <section className="panel settings-panel">
                  <div className="panel-heading">
                    <h2>网卡检测</h2>
                    <span className="subtle-label">仅检测</span>
                  </div>
                  <div className="setting-row">
                    <span className="setting-icon">
                      <Network size={19} />
                    </span>
                    <label htmlFor="watched-adapter">
                      <strong>监控网卡</strong>
                      <span title={snapshot.watchedAdapter.error}>
                        {!snapshot.online
                          ? "等待守护连接"
                          : snapshot.watchedAdapter.error
                            ? "网卡检测失败"
                            : `${snapshot.watchedAdapter.name} · ${snapshot.watchedAdapter.exists ? (snapshot.watchedAdapter.up ? "在线" : "已断开") : "不存在"}`}
                      </span>
                    </label>
                    <select
                      id="watched-adapter"
                      value={snapshot.networkAdapterId}
                      disabled={busy || !available}
                      onChange={(event) =>
                        void invoke({ action: "adapter:set", adapterId: event.target.value })
                      }
                    >
                      <option value="">自动识别联网网卡</option>
                      {snapshot.networkAdapterId &&
                        !snapshot.networkAdapters.some(
                          (n) => n.id === snapshot.networkAdapterId,
                        ) && <option value={snapshot.networkAdapterId}>所选网卡不存在</option>}
                      {snapshot.networkAdapters.map((n) => (
                        <option key={n.id} value={n.id}>
                          {n.name} · {n.up ? "在线" : "断开"}
                        </option>
                      ))}
                    </select>
                  </div>
                </section>
                <BrowserExtensionPanel
                  busy={busy}
                  available={available}
                  onSetup={async () => Boolean(await invoke({ action: "extension:setup" }))}
                />
                <UpdatePanel />
                <section className="panel settings-panel">
                  <div className="panel-heading">
                    <h2>后台与启动</h2>
                  </div>
                  <div className="setting-row">
                    <span className="setting-icon">
                      <ShieldCheck size={19} />
                    </span>
                    <label>
                      <strong>原生守护组件</strong>
                    </label>
                    <span className="fixed-value mono">
                      {snapshot.online ? snapshot.nativeVersion : "未连接"}
                    </span>
                  </div>
                  <div className="setting-row">
                    <span className="setting-icon">
                      <ArrowDownToLine size={19} />
                    </span>
                    <label id="autostart-label">
                      <strong>开机启动</strong>
                      <span>登录 Windows 后启动，直接进入托盘</span>
                    </label>
                    <Toggle
                      checked={snapshot.autostart}
                      label="开机启动"
                      disabled={busy || !available}
                      onChange={() =>
                        void invoke({ action: "autostart", enabled: !snapshot.autostart })
                      }
                    />
                  </div>
                  <div className="setting-row">
                    <span className="setting-icon">
                      <Monitor size={19} />
                    </span>
                    <div>
                      <strong>关闭窗口后留在托盘</strong>
                    </div>
                    <span className="fixed-value">
                      <Check size={14} />
                      已启用
                    </span>
                  </div>
                  <div className="setting-row">
                    <span className="setting-icon">
                      <ShieldOff size={19} />
                    </span>
                    <div>
                      <strong>IP 不匹配或校验失败时阻断</strong>
                    </div>
                    <span className="fixed-value">
                      <Check size={14} />
                      已启用
                    </span>
                  </div>
                </section>
                <section className="panel settings-panel">
                  <div className="panel-heading">
                    <h2>外观</h2>
                  </div>
                  <div className="setting-row">
                    <span className="setting-icon">
                      <Sun size={19} />
                    </span>
                    <strong>界面主题</strong>
                    <ThemeControl />
                  </div>
                </section>
              </>
            )}
            {page === "logs" && (
              <section className="panel">
                <div className="panel-heading">
                  <h2>事件记录</h2>
                  <div className="log-toolbar">
                    <select
                      aria-label="筛选日志等级"
                      value={filter}
                      onChange={(e) => setFilter(e.target.value)}
                    >
                      <option value="">所有事件</option>
                      <option value="info">正常</option>
                      <option value="warning">阻断</option>
                      <option value="error">错误</option>
                    </select>
                    <button
                      className="btn"
                      disabled={!bridge}
                      onClick={() => void invoke({ action: "logs" })}
                    >
                      <FolderOpen size={15} />
                      日志目录
                    </button>
                  </div>
                </div>
                {logList()}
              </section>
            )}
          </div>
          <footer className="workspace-footer">
            <span>
              <span className="tiny-dot good" />
              本机运行
            </span>
            <span>
              {enabledCount} 个程序已接管<span className="footer-separator">/</span>
              {snapshot.running.length} 个运行中
            </span>
          </footer>
        </main>
      </div>
      {editing && (
        <EditAppDialog
          key={editing.id}
          app={editing}
          busy={busy}
          available={available}
          onClose={() => setEditing(null)}
          onSave={async (value) => {
            const reply = await invoke({ action: "edit", id: editing.id, ...value });
            if (reply?.snapshot) {
              setEditing(null);
              toast.success("启动配置已更新");
            }
          }}
        />
      )}
      {adding && (
        <AddDialog
          apps={snapshot.apps}
          busy={busy}
          canAdd={available}
          onClose={() => setAdding(false)}
          onPick={async () => (await invoke({ action: "pick" }))?.selectedPath}
          onAdd={async (target) => {
            const result = await invoke({ action: "add", app: target });
            if (result?.snapshot) {
              setAdding(false);
              toast.success("已添加，开启开关后接管启动");
            }
          }}
        />
      )}
    </div>
  );
}
