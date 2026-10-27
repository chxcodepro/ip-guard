import { CircleX, LoaderCircle, RefreshCw, TriangleAlert } from "lucide-react";
import { useEffect, useState } from "react";

import type { CoffeeMetric, CoffeeReport } from "@ip-guard/electron";
import { formatIPText, ipv4Schema, ipv6Schema } from "@ip-guard/electron";

const initial: CoffeeReport = {
  phase: "idle",
  checkedAt: "",
  error: "",
  claudeIp: "",
  claudeTimezone: "",
  groups: [],
};
const field = (
  id: string,
  label: string,
  value: string,
  status: CoffeeMetric["status"] = "neutral",
  detail = "",
): CoffeeMetric => ({ id, label, value, status, detail });
const readString = (object: unknown, key: string) => {
  if (object === null || typeof object !== "object") return "";
  const value: unknown = Reflect.get(object, key);
  return typeof value === "string" ? value : "";
};
function deviceMetrics(): CoffeeMetric[] {
  const canvas = document.createElement("canvas");
  canvas.width = 240;
  canvas.height = 48;
  let fingerprint = "不可用",
    renderer = "不可用";
  const context = canvas.getContext("2d");
  if (context) {
    context.font = "16px Segoe UI";
    context.fillStyle = "#147d68";
    context.fillText("IP Guard · Canvas 0123456789", 4, 28);
    let code = 2166136261;
    for (const char of canvas.toDataURL()) code = Math.imul(code ^ char.charCodeAt(0), 16777619);
    fingerprint = (code >>> 0).toString(16).padStart(8, "0");
  }
  const gl = document.createElement("canvas").getContext("webgl");
  if (gl) {
    const extension = gl.getExtension("WEBGL_debug_renderer_info");
    const value: unknown = gl.getParameter(extension?.UNMASKED_RENDERER_WEBGL ?? gl.RENDERER);
    if (typeof value === "string") renderer = value;
    gl.getExtension("WEBGL_lose_context")?.loseContext();
  }
  const connection: unknown = Reflect.get(navigator, "connection");
  const network = [readString(connection, "type"), readString(connection, "effectiveType")]
    .filter(Boolean)
    .join(" · ");
  return [
    field("timezone", "本机时区", Intl.DateTimeFormat().resolvedOptions().timeZone),
    field("language", "语言", navigator.languages.join(" · ")),
    field("browser", "系统 / 浏览器", navigator.userAgent),
    field("touch", "触屏", navigator.maxTouchPoints > 0 ? "支持" : "未检测到"),
    field("network", "网络类型", network || "未提供", network ? "neutral" : "unknown"),
    field(
      "dnt",
      "Do Not Track",
      navigator.doNotTrack === "1" ? "开启" : navigator.doNotTrack === "0" ? "关闭" : "未设置",
    ),
    field("webgl", "WebGL 渲染器", renderer),
    field("canvas", "Canvas 指纹", fingerprint),
  ];
}
function offset(zone: string): number | null {
  try {
    const value =
      new Intl.DateTimeFormat("en", { timeZone: zone, timeZoneName: "longOffset" })
        .formatToParts(new Date())
        .find((part) => part.type === "timeZoneName")?.value ?? "";
    if (value === "GMT" || value === "UTC") return 0;
    const match = /^GMT([+-])(\d{1,2})(?::(\d{2}))?$/.exec(value);
    return match
      ? (match[1] === "-" ? -1 : 1) * (Number(match[2]) * 60 + Number(match[3] ?? 0))
      : null;
  } catch {
    return null;
  }
}
function offsetLabel(value: number | null) {
  if (value == null) return "未知";
  const minutes = Math.abs(value);
  return `UTC${value < 0 ? "-" : "+"}${Math.floor(minutes / 60)}${minutes % 60 ? `:${String(minutes % 60).padStart(2, "0")}` : ""}`;
}
function publicIPv4(value: string) {
  if (!ipv4Schema.safeParse(value).success) return false;
  const parts = value.split(".");
  const a = Number(parts[0]),
    b = Number(parts[1]);
  return !(
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 198 && (b === 18 || b === 19))
  );
}
type UdpResult = { phase: "running" | "complete"; ips: string[]; detail: string };
function udpProbe(signal: AbortSignal): Promise<UdpResult> {
  return new Promise((resolve) => {
    let pc: RTCPeerConnection | undefined;
    const ips = new Set<string>();
    let locals = 0;
    let done = false;
    const finish = (detail = "") => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      signal.removeEventListener("abort", cancel);
      pc?.close();
      resolve({
        phase: "complete",
        ips: [...ips],
        detail:
          detail || (ips.size ? "" : locals ? "仅获得本地候选，公网出口未知" : "未取得公网候选"),
      });
    };
    const cancel = () => finish("检测已取消");
    const timer = setTimeout(() => finish(), 6000);
    signal.addEventListener("abort", cancel, { once: true });
    if (signal.aborted) {
      cancel();
      return;
    }
    try {
      pc = new RTCPeerConnection({
        iceServers: [
          { urls: "stun:stun.l.google.com:19302" },
          { urls: "stun:stun.cloudflare.com:3478" },
        ],
      });
      pc.onicecandidate = (event) => {
        if (!event.candidate) {
          finish();
          return;
        }
        const address = event.candidate.address;
        if (event.candidate.type === "srflx" && address) ips.add(address);
        else locals++;
      };
      pc.createDataChannel("diagnostics");
      const active = pc;
      void pc
        .createOffer()
        .then((offer) => {
          if (!done) return active.setLocalDescription(offer);
        })
        .catch(() => finish("WebRTC 检测失败"));
    } catch {
      finish("WebRTC 不可用");
    }
  });
}
type HistoryEntry = { ip: string; time: string };
const historyKey = "ipguard.coffee.history";
function loadHistory(): HistoryEntry[] {
  try {
    const value: unknown = JSON.parse(localStorage.getItem(historyKey) ?? "[]");
    if (!Array.isArray(value)) return [];
    return value
      .flatMap((item: unknown) => {
        const ip = readString(item, "ip"),
          time = readString(item, "time");
        return ip && Number.isFinite(Date.parse(time)) ? [{ ip, time }] : [];
      })
      .slice(0, 6);
  } catch {
    return [];
  }
}
function MetricRows({ items, ipsVisible }: { items: CoffeeMetric[]; ipsVisible: boolean }) {
  return (
    <div className="coffee-metrics">
      {items.map((item) => (
        <div className={`coffee-metric ${item.status}`} key={item.id}>
          <span className="coffee-label">{formatIPText(item.label, ipsVisible)}</span>
          <div>
            <div className="coffee-value">
              <strong>{formatIPText(item.value, ipsVisible)}</strong>
              {(item.status === "warning" || item.status === "error") && (
                <span className={`coffee-risk-marker ${item.status}`}>
                  {item.status === "warning" ? <TriangleAlert size={13} /> : <CircleX size={13} />}
                  {item.status === "warning" ? "需核查" : "异常"}
                </span>
              )}
            </div>
            {item.detail && <small>{formatIPText(item.detail, ipsVisible)}</small>}
          </div>
        </div>
      ))}
    </div>
  );
}

export function CoffeePage({ ipsVisible }: { ipsVisible: boolean }) {
  const bridge = window.desktop;
  const [report, setReport] = useState(initial);
  const [error, setError] = useState("");
  const [generation, setGeneration] = useState(0);
  const [device, setDevice] = useState<CoffeeMetric[]>([]);
  const [udp, setUdp] = useState<UdpResult>({ phase: "running", ips: [], detail: "" });
  const [history, setHistory] = useState(loadHistory);
  useEffect(() => {
    if (!bridge) return;
    let alive = true;
    const unsubscribe = bridge.subscribeCoffee((value) => {
      if (alive) setReport(value);
    });
    void bridge
      .invoke({ action: "coffee:status" })
      .then((reply) => {
        if (alive && reply.diagnostics) setReport(reply.diagnostics);
      })
      .catch((err: unknown) => {
        if (alive) setError(err instanceof Error ? err.message : "诊断连接失败");
      });
    return () => {
      alive = false;
      unsubscribe();
    };
  }, [bridge]);
  useEffect(() => {
    setDevice(deviceMetrics());
    if (!bridge) {
      setUdp({ phase: "complete", ips: [], detail: "请在桌面版检测" });
      return;
    }
    const abort = new AbortController();
    let alive = true;
    setUdp({ phase: "running", ips: [], detail: "" });
    void udpProbe(abort.signal).then((value) => {
      if (alive) setUdp(value);
    });
    return () => {
      alive = false;
      abort.abort();
    };
  }, [bridge, generation]);
  useEffect(() => {
    if (report.phase !== "complete" || !report.claudeIp) return;
    const previous = loadHistory();
    const last = previous[0];
    if (last?.ip === report.claudeIp && Date.now() - Date.parse(last.time) < 86400000) return;
    const entries = [{ ip: report.claudeIp, time: report.checkedAt }, ...previous].slice(0, 6);
    try {
      localStorage.setItem(historyKey, JSON.stringify(entries));
      setHistory(entries);
    } catch {
      setError("IP 历史保存失败");
    }
  }, [report.checkedAt, report.claudeIp, report.phase]);
  const refresh = async () => {
    if (!bridge) return;
    setError("");
    setGeneration((value) => value + 1);
    try {
      const reply = await bridge.invoke({ action: "coffee:refresh" });
      if (reply.diagnostics) setReport(reply.diagnostics);
    } catch (err) {
      setError(err instanceof Error ? err.message : "刷新失败");
    }
  };
  const localZone = device.find((item) => item.id === "timezone")?.value ?? "";
  const localOffset = localZone ? offset(localZone) : null;
  const remoteOffset = report.claudeTimezone ? offset(report.claudeTimezone) : null;
  const timezoneDetail = `${localZone} ${offsetLabel(localOffset)} / ${report.claudeTimezone || "出口时区未知"} ${offsetLabel(remoteOffset)}`;
  const mainlandTimezone = localZone === "Asia/Shanghai" || localZone === "Asia/Urumqi";
  const timezoneMatch =
    localOffset != null && remoteOffset != null && Math.abs(localOffset - remoteOffset) <= 60;
  const timezone = mainlandTimezone
    ? field("timezone-check", "时区对照", "站点不推荐中国大陆时区", "warning", timezoneDetail)
    : localOffset != null && remoteOffset != null
      ? field(
          "timezone-check",
          "时区对照",
          timezoneMatch ? "时区一致" : "时区偏差超过 1 小时",
          timezoneMatch ? "ok" : "warning",
          timezoneDetail,
        )
      : field("timezone-check", "时区对照", "等待 IP 时区", "unknown");
  const publicUdp = udp.ips.filter(publicIPv4);
  const udp6 = udp.ips.filter((ip) => ipv6Schema.safeParse(ip).success);
  const udpDiffers = Boolean(report.claudeIp && publicUdp.some((ip) => ip !== report.claudeIp));
  const udpItems: CoffeeMetric[] =
    udp.phase === "running"
      ? [field("status", "状态", "检测中…", "unknown")]
      : publicUdp.length || udp6.length
        ? [
            field(
              "status",
              "状态",
              udpDiffers
                ? "可能泄露"
                : udp6.length
                  ? "检测到 UDP IPv6 出口"
                  : report.claudeIp
                    ? "未检测到泄露"
                    : "等待 Claude 出口对照",
              udpDiffers || udp6.length ? "warning" : report.claudeIp ? "ok" : "unknown",
            ),
            ...publicUdp.map((ip, index) =>
              field(
                `udp-${index}`,
                "UDP IPv4",
                ip,
                report.claudeIp ? (ip === report.claudeIp ? "ok" : "warning") : "unknown",
                report.claudeIp && ip !== report.claudeIp ? "与 Claude IPv4 出口不同" : "",
              ),
            ),
            ...udp6.map((ip, index) =>
              field(`udp6-${index}`, "UDP IPv6", ip, "warning", "站点建议核查 IPv6 出口"),
            ),
          ]
        : [field("status", "状态", "公网出口未知", "unknown", udp.detail)];
  const panel = (id: string) => {
    const group = report.groups.find((group) => group.id === id);
    return group ? (
      <section className={`panel coffee-${group.id}`} key={group.id}>
        <div className="panel-heading">
          <h2>{group.title}</h2>
          {group.id === "trust" && <span className="subtle-label">NET.COFFEE</span>}
        </div>
        <MetricRows items={group.items} ipsVisible={ipsVisible} />
      </section>
    ) : null;
  };
  return (
    <div className="coffee-page">
      <div className="coffee-toolbar">
        <div>
          <span className="coffee-readonly">仅检测</span>
          <span className="coffee-schedule">诊断每 5 分钟刷新</span>
          {report.checkedAt && (
            <time>{new Date(report.checkedAt).toLocaleTimeString("zh-CN", { hour12: false })}</time>
          )}
        </div>
        <div>
          <button
            type="button"
            className="btn primary"
            disabled={!bridge || report.phase === "running"}
            onClick={() => void refresh()}
          >
            {report.phase === "running" ? (
              <LoaderCircle size={15} className="spin" />
            ) : (
              <RefreshCw size={15} />
            )}
            刷新检测
          </button>
        </div>
      </div>
      <div className="coffee-legend" aria-label="检测颜色说明">
        <span className="ok">
          <i />
          正常
        </span>
        <span className="info">
          <i />
          提示
        </span>
        <span className="warning">
          <i />
          需核查
        </span>
        <span className="error">
          <i />
          异常
        </span>
        <span className="unknown">
          <i />
          未知
        </span>
      </div>
      {(error || report.error) && (
        <div className="notice" role="alert">
          {formatIPText(error || report.error, ipsVisible)}
        </div>
      )}
      {!report.groups.length && (
        <section className="panel">
          <div className="guard-empty">
            {bridge ? "正在连接诊断服务…" : "请在 Windows 桌面版运行检测"}
          </div>
        </section>
      )}
      <div className="coffee-grid">
        {panel("exits")}
        {panel("ipv6")}
        <div className="coffee-stack">
          {panel("trust")}
          {panel("security")}
          {panel("availability")}
        </div>
        <div className="coffee-stack">
          {panel("location")}
          {panel("dns")}
          <section className="panel coffee-udp">
            <div className="panel-heading">
              <h2>WebRTC / UDP</h2>
              {udp.phase === "running" && <LoaderCircle size={14} className="spin" />}
            </div>
            <MetricRows items={udpItems} ipsVisible={ipsVisible} />
          </section>
        </div>
        <section className="panel coffee-device">
          <div className="panel-heading">
            <h2>本机设备</h2>
          </div>
          <MetricRows items={[timezone, ...device]} ipsVisible={true} />
        </section>
        <section className="panel coffee-history">
          <div className="panel-heading">
            <h2>Claude 出口历史</h2>
            <button
              className="text-btn"
              type="button"
              disabled={!history.length}
              onClick={() => {
                try {
                  localStorage.removeItem(historyKey);
                  setHistory([]);
                } catch {
                  setError("清除历史失败");
                }
              }}
            >
              清除
            </button>
          </div>
          {history.length ? (
            <div className="coffee-history-list">
              {history.map((entry, index) => (
                <div key={`${entry.time}-${index}`}>
                  <time>{new Date(entry.time).toLocaleString("zh-CN", { hour12: false })}</time>
                  <strong className="mono">{formatIPText(entry.ip, ipsVisible)}</strong>
                </div>
              ))}
            </div>
          ) : (
            <div className="guard-empty">暂无历史</div>
          )}
        </section>
      </div>
    </div>
  );
}
