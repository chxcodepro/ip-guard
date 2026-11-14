import { Cable } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { formatIPText, proxySettingsSchema } from "@ip-guard/electron";
import type { Command, ProxyEnhancementState, ProxySettings, Reply } from "@ip-guard/electron";

export function ProxyEnhancementPanel({
  busy,
  onAction,
  ipsVisible,
}: {
  busy: boolean;
  onAction: (command: Command, onFailure?: (message: string) => void) => Promise<Reply | undefined>;
  ipsVisible: boolean;
}) {
  const [state, setState] = useState<ProxyEnhancementState>();
  const [mode, setMode] = useState<"system" | "manual">("system");
  const [address, setAddress] = useState("");
  const [error, setError] = useState("");
  const saved = useRef<ProxySettings | undefined>(undefined);
  const saving = useRef(false);
  const revision = useRef(0);
  const focusManual = useRef(false);
  const input = useRef<HTMLInputElement>(null);
  const selector = useRef<HTMLSelectElement>(null);
  useEffect(() => {
    if (focusManual.current && input.current) {
      input.current.focus();
      focusManual.current = false;
    }
  }, [mode]);
  useEffect(() => {
    let alive = true;
    const refresh = () => {
      const current = revision.current;
      void window.desktop
        ?.invoke({ action: "proxy:status" })
        .then((reply) => {
          if (!alive || saving.current || revision.current !== current || !reply.proxyEnhancement)
            return;
          setState(reply.proxyEnhancement);
          if (!saved.current) {
            saved.current = reply.proxyEnhancement.settings;
            setMode(saved.current.mode);
            if (saved.current.mode === "manual") setAddress(saved.current.address);
          }
        })
        .catch(() => {
          if (alive && revision.current === current) setError("代理状态读取失败");
        });
    };
    refresh();
    const timer = setInterval(refresh, 2000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, []);
  const save = async (settings: ProxySettings) => {
    if (saving.current) return;
    const previous = saved.current;
    if (
      previous?.mode === settings.mode &&
      (settings.mode === "system" ||
        (previous.mode === "manual" && previous.address === settings.address))
    ) {
      setError("");
      return;
    }
    saving.current = true;
    revision.current++;
    setError("");
    try {
      const reply = await onAction({ action: "proxy:configure", settings }, (message) =>
        setError(`${message}；已保留原设置`),
      );
      if (reply?.proxyEnhancement) {
        saved.current = reply.proxyEnhancement.settings;
        setState(reply.proxyEnhancement);
        setMode(saved.current.mode);
        if (saved.current.mode === "manual") setAddress(saved.current.address);
      }
    } finally {
      saving.current = false;
      revision.current++;
    }
  };
  const saveAddress = () => {
    if (busy || saving.current) return;
    const parsed = proxySettingsSchema.safeParse({ mode: "manual", address });
    if (!parsed.success) {
      setError(parsed.error.issues[0]?.message || "请填写有效的本机代理入口");
      return;
    }
    void save(parsed.data);
  };
  return (
    <div className="settings-group">
      <div className="setting-row">
        <span className="setting-icon">
          <Cable size={19} />
        </span>
        <div className="setting-info">
          <strong>Claude 专用代理</strong>
          <span className="setting-detail" role="status">
            {state?.error || state?.endpoint || "正在读取"}
          </span>
          {state?.verification && (
            <span className="setting-detail" role="status">
              {state.verification.reason}
              {state.verification.currentIp &&
                ` · ${formatIPText(state.verification.currentIp, ipsVisible)}`}
            </span>
          )}
        </div>
        <select
          ref={selector}
          aria-label="增强代理来源"
          value={mode}
          disabled={busy || !state || !window.desktop}
          onChange={(event) => {
            if (
              saving.current ||
              (event.target.value !== "system" && event.target.value !== "manual")
            )
              return;
            const next = event.target.value;
            setMode(next);
            setError("");
            if (next === "system") void save({ mode: "system" });
            else {
              focusManual.current = true;
              const parsed = proxySettingsSchema.safeParse({ mode: "manual", address });
              if (parsed.success) void save(parsed.data);
            }
          }}
        >
          <option value="system">自动识别当前代理核心</option>
          <option value="manual">指定本机代理入口</option>
        </select>
      </div>
      {(mode === "manual" || error) && (
        <div className="egress-import">
          {mode === "manual" && (
            <div className="egress-import-controls">
              <input
                ref={input}
                aria-label="本机代理入口地址"
                value={address}
                placeholder="http://127.0.0.1:7890"
                maxLength={2048}
                disabled={busy}
                aria-invalid={Boolean(error)}
                aria-describedby={error ? "proxy-source-error" : undefined}
                onChange={(event) => {
                  setAddress(event.target.value);
                  setError("");
                }}
                onBlur={(event) => {
                  if (event.relatedTarget !== selector.current) saveAddress();
                }}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    event.preventDefault();
                    saveAddress();
                  }
                }}
              />
            </div>
          )}
          {error && (
            <div id="proxy-source-error" className="form-error" role="alert">
              {error}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
