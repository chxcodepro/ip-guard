import { LoaderCircle, Plus, Save, ShieldCheck, Trash2, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { initialNetworkPolicy, networkPolicySchema, networkHost } from "@ip-guard/electron";
import type { Command, NetworkPolicy, NetworkPolicyState, Reply } from "@ip-guard/electron";

const phases = { active: "已生效", paused: "联网已暂停", inactive: "尚未启用", failed: "应用失败" };
export function NetworkPolicyDialog({
  busy,
  available,
  onClose,
  onAction,
}: {
  busy: boolean;
  available: boolean;
  onClose: () => void;
  onAction: (command: Command, onFailure?: (message: string) => void) => Promise<Reply | undefined>;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const initialized = useRef(false);
  const [state, setState] = useState<NetworkPolicyState>();
  const [draft, setDraft] = useState<NetworkPolicy>(structuredClone(initialNetworkPolicy));
  const [error, setError] = useState("");
  const [focusId, setFocusId] = useState("");
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    let alive = true;
    const refresh = () =>
      void window.desktop
        ?.invoke({ action: "network:status" })
        .then((reply) => {
          if (!alive || !reply.networkPolicy) return;
          setState(reply.networkPolicy);
          if (!initialized.current) {
            setDraft(structuredClone(reply.networkPolicy.settings));
            initialized.current = true;
          }
        })
        .catch((error: unknown) => {
          if (alive) setError(error instanceof Error ? error.message : "策略读取失败");
        });
    refresh();
    const timer = setInterval(refresh, 2000);
    return () => {
      alive = false;
      clearInterval(timer);
      element?.close();
    };
  }, []);
  const dirty = Boolean(state && JSON.stringify(draft) !== JSON.stringify(state.settings));
  const update = (index: number, value: Partial<NetworkPolicy["rules"][number]>) => {
    setError("");
    setDraft((current) => ({
      rules: current.rules.map((rule, i) => (i === index ? { ...rule, ...value } : rule)),
    }));
  };
  const save = async () => {
    const parsed = networkPolicySchema.safeParse(draft);
    if (!parsed.success) {
      const issue = parsed.error.issues[0],
        index = issue?.path[1];
      setError(
        (typeof index === "number" ? "规则 " + (index + 1) + "：" : "") +
          (issue?.message ?? "请检查规则"),
      );
      return;
    }
    setError("");
    const reply = await onAction({ action: "network:save", settings: parsed.data }, setError);
    if (reply?.networkPolicy && !reply.cancelled) {
      setState(reply.networkPolicy);
      setDraft(structuredClone(reply.networkPolicy.settings));
    }
  };
  return (
    <dialog
      ref={dialog}
      className="guard-dialog network-policy-dialog"
      aria-labelledby="network-policy-title"
      onCancel={(event) => {
        if (busy) event.preventDefault();
        else onClose();
      }}
      onClick={(event) => {
        if (!busy && event.target === event.currentTarget) onClose();
      }}
    >
      <form
        onSubmit={(event) => {
          event.preventDefault();
          if (!busy && available) void save();
        }}
      >
        <header>
          <div>
            <h2 id="network-policy-title">拦截策略</h2>
            <p className="policy-scope">
              {state?.scope === "managed_proxy" ? "受管代理连接" : "全局 · 使用受控代理的程序"}
            </p>
          </div>
          <button
            type="button"
            className="icon-btn"
            aria-label="关闭策略编辑"
            disabled={busy}
            onClick={onClose}
          >
            <X size={18} />
          </button>
        </header>
        <div className="policy-body">
          <section className="policy-effective" aria-label="实际防护状态">
            <div className="policy-section-heading">
              <h3>
                <ShieldCheck size={17} />
                当前防护
              </h3>
              <span className={`policy-status ${state?.phase ?? "loading"}`} role="status">
                {state ? phases[state.phase] : "正在读取…"}
              </span>
            </div>
            <dl className="policy-facts">
              <div>
                <dt>公网默认</dt>
                <dd>{state?.scope === "managed_proxy" ? "当前代理 / 网络" : "专用代理"}</dd>
              </div>
              <div>
                <dt>其他本机端口</dt>
                <dd>阻断</dd>
              </div>
              {state?.scope !== "managed_proxy" && (
                <div>
                  <dt>进程公网直连</dt>
                  <dd>阻断</dd>
                </div>
              )}
              {state?.scope !== "managed_proxy" && (
                <div>
                  <dt>进程 UDP / 公网 IPv6</dt>
                  <dd>阻断</dd>
                </div>
              )}
              <div>
                <dt>IPv4 未通过</dt>
                <dd>暂停公网连接</dd>
              </div>
              {state?.scope !== "managed_proxy" && (
                <div>
                  <dt>进程树过滤</dt>
                  <dd>{state?.childProtection ? "已就绪" : "未就绪"}</dd>
                </div>
              )}
              <div className="policy-fact-wide">
                <dt>{state?.scope === "managed_proxy" ? "代理本机端口" : "内核本机端口"}</dt>
                <dd>
                  {state?.childProtection || state?.scope === "managed_proxy"
                    ? state.localPorts.length
                      ? state.localPorts.join("、")
                      : "无"
                    : "—"}
                </dd>
              </div>
              <div className="policy-fact-wide">
                <dt>作用程序</dt>
                <dd>{state?.programs.join("、") || "暂无使用受控代理的程序"}</dd>
              </div>
            </dl>
            {state?.error && (
              <div className="form-error" role="alert">
                {state.error}
              </div>
            )}
          </section>
          <section aria-labelledby="policy-rules-title">
            <div className="policy-section-heading">
              <h3 id="policy-rules-title">
                放行与阻断例外{dirty && <span className="policy-dirty">未保存</span>}
              </h3>
              <button
                type="button"
                className="btn"
                disabled={busy || !state || draft.rules.length >= 64}
                onClick={() => {
                  const id = crypto.randomUUID();
                  setFocusId(id);
                  setDraft((current) => ({
                    rules: [
                      ...current.rules,
                      {
                        id,
                        enabled: true,
                        host: "",
                        port: 443,
                        action: "proxy",
                      },
                    ],
                  }));
                }}
              >
                <Plus size={14} />
                添加规则
              </button>
            </div>
            <div className="policy-rule-labels" aria-hidden="true">
              <span>启用</span>
              <span>目标主机</span>
              <span>端口</span>
              <span>处理</span>
              <span />
            </div>
            <div className="policy-rules">
              {draft.rules.map((rule, index) => (
                <div className={`policy-rule ${rule.enabled ? "" : "disabled"}`} key={rule.id}>
                  <input
                    type="checkbox"
                    aria-label={`启用规则 ${index + 1}`}
                    checked={rule.enabled}
                    disabled={busy || !state}
                    onChange={(event) => update(index, { enabled: event.target.checked })}
                  />
                  <input
                    aria-label={`规则 ${index + 1} 目标主机`}
                    autoFocus={focusId === rule.id}
                    value={rule.host}
                    placeholder="localhost 或 example.com"
                    maxLength={253}
                    disabled={busy || !state}
                    required
                    onChange={(event) =>
                      update(index, {
                        host: event.target.value,
                        ...(networkHost(event.target.value) === "localhost" &&
                        rule.action === "proxy"
                          ? { action: "direct" }
                          : {}),
                      })
                    }
                  />
                  <input
                    aria-label={`规则 ${index + 1} 端口`}
                    type="number"
                    min={1}
                    max={65535}
                    value={rule.port || ""}
                    disabled={busy || !state}
                    required
                    onChange={(event) => update(index, { port: Number(event.target.value) })}
                  />
                  <select
                    aria-label={`规则 ${index + 1} 处理`}
                    value={rule.action}
                    disabled={busy || !state}
                    onChange={(event) => {
                      const value = event.target.value;
                      if (value === "proxy" || value === "direct" || value === "block")
                        update(index, { action: value });
                    }}
                  >
                    <option value="proxy" disabled={networkHost(rule.host) === "localhost"}>
                      走专用代理
                    </option>
                    <option value="direct">直连</option>
                    <option value="block">阻断</option>
                  </select>
                  <button
                    type="button"
                    className="icon-btn"
                    aria-label={`删除规则 ${index + 1}`}
                    disabled={busy || !state}
                    onClick={() =>
                      setDraft((current) => ({
                        rules: current.rules.filter((item) => item.id !== rule.id),
                      }))
                    }
                  >
                    <Trash2 size={15} />
                  </button>
                </div>
              ))}
              {!draft.rules.length && <div className="policy-empty">无例外，使用默认拦截策略</div>}
            </div>
          </section>
          {error && error !== state?.error && (
            <div className="form-error" role="alert">
              {error}
            </div>
          )}
        </div>
        <footer>
          {(dirty || state?.phase === "failed") && (
            <span className="policy-footer-state">
              {dirty ? "修改尚未应用" : "请检查并重新应用"}
            </span>
          )}
          <button type="button" className="btn" disabled={busy} onClick={onClose}>
            {dirty ? "取消" : "关闭"}
          </button>
          <button
            type="submit"
            className="btn primary"
            title={!available ? "请先连接管理员守护" : undefined}
            disabled={busy || !available || !state || (!dirty && state.phase !== "failed")}
          >
            {busy ? <LoaderCircle size={15} className="spin" /> : <Save size={15} />}
            {!dirty && state?.phase === "failed" ? "重新应用" : "保存并应用"}
          </button>
        </footer>
      </form>
    </dialog>
  );
}
