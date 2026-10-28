import { browserHostName, browserStateSchema, isNewerExtensionVersion } from "@ip-guard/electron";
import type { BrowserState } from "@ip-guard/electron";

let state: BrowserState = {
  protocol: 1,
  appVersion: "",
  phase: "offline",
  currentIp: "",
  expectedIp: "",
  checkedAt: "",
  reason: "正在连接 IP Guard",
};
let port: chrome.runtime.Port | undefined;
let lastHeartbeat = 0;
let reconnect: ReturnType<typeof setTimeout> | undefined;
let queue = Promise.resolve();
let permitted = false;
const isClaude = (value: string) => {
  try {
    const url = new URL(value);
    return (
      ["https:", "http:"].includes(url.protocol) &&
      (url.hostname === "claude.ai" || url.hostname.endsWith(".claude.ai"))
    );
  } catch {
    return false;
  }
};
const offline = (reason: string) => ({
  ...state,
  phase: "offline" as const,
  currentIp: "",
  reason,
});
const allowed = () => state.phase === "allowed" && Date.now() - lastHeartbeat < 3500;
async function blockTabs() {
  const tabs = await chrome.tabs.query({ url: ["*://claude.ai/*", "*://*.claude.ai/*"] });
  await Promise.all(
    tabs.map(async (tab) => {
      if (tab.id === undefined || !tab.url || !isClaude(tab.url)) return;
      try {
        await chrome.tabs.update(tab.id, {
          url: chrome.runtime.getURL(`blocked.html?target=${encodeURIComponent(tab.url)}`),
        });
      } catch {
        /* A tab can close while the policy changes. */
      }
    }),
  );
}
function publish() {
  queue = queue
    .then(async () => {
      const permit = allowed();
      if (permit !== permitted) {
        await chrome.declarativeNetRequest.updateSessionRules({
          removeRuleIds: [100],
          addRules: permit
            ? [
                {
                  id: 100,
                  priority: 1000,
                  action: { type: chrome.declarativeNetRequest.RuleActionType.ALLOW },
                  condition: {
                    requestDomains: ["claude.ai"],
                    resourceTypes: Object.values(chrome.declarativeNetRequest.ResourceType),
                  },
                },
              ]
            : [],
        });
        permitted = permit;
      }
      if (!permit) await blockTabs();
      await chrome.storage.session.set({ state, receivedAt: Date.now() });
      const latest = state.latestExtensionVersion ?? state.appVersion;
      const update = isNewerExtensionVersion(latest, chrome.runtime.getManifest().version);
      await chrome.action.setBadgeText({ text: !permit ? "!" : update ? "↑" : "" });
      await chrome.action.setBadgeBackgroundColor({
        color: !permit || update ? "#a6691a" : "#137e51",
      });
      await chrome.action.setTitle({
        title: `IP Guard${!permit ? " · 访问已阻断" : ""}${update ? ` · 插件有更新 v${latest}` : ""}`,
      });
    })
    .catch(async (error: unknown) => {
      state = offline(error instanceof Error ? error.message : "浏览器规则更新失败");
      port?.disconnect();
      port = undefined;
      await chrome.declarativeNetRequest
        .updateSessionRules({ removeRuleIds: [100] })
        .catch(() => undefined);
      permitted = false;
      await blockTabs();
      await chrome.storage.session.set({ state, receivedAt: Date.now() });
    });
  return queue;
}
function connect() {
  if (port) return;
  clearTimeout(reconnect);
  const next = chrome.runtime.connectNative(browserHostName);
  port = next;
  lastHeartbeat = Date.now();
  next.onMessage.addListener((input: unknown) => {
    if (port !== next) return;
    const result = browserStateSchema.safeParse(input);
    if (!result.success) {
      state = offline("守护消息无效，请更新 IP Guard 与扩展");
      next.disconnect();
      port = undefined;
      reconnect = setTimeout(connect, 3000);
    } else {
      state = result.data;
      lastHeartbeat = Date.now();
    }
    void publish();
  });
  next.onDisconnect.addListener(() => {
    const reason = chrome.runtime.lastError?.message;
    if (port !== next) return;
    port = undefined;
    state = offline(reason ? "请在新版 IP Guard 设置中准备浏览器扩展" : "IP Guard 连接已断开");
    void publish();
    reconnect = setTimeout(connect, 3000);
  });
  next.postMessage({
    action: "watch",
    protocol: 1,
    extensionVersion: chrome.runtime.getManifest().version,
  });
}
chrome.runtime.onMessage.addListener((input: unknown, sender, reply) => {
  if (sender.id !== chrome.runtime.id || !input || typeof input !== "object") return;
  if (Reflect.get(input, "action") === "reconnect") {
    port?.disconnect();
    port = undefined;
    state = offline("正在重新连接");
    void publish().then(connect);
    reply({ ok: true });
  }
});
chrome.tabs.onUpdated.addListener((_id, change) => {
  if (change.url && isClaude(change.url) && !allowed()) void publish();
});
chrome.alarms.onAlarm.addListener(() => {
  if (!port) connect();
});
setInterval(() => {
  if (port && Date.now() - lastHeartbeat > 3500) {
    const previous = port;
    port = undefined;
    previous.disconnect();
    state = offline("守护心跳已过期");
    void publish();
    reconnect = setTimeout(connect, 3000);
  }
}, 1000);
void chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [100] }).then(async () => {
  await chrome.alarms.create("reconnect", { periodInMinutes: 0.5 });
  await publish();
  connect();
});
