import { browserStateSchema, formatIPText, isNewerExtensionVersion } from "@ip-guard/electron";

import "./style.css";

const app = document.getElementById("app");
if (!app) throw new Error("Missing page root");
const blocked = document.body.dataset.view === "blocked";
app.innerHTML = `<header><span class="brand">IP Guard <small>CLAUDE 防护</small></span><div class="header-actions"><button id="ip-visibility" class="quiet" aria-label="显示 IP 地址" title="显示 IP 地址" aria-pressed="false"></button><button id="theme" class="quiet" aria-label="切换深浅主题">◐</button></div></header>
<section id="extension-update" class="extension-update" hidden aria-live="polite"><strong id="update-version"></strong><a id="update-download" target="_blank" rel="noopener">下载插件</a><p>更新扩展文件后，在扩展管理页点击<span>「重新加载」</span>。</p></section>
<div class="scene"><svg class="shield" viewBox="0 0 48 48" fill="none" aria-hidden="true"><path d="M24 6 39 12v12c0 9-7 15-15 18C16 39 9 33 9 24V12Z"/><path class="tick" d="m17 24 5 5 10-11"/></svg></div>
<h1 id="status" role="status">连接中</h1><p id="reason"></p>
<dl><div><dt>Claude AI 出口 IPv4</dt><dd id="current">—</dd></div><div><dt>锁定 IPv4</dt><dd id="expected">—</dd></div></dl>
<ol id="steps"><li>守护连接<span></span></li><li>地址锁定<span></span></li><li>Claude AI 出口<span></span></li><li>IPv4 对照<span></span></li></ol>
<div class="actions"><button id="reconnect">重新连接</button><button id="open" class="primary" disabled>${blocked ? "返回 Claude" : "打开 Claude"}</button></div>
<footer><span id="time">等待守护结果</span><span id="version"></span></footer>`;
function element(id: string) {
  const found = document.getElementById(id);
  if (!found) throw new Error(`Missing ${id}`);
  return found;
}
function button(id: string) {
  const found = element(id);
  if (!(found instanceof HTMLButtonElement)) throw new Error(`Missing button ${id}`);
  return found;
}
const open = button("open");
document.documentElement.dataset.theme =
  localStorage.getItem("theme") ??
  (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
element("theme").addEventListener("click", () => {
  const value = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = value;
  localStorage.setItem("theme", value);
});
let permitted = false;
let ipsVisible = false;
function updatePrivacyButton() {
  const control = element("ip-visibility");
  const label = ipsVisible ? "隐藏 IP 地址" : "显示 IP 地址";
  control.setAttribute("aria-label", label);
  control.setAttribute("title", label);
  control.setAttribute("aria-pressed", String(ipsVisible));
  control.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>${ipsVisible ? '<path d="m3 3 18 18"/>' : ""}</svg>`;
}
element("ip-visibility").addEventListener("click", () => {
  ipsVisible = !ipsVisible;
  updatePrivacyButton();
  void render();
});
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    ipsVisible = false;
    updatePrivacyButton();
    void render();
  }
});
updatePrivacyButton();
async function render() {
  const saved = await chrome.storage.session.get(["state", "receivedAt"]);
  const parsed = browserStateSchema.safeParse(saved.state);
  const state = parsed.success ? parsed.data : undefined;
  const fresh = typeof saved.receivedAt === "number" && Date.now() - saved.receivedAt < 3500;
  const phase = fresh && state ? state.phase : "offline";
  const installedVersion = chrome.runtime.getManifest().version;
  const latestVersion = state?.latestExtensionVersion ?? state?.appVersion ?? "";
  const updateAvailable = isNewerExtensionVersion(latestVersion, installedVersion);
  document.body.dataset.update = String(updateAvailable);
  element("extension-update").hidden = !updateAvailable;
  const updateLabel = updateAvailable ? `插件有更新 v${latestVersion}` : "";
  const updateHeading = element("update-version");
  if (updateHeading.textContent !== updateLabel) updateHeading.textContent = updateLabel;
  if (updateAvailable)
    element("update-download").setAttribute(
      "href",
      `https://github.com/chxcodepro/ip-guard/releases/download/v${latestVersion}/IP-Guard-Browser-${latestVersion}.zip`,
    );
  permitted = phase === "allowed";
  document.body.dataset.phase = phase;
  element("status").textContent = permitted
    ? "校验通过"
    : phase === "checking"
      ? "正在检测"
      : "访问已阻断";
  element("reason").textContent = formatIPText(
    fresh && state ? state.reason : "请运行 IP Guard 并准备浏览器扩展",
    ipsVisible,
  );
  element("current").textContent = formatIPText(state?.currentIp || "—", ipsVisible);
  element("expected").textContent = formatIPText(state?.expectedIp || "—", ipsVisible);
  element("version").textContent = `插件 v${installedVersion}`;
  const date = state?.checkedAt ? new Date(state.checkedAt) : undefined;
  element("time").textContent =
    date && Number.isFinite(date.getTime())
      ? `最近检测 ${date.toLocaleTimeString("zh-CN", { hour12: false })}`
      : "等待守护结果";
  open.disabled = !permitted;
  const values = [
    phase !== "offline",
    phase !== "offline" && phase !== "unlocked",
    Boolean(state?.currentIp) && fresh,
    permitted,
  ];
  element("steps")
    .querySelectorAll("li")
    .forEach((step, index) => {
      step.dataset.done = String(values[index]);
      const marker = step.querySelector("span");
      if (marker) marker.textContent = values[index] ? "✓" : phase === "checking" ? "·" : "—";
    });
}
element("reconnect").addEventListener("click", () => {
  void chrome.runtime.sendMessage({ action: "reconnect" }).catch(() => {
    element("reason").textContent = "扩展后台未连接，请重新加载扩展";
  });
});
open.addEventListener("click", () => {
  if (!permitted) return;
  let target = "https://claude.ai/";
  try {
    const url = new URL(new URLSearchParams(location.search).get("target") ?? target);
    if (
      url.protocol === "https:" &&
      (url.hostname === "claude.ai" || url.hostname.endsWith(".claude.ai"))
    )
      target = url.href;
  } catch {
    target = "https://claude.ai/";
  }
  if (blocked) location.replace(target);
  else void chrome.tabs.create({ url: target });
});
chrome.storage.onChanged.addListener(() => void render());
setInterval(() => void render(), 1000);
void render();
