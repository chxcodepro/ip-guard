# Claude 网页防护

适用于 Chrome / Edge，配合 IP Guard 0.12.0 使用。仅保护 claude.ai 网页；不接管浏览器代理、WebRTC 或官方 Claude in Chrome / Edge 插件。

## 安装

1. 在桌面「防护设置 → Claude 网页防护」准备扩展，或解压 `IP-Guard-Browser-<版本>.zip`。
2. Chrome 打开 `chrome://extensions/`，Edge 打开 `edge://extensions/`；开启开发者模式，加载扩展目录。
3. 保持桌面运行并锁定允许 IPv4。插件校验通过后，直接输入 claude.ai 或点击「打开 Claude」「返回 Claude」进入网站。

使用过 0.12.x / 0.13.0–0.13.3 的用户，请先移除旧 IP Guard 扩展，再加载新版，以释放旧版代理和 WebRTC 覆盖。保留官方 Claude 插件；旧版曾暂停它时请手动重新启用。普通网页扩展版本后续更新覆盖目录并重新加载即可。

## 范围与状态

- 静态主导航规则仅作用于 claude.ai 及子域，页面请求规则同时匹配 Claude 网页发起源；官方插件后台与其他网站请求保留。
- 锁定且新鲜的 Claude AI IPv4 命中允许列表后，使用包含 main_frame 的会话规则放行；异常、未锁定、失联或心跳过期时撤销，现有 Claude 标签页切换到本地结果页。
- 网页 IP 通过系统代理单独检测，与 EXE 的增强通道分开。没有新增全浏览器代理，插件当前版本和 GitHub 更新提醒继续显示。
- 权限没有 proxy、privacy 或 management；不启停官方 Claude 插件，不修改浏览器资料或其他扩展。
- 浏览器卸载或停用本网页扩展会停止网页判断，npm / 原生 / Desktop 的独立防护继续由桌面程序管理。

## 开发

根目录执行 `pnpm exec vp run --filter @ip-guard/browser-extension build`，输出 `apps/browser-extension/dist`。本轮只定向编译、审查与隔离预览，不运行测试套件，不操作当前用户浏览器资料或网络规则。
