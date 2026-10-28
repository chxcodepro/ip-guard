# Claude 浏览器防护

适用于 Windows 上的 Chrome / Edge，需要 IP Guard 0.8.0 或更新版本。

## 安装

1. 先保存 Claude 会话，再安装新版 IP Guard。覆盖安装会结束受保护程序。
2. 打开 IP Guard，在设置中点击「准备安装扩展」或「打开扩展文件夹」。它会注册当前 Windows 用户的浏览器连接，并打开扩展文件夹。
3. Chrome 打开 `chrome://extensions`，Edge 打开 `edge://extensions`。
4. 开启「开发者模式」，选择「加载已解压的扩展」，选中上一步打开的文件夹。
5. 将 IP Guard 扩展固定到工具栏，在桌面程序中锁定允许的 IPv4；扩展显示「校验通过」后打开 Claude。

也可从 Releases 下载 `IP-Guard-Browser-<版本>.zip`，解压到长期保留的目录，再加载该目录。更新 ZIP 后在扩展管理页点击重新加载。桌面更新通过软件内更新完成。

## 防护规则

- 新请求覆盖 `claude.ai` 及其子域；其他网站保留原行为。
- 地址取自桌面程序的 Claude AI 出口，扩展共用锁定地址和检测间隔。
- 连接未就绪、地址未锁定、IP 不匹配、检测失败或结果过期时阻断。
- 阻断时已打开的 Claude 页面切换到本地结果页，中断页面连接，未发送内容可能丢失。
- 匹配后点击「返回 Claude」恢复原页面；后台持续检测。
- 匹配且放行规则就绪时，直接输入 `claude.ai` 或点击「打开 Claude」「返回 Claude」直接进入 Claude 网站。
- 无痕 / InPrivate 窗口需要在扩展详情中单独允许。
- 扩展需保持启用，IP Guard 需持续运行；退出桌面程序后网页保持阻断。

## 连接与隐私

使用浏览器 Native Messaging 和按当前用户隔离的命名管道。扩展接收防护状态、当前 IP、锁定 IP、检测时间及插件最新版本，并上报自身版本。聊天内容和系统代理保持原样。宿主仅接受固定扩展 ID `blmgamidelconfabgilaacbkokomegep`。

## 更新提醒

桌面和扩展 0.9.4 起提供版本提醒，复用桌面启动时的 GitHub Releases 检查。工具栏 `↑` 与插件页面提示新版；阻断时 `!` 优先显示。插件页底部显示实际插件版本，桌面设置会核对正在运行的版本并标记「插件待更新」。

- 桌面自带目录：更新桌面程序后，在扩展管理页点击「重新加载」。
- 独立 ZIP：点击「下载插件」，解压覆盖原目录，再到扩展管理页点击「重新加载」。
- Chrome 扩展管理页为 `chrome://extensions`，Edge 为 `edge://extensions`。

官方依据：[Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)、[请求规则](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest)、[后台生命周期](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle)。

## 开发

仓库根运行 `pnpm exec vp run --filter @ip-guard/browser-extension build`，输出 `apps/browser-extension/dist`。桌面打包会同时生成扩展 ZIP，并将扩展文件包含进安装包。
