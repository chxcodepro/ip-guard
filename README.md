# IP Guard

Windows 10/11 x64 桌面公网 IPv4 守卫。使用 VibeStart CLI 0.1.1 创建，React + Electron 界面，原生 C# 守护器负责 Windows 策略。

## 开始使用

1. 从 [GitHub Releases](https://github.com/chxcodepro/ip-guard/releases/latest) 下载 `IP-Guard-Setup-*.exe` 并安装。
2. 打开 IP Guard。如果显示普通权限，点击「以管理员身份重启」，确认 Windows 授权。
3. 在「允许的公网 IPv4」旁点「获取当前 IPv4」填入地址，再点「锁定」。获取只改变表单草稿；数据统一取自「Claude 检测」中的「Claude AI 出口」，即 `https://claude.ai/cdn-cgi/trace`。
4. 关闭目标程序，在「受保护程序」添加 EXE，再打开程序旁的防护开关。
5. 从启动按钮、原快捷方式或双击 EXE 启动。每次启动都会重新校验。
6. 按需在设置中开启「开机启动」。登录 Windows 后进入托盘；关闭窗口继续后台运行。

安装包尚未配置代码签名。Windows 可能显示未知发布者提示。

覆盖升级保留检测配置与程序列表，并恢复已经开启的登录任务；卸载和整体恢复会解除防护。安装器兼容 0.1.0 的旧卸载逻辑，先备份配置，再恢复到新版本。

原生组件按版本放在 `resources/native/<版本>/`，界面与组件握手匹配后才初始化防护。设置页显示实际守护版本，组件缺失或混装时显示升级错误；启动时保留原有允许 IP、程序列表和锁定状态。

## Claude 路径预设

在「添加程序」中选择「Claude Code（npm）」「Claude Code（原生）」或「Claude Desktop」，自动填写当前安装路径与名称。预设只填表，添加后仍需手动开启防护。

- npm：定位当前用户的全局安装目录，读取包内原生 `claude.exe`，沿用 `claude.cmd` 实际调用的 EXE。
- 原生：识别 [官方 irm 安装](https://code.claude.com/docs/en/setup)的独立版本，检查 `%USERPROFILE%/.local/bin/claude.exe` 和 PATH 中的独立 EXE。只读取文件信息，不启动 Claude；未安装显示「未找到」，可手动浏览选择。
- Desktop：读取当前注册的 Claude MSIX 主应用路径，也支持传统安装的卸载注册信息。

每次打开添加窗口都会重新定位。已在列表中的路径显示「已添加」，预设和重复添加操作禁用。MSIX Desktop 更新前解除旧路径防护，更新后重新选择预设并启用；版本目录随 Desktop 更新变化。未找到或定位失败时可以浏览选择 EXE。

程序行的铅笔按钮可编辑名称与启动参数。保存不停止当前进程，参数在下次从 IP Guard 点击启动时生效；从终端启动继续使用该终端输入的参数。

### 从原终端启动

在 PowerShell、CMD 或 Pebrel 中继续使用原来的 `claude` 命令。控制台 EXE 使用 `IpGuard.Terminal.exe` 门卫，继承原终端输入输出、环境和工作目录。门卫固定执行已登记的 EXE，保留原参数、argv0 和退出码；GUI 与 MSIX 程序继续使用原窗口门卫。

同一受保护进程树中的同应用内部调用复用首次 IP 许可，例如 Claude 的版本查询和内置文件搜索，不重复弹窗或发起启动查询。归属由 Windows Job 和命名管道真实客户端核对；另开终端启动仍完整校验。后台轮询、网络变化复核及 IP 异常结束整棵进程树的规则保持不变。

## Claude 进程控制

窗口顶部「停止 Claude 进程树」旁显示运行状态。界面可见时每 3 秒刷新，恢复可见立即刷新；未运行时停止按钮禁用。

点击停止后确认，会结束当前登录用户、当前 Windows 会话中的 Claude CLI 和 Desktop 及其子进程，未保存会话可能丢失。若 IP Guard 自身由 Claude 子进程启动，请先从 Windows 快捷方式打开 IP Guard，以保留控制通道。读取信息失败会显示状态未知。

## 运行规则

### 启动浮窗

从原快捷方式、任务栏入口或 IP Guard 启动受保护程序时，先显示独立浮窗。绿色环绕图标转动，左侧按实际进度呈现守护连接、系统防护、检测网址 DNS 解析、公网 IPv4、本机时区与锁定地址对照。完成后显示当次 IPv4 和锁定 IP；匹配时播放绿勾，结果停留 2.2 秒，末段 200ms 淡出后恢复目标程序执行。被阻断时显示原因与「知道了」，窗口保留到确认。关闭浮窗或按 Esc 会取消本次启动。

时区与 DNS 解析结果仅展示，IPv4 不匹配或校验失败仍是地址阻断依据。浮窗跟随 Windows 深浅色与动画设置，不在任务栏创建图标。MSIX Desktop 保留 Windows 包激活与 AppUserModelID，通过系统包调试入口在执行前接管进程；普通 Win32 与 npm 原生 EXE 沿用全路径 IFEO。

### 防护状态

- 锁定后地址和间隔保持只读，来源固定为 Claude AI 出口。取消锁定需确认，会结束受保护进程树并封锁连接；程序列表和防护开关保留，重新锁定后再启动。锁定状态在重启后保留，旧版已保存的有效 IP 升级后视为已锁定。
- 启动按钮旁会显示尚缺的条件：锁定 IP、开启程序防护、管理员权限或守护连接。
- IPv4 完全匹配才放行；网址不可达、超时、证书错误、重定向、返回格式错误也会触发阻断。
- 默认每 2 秒发起查询，请求共用一个生产者且不并发重复。单次含代理、DNS、HTTPS 与正文的查询最多等待 4.5 秒；变化发现时间包含请求耗时和系统调度。界面显示检测中及最新检测时间。
- 网卡、网络可用性、Wi-Fi、路由和电源变化只记录并立即复核公网 IPv4。仅在公网 IPv4 不匹配或校验失败时结束受保护 Job，并封锁目标 EXE 的入站、出站连接。
- 地址匹配时放行 IPv4 与 IPv6；升级时清除本工具 0.1.0 的 IPv6 常驻规则。普通子进程由 Job 共同结束；独立服务、WMI 或既有代理代发的连接需另行识别实际执行进程。
- 触发 IPv4 阻断后保持程序停止，下一次手动启动会重新校验。
- 托盘退出会结束受保护进程，保留 IFEO 和防火墙策略。守护程序缺席时原启动方式继续被拦截。门卫失联或收不到租约约 1.8 秒后结束 Job。
- 检测使用 Electron 网络栈的系统代理设置，使用独立网络会话，并在每次查询前关闭该会话的旧连接，避免代理节点切换后沿用旧隧道。获取按钮、两秒轮询、启动校验与 Claude AI 出口卡片使用同一结果；返回非 IPv4 或检测失败时继续阻断。目标应用若配置独立代理，需确认它与此出口一致。

### 网卡检测

设置页的「监控网卡」可选「自动识别联网网卡」或固定某张网卡。自动模式优先选择系统 IPv4 路由使用的接口；固定模式保留网卡标识，设备移除后显示「不存在」，重新接入后恢复识别。总览显示当前网卡及在线、断开、无 IPv4 或缺失状态。

网卡信息只作诊断；网络变化触发 Claude 出口 IPv4 复核，地址不匹配或检测失败时阻断。

### 开启 Windows 防火墙

域、专用或公用配置关闭时，IP Guard 会显示关闭项和操作指引。点「打开 Windows 防火墙」进入管理界面，点击「Windows Defender 防火墙属性」，将域、专用、公用三个选项卡中的「防火墙状态」设为「启用（推荐）」，确定后回到 IP Guard 重试。原 EXE 启动时遇到同类问题也会提示打开管理界面。远程桌面和局域网共享按需保留入站放行规则。

## Claude 检测

「Claude 检测」接入 [Net.Coffee 检测页](https://ip.net.coffee/claude/)的公开检测端点：国内、Cloudflare 和 Claude 出口，信任分、支持地区、位置/ASN/运营商、安全属性、连通性与 DNS 解析器。Claude AI 出口随守护轮询实时更新；其余诊断后台每 5 分钟刷新，可手动刷新。出口变动后重新检测关联属性。未取得结果或请求失败会直接显示。

WebRTC/UDP 在检测页中通过公开 STUN 服务采集；本机时区、语言、浏览器、网络类型、触屏、DNT、WebGL 与 Canvas 信息在本地展示。Claude 出口历史保存在本机，最多 6 条，可清除。

Claude AI 出口 IPv4 是允许地址的比较依据；低分、代理、Tor、DNS/UDP 出口不同及其余诊断失败只展示。服务地区和分数采用该站点评估。DNS 未观测到解析器或 UDP 无公网候选时显示未知。

IPv6 使用独立的 IPv6 请求检测公网、Cloudflare 和 Claude 出口，结果同时出现在总览及检测页。公网 IPv6 使用 [ipify 的 IPv6 专用接口](https://www.ipify.org/)。IPv6 请求保持 IPv6 地址族；无可用路由、超时或结果缺失显示未知。IPv6 仅检测，不参与阻断，也不改动系统 IPv6 设置。

颜色按站点公开规则呈现：绿色正常、蓝色提示、黄色需核查、红色异常、灰色未知。信任分按 95/80/50/25 分段；受限地区、机房与安全属性分别标记。DNS 依据中国解析器与非中国 Claude 出口组合，UDP 依据公网 IPv4 候选与 Claude 出口不一致标记；时区容差为 1 小时，中国大陆时区单独提示。连接延迟达到 500ms 标黄。异常行同时提供图标和文字。

## 浏览器防护

0.8.0 起提供 Chrome / Edge 扩展，按同一个锁定 IPv4 保护 `claude.ai` 及子域。IP 不匹配、检测失败、未锁定或守护离线时阻断请求，并将已有 Claude 页面切换到本地结果页；未发送内容可能丢失。

安装新版桌面程序后，在设置中点击「准备浏览器扩展」，再到浏览器扩展管理页开启开发者模式并加载打开的文件夹。也可加载 Releases 中插件 ZIP 解压后的目录。扩展显示匹配后点击「返回 Claude」。[完整安装步骤](apps/browser-extension/README.md)。

浏览器连接使用 Native Messaging，不接管系统代理。保留现有 Claude 会话时，可先下载安装包与插件，保存会话后再安装。

设置页显示「未安装」「已安装」「正在运行」。Chrome / Edge 标准用户目录中的本扩展安装记录用于判断已安装，实时宿主连接用于判断正在运行；读取失败显示未知。页面可见时每 5 秒刷新，恢复焦点立即刷新。自定义用户目录中的扩展连接后也会显示正在运行。

## 解除防护与恢复

单个程序：关闭程序旁的防护开关，会结束其受保护进程，移除本工具的 IFEO 路径过滤项和防火墙规则。

整体恢复：先从托盘退出，再运行安装目录 `resources/recover.cmd` 并确认管理员授权。工具会移除当前用户的 IP Guard 拦截、规则和登录任务；原配置另存为 `settings.json.recovery.bak`。卸载器也会调用同一恢复逻辑。请使用启用防护的同一个 Windows 账户解除或卸载。

配置：`%LOCALAPPDATA%/IPGuard/settings.json`，上次保存备份为 `settings.json.bak`。

日志：同目录 `events.jsonl`，达到 1MB 后轮换至 `events.jsonl.1`。界面显示当前会话最近 200 条事件。

## 适用程序

支持本机普通 Win32 EXE，按完整路径拦截。同名的其他路径保留原行为。MSIX 主应用从已注册包与清单定位入口，使用 Windows 的 `IPackageDebugSettings`；解除和整体恢复时撤销本工具持有的包调试设置。已存在的外部 IFEO 或包调试配置会直接报告。

反作弊、反调试和受保护进程可能拒绝接管。MSIX 的旧版 IFEO 设置在下次守护启动时改用包调试入口；原任务栏与快捷方式保持原有包身份。系统关键进程与恢复工具保留原启动方式。此版本采用用户态事件监控与轮询，短暂变化的发现依赖事件和采样时序。

## 开发与构建

Node 24，pnpm 12，Windows 自带 .NET Framework 4.x 编译器。无需单独安装 .NET SDK。

```powershell
npx --yes pnpm@12.15.0 install
npx --yes pnpm@12.15.0 exec vp run dev
npx --yes pnpm@12.15.0 exec vp run package:desktop
```

若已安装 Vite+，可直接使用 `vp install`、`vp run dev`、`vp run package:desktop`。浏览器预览只显示界面；管理策略通过 Electron 的隔离桥执行。开发模式需要从管理员终端启动才能启用真实防护。

## GitHub 发布与软件更新

在 [chxcodepro/ip-guard](https://github.com/chxcodepro/ip-guard) 发布稳定版 Release，即可触发 Windows 安装包构建：

1. 运行 `pnpm run version:app 0.9.1`，同步应用、原生组件与浏览器扩展版本。
2. 提交并推送代码，在该提交上创建并发布 `v0.9.1` Release。标签须与应用版本完全一致。
3. 等待 `Build Windows release` 工作流完成。它会向该 Release 附加桌面安装器、对应 `.blockmap`、`latest.yml` 和同版本浏览器扩展 ZIP。
4. 首次手动安装 GitHub 构建的版本，软件会自动绑定该仓库的更新源。

每次启动、重新打开托盘中的实例或从托盘打开窗口时检查更新；正在检查、下载或安装时复用当前操作。也可在「防护设置 → 软件更新」手动检查、下载，再确认「安装并重启」。安装会结束受保护程序，请先保存会话。关闭窗口或普通退出时保留已下载更新，等待下次主动安装。

本地安装包未绑定仓库时显示「GitHub 更新源未配置」，请安装 Releases 提供的版本。构建流程使用 [electron-updater](https://www.electron.build/docs/features/auto-update/) 的 GitHub provider 与 NSIS 更新元数据。

主要源码：

- `apps/desktop/native/`：IFEO、Job、网络监控、防火墙、登录任务、恢复。
- `apps/desktop/native/LaunchWindow.cs`、`LaunchGate.cs`：独立启动浮窗与挂起、租约、恢复执行。
- `apps/desktop/native/TerminalProcess.cs`：控制台门卫、标准句柄继承与退出码。
- `apps/desktop/native/PackagePolicy.cs`：保留 MSIX 身份的启动、接管与恢复。
- `apps/desktop/src/main/`：守护器通信、权限重启、托盘与窗口。
- `apps/desktop/src/main/coffee.ts`：独立的 Net.Coffee 数据采集。
- `apps/desktop/src/main/presets.ts`：Claude CLI 与 Desktop 安装路径发现。
- `apps/desktop/src/main/claude-ip.ts`：唯一 Claude AI 出口 IPv4 生产者，使用系统代理。
- `apps/desktop/native/ClaudeProbe.cs`：原生校验向主进程请求新结果，验证地址及新鲜度。
- `apps/desktop/src/main/claude-processes.ts`：当前用户 Claude 进程查询与确认后的树终止。
- `apps/desktop/src/main/updates.ts`：GitHub 更新状态、下载与确认安装。
- `apps/desktop/src/main/browser-installation.ts`：Chrome / Edge 扩展安装记录查询。
- `.github/workflows/release.yml`：Release 发布后的 Windows 构建与附件上传。
- `packages/electron/src/index.ts`：IPC Schema 与类型。
- `apps/web/src/components/guard-app.tsx`、`apps/web/src/guard.css`：双主题操作界面。
- `apps/web/src/components/coffee-page.tsx`：只读诊断、本机信息与 UDP 检测。
- `apps/web/src/components/claude-control.tsx`：停止按钮与运行状态。

守护异常退出的代码、错误信息和标准错误尾部保存在 `%LOCALAPPDATA%/IPGuard/guardian-errors.log`。

Windows API 依据：[MSIX 调试生命周期](https://learn.microsoft.com/en-us/windows/msix/desktop/desktop-to-uwp-debug)、[IPackageDebugSettings](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-ipackagedebugsettings)。

## 验证状态

0.9.0 已完成编译打包、修改范围 TypeScript / lint 与双主题界面检查。新控制台门卫通过现有守护校验后，将 Claude 版本输出回原 PowerShell 通道，完整路径与别名调用均返回 0。安装状态读取识别到本机 Chrome 扩展。未执行测试套件。

Pebrel 完整交互、独立原生 Claude 的实际启动、地址切换时的既有页面终止、开机登录、卸载恢复及软件内更新安装仍待目标环境联动验收。安装新版前请保存受保护程序中的内容。

Windows API 依据：[IFEO 启动转交](https://devblogs.microsoft.com/oldnewthing/20070702-00/?p=26193)、[Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)、[路径过滤与调试创建机制](https://diversenok.github.io/2021/02/26/IFEO.html)。
