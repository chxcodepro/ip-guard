# Fort 离线检查与恢复组件

本目录保留 Fort Firewall 3.20.9 / ABI 65 的内存自检入口。实现已移至 `apps/desktop/native/process-network`，自 v0.12.0 起随应用分发，增强默认关闭。

**实机加载验证曾造成全机断网。修复后的驱动接入仍待隔离测试系统验收，当前电脑保持已恢复的网络状态。** 恢复实现与验收依赖见下方章节。

## 只编译，不执行

在仓库根运行：

```powershell
node apps/desktop/scripts/build-process-network.ts
```

产物：

- `artifacts/process-network-prototype/IpGuard.ProcessNetwork.Review.exe`：`--self-check` 仅检查内存中的协议、状态机和过滤项身份。
- `artifacts/process-network-prototype/IpGuard.ProcessNetwork.Recovery.exe`：默认 `--status` 仅读取状态；`--repair` 会停止自有受控进程、停用驱动并清理自有规则，`--automatic` 在恢复互斥下重新确认失联条件后才执行相同步骤。

构建脚本还编译正式原生入口；各脚本均不启动产物或加载驱动。新增回归源已编译审查，实机网络与恢复验收尚未完成。

## 固定出口由内核规则和代理门禁共同控制

`FortPolicy` 编码精确 EXE 路径的递归父子规则：只允许 IPv4 TCP 出站到 `127.0.0.1:<固定代理端口>`；其他地址、端口、IPv6、UDP 和新入站连接均拒绝。回环和 LAN 过滤开启，其他程序默认允许。布局与位标志见 [线协议契约](CONTRACT.md)。

公网 IPv4 授权归现有固定通道门禁。复核期间关闭转发和既有代理连接，保留进程；通过后恢复同一实例。后台复核不重复提交内核配置。

## 加载前置条件

- HVCI 运行、已配置、待启用或状态读取失败时保持关闭，系统安全设置保持原样。
- 提供者数据的 `boot_filter=1` / `filter_locals=1`，以及四个启动项、四个持久 ALE BLOCK 均须核实。`FortProvider.ReadProtection` 仅读取证明。
- 自有注册使用受管理员 / SYSTEM 保护的 64 位 `HKLM\SOFTWARE\IPGuard\ProcessNetwork`，格式为 `Format=2`，绑定 `OwnerSid` 与完整 `DriverPath`。
- 服务为 `fortfw`，按需启动，驱动路径使用未加引号的 NT 路径。已有其他 Fort 安装时保留其服务和规则。
- 驱动来自官方 x64 安装包，118832 字节，微软硬件兼容发布者签名有效；资源版本 **1.0.0** 与接口版本 **65** 分别核对。

## 失败立即回滚，恢复完成后停止重试

安装只注册按需服务。加载前核对独立 SYSTEM 恢复任务已启用、执行路径正确，再取得守护租约。租约取得和自动恢复条件复核共用操作互斥，设备 IO 与服务停止不持有它。

初始化失败会立即关闭门禁、关闭设备、停止自有驱动并清理过滤项。原始错误与恢复错误一起传给界面。正常退出先冻结新 Job，等待受控 Job 排空后执行同一清理；中途失败支持再次停止。

Fort 原生过滤项的 `providerKey` 为空。清理按固定版本的 GUID、名称、层 / 子层和动作核对，通过逐键查询覆盖启动项及禁用项。提供者缺失时仍清理已核实的孤立项；其他提供者或身份不匹配的对象保留。

过滤项删除先独立提交，再清理 callout、子层和提供者。后一步失败时，已删除的 BLOCK 项保持删除。全部成功后按操作 nonce 清除 `RecoveryPending`，防止分钟任务重复恢复；故障恢复后的服务保持禁用，重新加载须经手动恢复。

## 验收依赖

首包、长连接、缺失元数据、失联恢复、重启清理、TUN / v2rayN 及其他驱动共存仍需在隔离测试系统验证。原版 Fort 在映像或命令行缺失时跳过进程登记；调试门禁覆盖本机进程的方案也尚未完成实机验收。WMI、任务计划、共享 DNS、本地 Cowork VM 等代理执行路径需要独立归属证据。

项目经用户确认采用 GPL-3.0-only；分发须附对应源码与许可。该组件随稳定版分发，增强仍为实验状态。固定节点服务端的出口变化仍由现有公网探测发现。

## 原始依据

- [接口版本](https://github.com/tnodir/fort/blob/v3.20.9/src/version/fort_version.h)、[IOCTL](https://github.com/tnodir/fort/blob/v3.20.9/src/driver/common/fortioctl.h)、[配置布局](https://github.com/tnodir/fort/blob/v3.20.9/src/driver/common/fortconf.h)
- [过滤项定义与归属字段](https://github.com/tnodir/fort/blob/v3.20.9/src/driver/common/fortprov.c)、[客户端失联](https://github.com/tnodir/fort/blob/v3.20.9/src/driver/fortdev.c)
- [Windows 过滤项枚举标志](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_enum_template0)、[启动与持久过滤项生命周期](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilteradd0)
- [HVCI 约束](https://github.com/tnodir/fort/wiki/HVCI)、[官方发布](https://github.com/tnodir/fort/releases/tag/v3.20.9)、[许可](https://github.com/tnodir/fort/blob/v3.20.9/LICENSE)
