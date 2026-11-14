# Fort 3.20.9 / ABI 65 的最小配置契约

以下数值独立取自上游 `fortconf.h`、`fortioctl.h`、`fortconf_valid.c`、`confdata.cpp`。原型仅面向 Windows x64，小端序；输入输出都是变长数据，不使用 C# 默认结构布局猜测协议。

| 项目 | 线协议 |
| --- | --- |
| VALIDATE | IOCTL `0xD000B400`，载荷 `41 00` |
| SETCONF | IOCTL `0xD000B408` |
| FORT_CONF_IO.conf | 偏移 8，前 8 字节为 active periods mask |
| FORT_CONF.data | 相对 conf 偏移 28，整个载荷偏移 36 |
| 配置 flags | `0x4039`：boot、启用过滤、过滤回环、过滤局域网、允许非目标程序 |
| exe_apps_n | 整个载荷偏移 18，UINT16 |
| 地址组 | 偏移表 8 字节，两个空列表头各 16 字节，共 40 字节；include_all 与空列表位为 `0xD`，不显式放行任何已列地址 |
| 应用数据 | 24 字节：flags、zone masks、speed IDs、padding、groups、app ID |
| 应用 flags | `0x4002`：found + apply_child；不设置 blocked，交由末尾拒绝规则处理 |
| 应用 path | entry 偏移 30，UTF-16LE 字节长度，后附 WCHAR NUL |
| 应用 rule | 紧跟路径 NUL，没有额外对齐；长度 64 字节 |
| Rule flags | `0x2061`：enabled、has_filters、terminate、term_blocked |
| Filter header | `(size << 7) | (type << 3)`；本原型各子过滤器补齐到 4 字节 |

规则为 IPv4、出站、TCP、远端地址 `127.0.0.1`、配置端口的 AND。命中放行；不命中走 terminating deny。IPv4 与端口数值采用上游的主机整数表示，再以小端写入。

对于端口 **23456**，64 字节规则的固定期望值：

```text
61 20 00 00 78 1e 00 00
28 04 00 00 01 00 00 00
30 04 00 00 02 00 00 00
20 04 00 00 01 00 06 00
00 0c 00 00 01 00 00 00 00 00 00 00
01 00 00 7f 00 00 00 00 00 00 00 00
08 04 00 00 01 00 a0 5b
```

单个路径 `C:\apps\claude.exe` 为 18 个 UTF-16 字符，路径长度字段 36，整个 SETCONF 208 字节，应用项起始于 76，规则起始于 144。这些固定值用于内存自检，尚未执行。

持久提供者数据 `FORT_PROV_BOOT_CONF` 为四字节值 **3**：boot_filter + filter_locals。它和四个无条件 ALE 持久 BLOCK 项必须在驱动加载前准备；仅把配置 flags 的 boot 位设为 1，无法证明设备级故障封锁已生效。

WFP x64 读取使用 SDK 布局：提供者 key 0、flags 32、providerData 40、serviceName 56；过滤器 providerKey 40、layerKey 64、numFilterConditions 112、action.type 128。实际驱动、WFP 读取及恢复仍须在获准的隔离验证中确认。

读取前提还排除 SDK 的提供者禁用位 `0x10`、过滤器禁用位 `0x20`，并要求持久阻断项具有 PERSISTENT 与 CLEAR_ACTION_RIGHT（`0x9`）。仅存在同名对象不足以判定封锁就绪。
