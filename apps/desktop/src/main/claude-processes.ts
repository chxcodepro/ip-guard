import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";

import { z } from "zod";

import type { ClaudeState } from "@ip-guard/electron";

const run = promisify(execFile);
const windows = path.join(process.env.SystemRoot ?? "C:\\Windows", "System32");
const snapshotSchema = z.object({
  session: z.number().int().nonnegative(),
  username: z.string().min(1),
  unknown: z.number().int().nonnegative(),
  selfInTree: z.boolean(),
  processes: z.array(
    z.object({ pid: z.number().int().positive(), parent: z.number().int().nonnegative() }),
  ),
});
type ProcessSnapshot = z.infer<typeof snapshotSchema>;
const query = `
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$username=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$session=[System.Diagnostics.Process]::GetCurrentProcess().SessionId
$all=@(Get-CimInstance Win32_Process -Filter ("SessionId="+$session) -Property Handle,ProcessId,ParentProcessId,Name -ErrorAction Stop)
$items=@(); $unknown=0; $parents=@{}
foreach($p in $all) {
  $parents[[int]$p.ProcessId]=[int]$p.ParentProcessId
  if($p.Name -ne 'Claude.exe') { continue }
  try {
    $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop
    if($owner.ReturnValue -eq 0 -and $owner.Sid -eq $sid) { $items+=@{pid=[int]$p.ProcessId;parent=[int]$p.ParentProcessId} }
    elseif($owner.ReturnValue -ne 0) { $unknown++ }
  } catch { $unknown++ }
}
$ancestors=[System.Collections.Generic.HashSet[int]]::new()
$cursor=${process.pid}
while($cursor -gt 0 -and $ancestors.Add($cursor)) {
  if(-not $parents.ContainsKey($cursor)) { break }
  $cursor=$parents[$cursor]
}
$selfInTree=$false
foreach($p in $items) { if($ancestors.Contains($p.pid)) { $selfInTree=$true } }
@{session=$session;username=$username;unknown=$unknown;selfInTree=$selfInTree;processes=@($items)} | ConvertTo-Json -Depth 4 -Compress
`;
async function snapshot(): Promise<ProcessSnapshot> {
  const result = await run(
    path.join(windows, "WindowsPowerShell/v1.0/powershell.exe"),
    ["-NoProfile", "-NonInteractive", "-Command", query],
    { windowsHide: true, timeout: 12000, maxBuffer: 131072, encoding: "utf8" },
  );
  const value: unknown = JSON.parse(result.stdout.trim().replace(/^\uFEFF/, ""));
  return snapshotSchema.parse(value);
}
function state(value: ProcessSnapshot): ClaudeState {
  const running = value.processes.length > 0;
  return {
    phase: running ? "running" : value.unknown ? "unknown" : "stopped",
    count: value.processes.length,
    canStop: running && !value.selfInTree,
    message: value.selfInTree
      ? "请从 Windows 快捷方式打开 IP Guard 后停止 Claude"
      : value.unknown
        ? "部分进程信息读取失败"
        : "",
    checkedAt: new Date().toISOString(),
  };
}
let pending: Promise<ClaudeState> | undefined;
export function claudeStatus(): Promise<ClaudeState> {
  pending ??= snapshot()
    .then(state)
    .catch((): ClaudeState => ({
      phase: "unknown",
      count: 0,
      canStop: false,
      message: "Claude 进程状态读取失败",
      checkedAt: new Date().toISOString(),
    }))
    .finally(() => {
      pending = undefined;
    });
  return pending;
}
export async function stopClaudeTrees(): Promise<ClaudeState> {
  const before = await snapshot();
  if (before.selfInTree) throw new Error("请从 Windows 快捷方式打开 IP Guard 后停止 Claude");
  const ids = new Set(before.processes.map((item) => item.pid));
  const roots = before.processes.filter((item) => !ids.has(item.parent));
  await Promise.allSettled(
    roots.map((item) =>
      run(
        path.join(windows, "taskkill.exe"),
        [
          "/PID",
          String(item.pid),
          "/T",
          "/F",
          "/FI",
          "IMAGENAME eq Claude.exe",
          "/FI",
          `SESSION eq ${before.session}`,
          "/FI",
          `USERNAME eq ${before.username}`,
        ],
        { windowsHide: true, timeout: 10000, maxBuffer: 131072, encoding: "utf8" },
      ),
    ),
  );
  const after = state(await snapshot());
  if (after.phase === "running") throw new Error("部分 Claude 进程仍在运行，请检查权限后重试");
  if (after.phase === "unknown") throw new Error("停止请求已发送，进程状态暂未确认");
  return after;
}
