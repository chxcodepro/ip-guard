using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;

namespace IpGuard {
    internal static class DebugProcessTree {
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int type,IntPtr info,uint length,IntPtr returned);
        static bool HasProcesses(IntPtr job) {
            IntPtr data=Marshal.AllocHGlobal(48);
            try {Win32.Check(QueryInformationJobObject(job,1,data,48,IntPtr.Zero));return Marshal.ReadInt32(data,40)>0;}
            finally {Marshal.FreeHGlobal(data);}
        }
        public static void Run(Win32.ProcessInfo root,IntPtr job,Func<bool> active,Func<bool> heartbeat,bool protectChildren) {
            var debugged=new HashSet<uint>();debugged.Add(root.pid);
            try {
                while(active()) {
                    if(!heartbeat()) throw new Exception("守护连接超时，受保护程序已结束。");
                    Win32.DebugEvent item;
                    if(!Win32.WaitForDebugEvent(out item,200)) {if(protectChildren && !HasProcesses(job)) break;continue;}
                    if(protectChildren && item.code==3) {
                        debugged.Add(item.pid);
                        try {ProcessTreeMetadata.EnableChildren(item.info.process);ProcessTreeMetadata.Require(item.info.process);}
                        catch {Win32.TerminateJobObject(job,1);Win32.ContinueDebugEvent(item.pid,item.tid,0x00010002);throw;}
                    }
                    if((item.code==3 || item.code==6) && item.info.file!=IntPtr.Zero && item.info.file!=new IntPtr(-1)) Win32.CloseHandle(item.info.file);
                    uint status=item.code==1 && item.info.exception!=0x80000003 && item.info.exception!=0x80000004 ? 0x80010001U : 0x00010002U;
                    Win32.Check(Win32.ContinueDebugEvent(item.pid,item.tid,status));
                    if(item.code==5) debugged.Remove(item.pid);
                    if(item.code==5 && item.pid==root.pid && !protectChildren) {
                        while(active() && HasProcesses(job)) {if(!heartbeat()) throw new Exception("守护连接超时，受保护程序已结束。");Thread.Sleep(200);}break;
                    }
                    if(protectChildren && item.code==5 && !HasProcesses(job)) break;
                }
            } catch {
                if(protectChildren) {Win32.TerminateJobObject(job,1);foreach(uint pid in debugged) Win32.DebugActiveProcessStop(pid);}
                throw;
            }
        }
    }
}
