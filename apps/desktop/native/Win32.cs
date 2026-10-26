using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace IpGuard {
    public static class Win32 {
        [StructLayout(LayoutKind.Sequential)] public struct StartupInfo {
            public int cb; public string reserved; public string desktop; public string title;
            public uint x, y, xSize, ySize, xChars, yChars, fill, flags;
            public short showWindow, reserved2; public IntPtr reservedPtr, stdin, stdout, stderr;
        }
        [StructLayout(LayoutKind.Sequential)] public struct ProcessInfo { public IntPtr process, thread; public uint pid, tid; }
        [StructLayout(LayoutKind.Sequential)] public struct BasicLimits {
            public long processTime, jobTime; public uint flags; public UIntPtr min, max;
            public uint active; public UIntPtr affinity; public uint priority, scheduling;
        }
        [StructLayout(LayoutKind.Sequential)] public struct IoCounters { public ulong r, w, o, rb, wb, ob; }
        [StructLayout(LayoutKind.Sequential)] public struct ExtendedLimits {
            public BasicLimits basic; public IoCounters io; public UIntPtr processMemory, jobMemory, peakProcess, peakJob;
        }
        [StructLayout(LayoutKind.Explicit, Size = 160)] public struct DebugInfo {
            [FieldOffset(0)] public IntPtr file;
            [FieldOffset(0)] public uint exception;
        }
        [StructLayout(LayoutKind.Sequential)] public struct DebugEvent { public uint code, pid, tid; public DebugInfo info; }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr CreateJobObject(IntPtr security, string name);
        [StructLayout(LayoutKind.Sequential)] public struct SecurityAttributes { public int length; public IntPtr descriptor; public int inherit; }
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text, uint revision, out IntPtr descriptor, IntPtr size);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr OpenJobObject(uint access, bool inherit, string name);
        [DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetInformationJobObject(IntPtr job, int type, ref ExtendedLimits info, uint length);
        [DllImport("kernel32.dll", SetLastError=true)] public static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
        [DllImport("kernel32.dll", SetLastError=true)] public static extern bool TerminateJobObject(IntPtr job, uint code);
        [DllImport("kernel32.dll", SetLastError=true)] public static extern bool TerminateProcess(IntPtr process, uint code);
        [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError=true)] public static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
        [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenThread(uint access, bool inherit, uint tid);
        [DllImport("kernel32.dll", SetLastError=true)] public static extern uint GetProcessIdOfThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError=true)] public static extern bool DebugActiveProcess(uint pid);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern bool CreateProcess(string app, StringBuilder command, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr environment, string cwd, ref StartupInfo startup, out ProcessInfo info);
        [DllImport("kernel32.dll", SetLastError=true)] public static extern bool WaitForDebugEvent(out DebugEvent debug, uint timeout);
        [DllImport("kernel32.dll", SetLastError=true)] public static extern bool ContinueDebugEvent(uint pid, uint tid, uint status);
        [DllImport("kernel32.dll")] public static extern bool DebugSetProcessKillOnExit(bool kill);
        [DllImport("iphlpapi.dll")] public static extern uint GetIpForwardTable(IntPtr table, ref uint size, bool order);
        [DllImport("iphlpapi.dll")] public static extern uint GetBestInterface(uint destination, out uint index);
        [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int MessageBox(IntPtr hwnd, string text, string title, uint type);
        public static void Check(bool ok, string action = null) {
            if(ok) return;
            int error=Marshal.GetLastWin32Error();
            if(action==null) throw new Win32Exception(error);
            throw new Win32Exception(error,action+" · "+new Win32Exception(error).Message);
        }
        public static IntPtr NewJob(string name) {
            IntPtr descriptor;
            Check(ConvertStringSecurityDescriptorToSecurityDescriptor("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + SystemPolicy.Sid + ")S:(ML;;NW;;;ME)", 1, out descriptor, IntPtr.Zero));
            SecurityAttributes attributes = new SecurityAttributes(); attributes.length = Marshal.SizeOf(attributes); attributes.descriptor = descriptor;
            IntPtr security = Marshal.AllocHGlobal(attributes.length); IntPtr job;
            try { Marshal.StructureToPtr(attributes,security,false); job = CreateJobObject(security,name); }
            finally { Marshal.FreeHGlobal(security); LocalFree(descriptor); }
            if (job == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            ExtendedLimits info = new ExtendedLimits(); info.basic.flags = 0x2000;
            try { Check(SetInformationJobObject(job, 9, ref info, (uint)Marshal.SizeOf(info))); return job; }
            catch { CloseHandle(job); throw; }
        }
    }
}
