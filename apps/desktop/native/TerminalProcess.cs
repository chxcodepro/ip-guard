using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace IpGuard {
    public static class TerminalProgram {
        [MTAThread] public static int Main(string[] args) {
            TerminalProcess.Attach();
            return Program.Main(args);
        }
    }
    public sealed class TerminalProcess : IDisposable {
        [StructLayout(LayoutKind.Sequential)] struct StartupEx { public Win32.StartupInfo startup; public IntPtr attributes; }
        delegate bool ControlHandler(uint signal);
        static volatile Action cancelStartup;
        static volatile bool started;
        static readonly ControlHandler control=signal=>{
            if(signal!=0 && signal!=1) return false;
            if(!started) { Action cancel=cancelStartup; if(cancel!=null) cancel(); }
            return true;
        };
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool AttachConsole(uint process);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetConsoleCtrlHandler(ControlHandler handler,bool add);
        [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int kind);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool DuplicateHandle(IntPtr sourceProcess,IntPtr source,IntPtr targetProcess,out IntPtr target,uint access,bool inherit,uint options);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,uint flags,ref IntPtr size);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr previous,IntPtr returned);
        [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll",EntryPoint="CreateProcessW",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string app,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr environment,string cwd,ref StartupEx startup,out Win32.ProcessInfo process);
        readonly List<IntPtr> handles=new List<IntPtr>();
        IntPtr attributes,handleArray;
        bool initialized;
        public static void BindCancel(Action cancel) { started=false; cancelStartup=cancel; }
        public static void MarkStarted() { started=true; }
        public static void UnbindCancel() { cancelStartup=null; }
        public static void Attach() { AttachConsole(UInt32.MaxValue); SetConsoleCtrlHandler(control,true); }
        public static bool IsConsole(string file) {
            using(FileStream stream=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete)) using(BinaryReader reader=new BinaryReader(stream)) {
                if(stream.Length<64 || reader.ReadUInt16()!=0x5a4d) return false;
                stream.Position=60; int offset=reader.ReadInt32();
                if(offset<0 || offset>stream.Length-94) return false;
                stream.Position=offset; if(reader.ReadUInt32()!=0x4550) return false;
                stream.Position=offset+24; ushort magic=reader.ReadUInt16(); if(magic!=0x10b && magic!=0x20b) return false;
                stream.Position=offset+24+68; return reader.ReadUInt16()==3;
            }
        }
        IntPtr Copy(int kind) {
            IntPtr original=GetStdHandle(kind);
            if(original==IntPtr.Zero || original==new IntPtr(-1)) return original;
            IntPtr handle; Win32.Check(DuplicateHandle(GetCurrentProcess(),original,GetCurrentProcess(),out handle,0,true,2),"无法继承终端输入输出"); handles.Add(handle); return handle;
        }
        public Win32.ProcessInfo Start(string exe,string command) {
            StartupEx info=new StartupEx(); info.startup.cb=Marshal.SizeOf(info);
            info.startup.flags=0x100; info.startup.stdin=Copy(-10); info.startup.stdout=Copy(-11); info.startup.stderr=Copy(-12);
            if(handles.Count>0) {
                IntPtr size=IntPtr.Zero; InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref size);
                if(size==IntPtr.Zero) throw new IOException("终端句柄列表初始化失败");
                attributes=Marshal.AllocHGlobal(size); Win32.Check(InitializeProcThreadAttributeList(attributes,1,0,ref size));
                initialized=true;
                handleArray=Marshal.AllocHGlobal(IntPtr.Size*handles.Count);
                for(int i=0;i<handles.Count;i++) Marshal.WriteIntPtr(handleArray,i*IntPtr.Size,handles[i]);
                Win32.Check(UpdateProcThreadAttribute(attributes,0,new IntPtr(0x20002),handleArray,new IntPtr(IntPtr.Size*handles.Count),IntPtr.Zero,IntPtr.Zero)); info.attributes=attributes;
            }
            Win32.ProcessInfo process;
            Win32.Check(CreateProcess(exe,new StringBuilder(command),IntPtr.Zero,IntPtr.Zero,handles.Count>0,0x80006,IntPtr.Zero,Environment.CurrentDirectory,ref info,out process),"无法在原终端创建受保护程序");
            return process;
        }
        public void Dispose() {
            if(attributes!=IntPtr.Zero) { if(initialized) DeleteProcThreadAttributeList(attributes); Marshal.FreeHGlobal(attributes); }
            if(handleArray!=IntPtr.Zero) Marshal.FreeHGlobal(handleArray);
            foreach(IntPtr handle in handles) Win32.CloseHandle(handle);
        }
    }
}
