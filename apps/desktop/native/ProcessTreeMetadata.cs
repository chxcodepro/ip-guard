using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace IpGuard {
    internal static class ProcessTreeMetadata {
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandle(SafeFileHandle file,StringBuilder path,uint length,uint flags);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr process,uint flags,StringBuilder path,ref uint length);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadProcessMemory(IntPtr process,IntPtr address,byte[] buffer,UIntPtr length,out UIntPtr read);
        [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr process,int type,IntPtr data,uint length,out uint returned);
        [DllImport("ntdll.dll")] static extern int NtSetInformationProcess(IntPtr process,int type,ref uint value,uint length);
        public static string CanonicalPath(string path) {
            using(FileStream file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete)) {
                var buffer=new StringBuilder(4096);uint length=GetFinalPathNameByHandle(file.SafeFileHandle,buffer,(uint)buffer.Capacity,0);
                if(length==0 || length>=buffer.Capacity) throw new IOException("无法解析程序真实路径。");
                string value=buffer.ToString();if(value.StartsWith(@"\\?\",StringComparison.Ordinal)) value=value.Substring(4);
                return ProcessNetwork.OwnedDriverRegistration.LocalPath(value);
            }
        }
        public static void EnableChildren(IntPtr process) {uint flags=0;if(NtSetInformationProcess(process,31,ref flags,4)<0) throw new Exception("无法建立子进程启动门禁，启动已阻断。");}
        public static void PrepareRoot(uint pid) {
            IntPtr process=Win32.OpenProcess(0x1610,false,pid);if(process==IntPtr.Zero) throw new Exception("无法核验根进程启动信息。");
            try {EnableChildren(process);Require(process);} finally {Win32.CloseHandle(process);}
        }
        static byte[] Read(IntPtr process,long address,int length) {
            byte[] bytes=new byte[length];UIntPtr read;
            if(address==0 || !ReadProcessMemory(process,new IntPtr(address),bytes,(UIntPtr)length,out read) || read.ToUInt64()!=(ulong)length) throw new Exception("子进程启动信息不可核验，已阻断。");return bytes;
        }
        public static void Require(IntPtr process) {
            uint length=4096;var image=new StringBuilder((int)length);
            Win32.Check(QueryFullProcessImageName(process,0,image,ref length),"无法核验子进程映像");
            using(var file=new FileStream(image.ToString(),FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete)) using(var reader=new BinaryReader(file)) {
                if(file.Length<64 || reader.ReadUInt16()!=0x5a4d) throw new Exception("子进程映像不受支持，已阻断。");
                file.Position=60;int pe=reader.ReadInt32();if(pe<0 || pe>file.Length-94) throw new Exception("子进程映像信息无效。");
                file.Position=pe+24;ushort magic=reader.ReadUInt16();file.Position=pe+24+68;ushort subsystem=reader.ReadUInt16();
                if((magic!=0x20b && magic!=0x10b) || (subsystem!=2 && subsystem!=3)) throw new Exception("此子进程类型不支持本机出口保护，已阻断。");
            }
            IntPtr info=Marshal.AllocHGlobal(48);
            try {
                uint returned;long peb;bool wow=false;
                if(NtQueryInformationProcess(process,26,info,(uint)IntPtr.Size,out returned)>=0 && Marshal.ReadIntPtr(info)!=IntPtr.Zero) {peb=Marshal.ReadIntPtr(info).ToInt64();wow=true;}
                else {if(NtQueryInformationProcess(process,0,info,48,out returned)<0) throw new Exception("子进程运行环境无法核验。");peb=Marshal.ReadIntPtr(info,8).ToInt64();}
                byte[] pointer=Read(process,peb+(wow ? 0x10 : 0x20),wow ? 4 : 8);
                long parameters=wow ? BitConverter.ToUInt32(pointer,0) : BitConverter.ToInt64(pointer,0);
                // Inspect only the command-line descriptor, never the argument or chat contents.
                byte[] descriptor=Read(process,parameters+(wow ? 0x40 : 0x70),wow ? 8 : 16);
                if(BitConverter.ToUInt16(descriptor,0)==0 || (wow ? BitConverter.ToUInt32(descriptor,4)==0 : BitConverter.ToInt64(descriptor,8)==0)) throw new Exception("子进程缺少可核验的启动元数据，已在运行前阻断。");
            } finally {Marshal.FreeHGlobal(info);}
        }
    }
}
