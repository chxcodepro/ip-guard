using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Xml;
using Microsoft.Win32;

namespace IpGuard {
    public sealed class PackageUnavailableException : Exception {
        public PackageUnavailableException() : base("此安装包未注册或路径已更新，请更新程序路径。") { }
    }
    public sealed class PackageIdentity {
        public string fullName, appUserModelId;
    }
    [ComImport, Guid("F27C3930-8029-4AD1-94E3-3DBA417810C1"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IPackageDebugSettings {
        [PreserveSig] int EnableDebugging([MarshalAs(UnmanagedType.LPWStr)] string package, [MarshalAs(UnmanagedType.LPWStr)] string command, IntPtr environment);
        [PreserveSig] int DisableDebugging([MarshalAs(UnmanagedType.LPWStr)] string package);
    }
    [ComImport, Guid("2E941141-7F97-4756-BA1D-9DECDE894A3D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IApplicationActivationManager {
        [PreserveSig] int ActivateApplication([MarshalAs(UnmanagedType.LPWStr)] string appUserModelId, [MarshalAs(UnmanagedType.LPWStr)] string arguments, uint options, out uint pid);
    }
    public static class PackagePolicy {
        public static bool IsClaudeDesktop(string exe) {
            if(!String.Equals(Path.GetFileName(exe),"Claude.exe",StringComparison.OrdinalIgnoreCase)) return false;
            DirectoryInfo directory=new FileInfo(exe).Directory;
            while(directory!=null) {
                string[] parts=directory.Name.Split('_');Version version;
                if(parts.Length==5 && Version.TryParse(parts[1],out version) && version.Build>=0 && version.Revision>=0 && BuildInfo.ClaudeDesktopFamilies.Any(family=>String.Equals(family,parts[0]+"_"+parts[4],StringComparison.OrdinalIgnoreCase))) return true;
                directory=directory.Parent;
            }
            return false;
        }
        const string Owned = @"Software\IPGuard\PackageDebugging";
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern int GetPackagePathByFullName(string package, ref uint length, StringBuilder path);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern int GetPackagesByPackageFamily(string family,ref uint count,IntPtr names,ref uint length,IntPtr buffer);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern int GetPackageFullName(IntPtr process, ref uint length, StringBuilder name);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
        static IPackageDebugSettings Debugger() { return (IPackageDebugSettings)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("B1AEC16F-2383-4852-B0E9-8F0B1DC66B4D"), true)); }
        static bool Registered(string fullName) {
            string[] parts=fullName.Split('_');
            if(parts.Length!=5) throw new Exception("安装包身份无效。");
            uint count=0,length=0;
            int result=GetPackagesByPackageFamily(parts[0]+"_"+parts[4],ref count,IntPtr.Zero,ref length,IntPtr.Zero);
            if(result!=0 && result!=122) throw new Win32Exception(result);
            if(count==0) return false;
            IntPtr names=IntPtr.Zero,buffer=IntPtr.Zero;
            try {
                names=Marshal.AllocHGlobal(checked((int)count*IntPtr.Size));buffer=Marshal.AllocHGlobal(checked((int)length*2));
                result=GetPackagesByPackageFamily(parts[0]+"_"+parts[4],ref count,names,ref length,buffer);
                if(result!=0) throw new Win32Exception(result);
                for(int i=0;i<count;i++) if(String.Equals(Marshal.PtrToStringUni(Marshal.ReadIntPtr(names,i*IntPtr.Size)),fullName,StringComparison.OrdinalIgnoreCase)) return true;
                return false;
            } finally {if(names!=IntPtr.Zero) Marshal.FreeHGlobal(names);if(buffer!=IntPtr.Zero) Marshal.FreeHGlobal(buffer);}
        }
        static string PackagePath(string name) {
            uint length=0; int result=GetPackagePathByFullName(name, ref length, null);
            if(result==15700 || result==2 || result==1168) return null;
            if(result!=122) throw new Win32Exception(result);
            StringBuilder value=new StringBuilder((int)length);
            result=GetPackagePathByFullName(name, ref length, value);
            if(result!=0) throw new Win32Exception(result); return value.ToString();
        }
        public static PackageIdentity Find(string exe) {
            DirectoryInfo directory=new FileInfo(exe).Directory;
            while(directory!=null) {
                string manifest=Path.Combine(directory.FullName,"AppxManifest.xml");
                if(File.Exists(manifest)) {
                    string[] parts=directory.Name.Split('_'); Version version;
                    if(parts.Length!=5 || !Version.TryParse(parts[1],out version) || version.Build<0 || version.Revision<0) return null;
                    if(!Registered(directory.Name)) throw new PackageUnavailableException();
                    string registered=PackagePath(directory.Name);
                    if(registered==null || !String.Equals(Path.GetFullPath(registered),directory.FullName,StringComparison.OrdinalIgnoreCase)) throw new PackageUnavailableException();
                    XmlDocument xml=new XmlDocument { XmlResolver=null };
                    using(XmlReader reader=XmlReader.Create(manifest,new XmlReaderSettings { DtdProcessing=DtdProcessing.Prohibit, XmlResolver=null })) xml.Load(reader);
                    foreach(XmlNode node in xml.GetElementsByTagName("Application")) {
                        XmlAttribute executable=node.Attributes["Executable"], id=node.Attributes["Id"];
                        if(executable==null || id==null) continue;
                        string candidate=Path.GetFullPath(Path.Combine(directory.FullName,executable.Value));
                        if(String.Equals(candidate,exe,StringComparison.OrdinalIgnoreCase))
                            return new PackageIdentity { fullName=directory.Name, appUserModelId=parts[0]+"_"+parts[4]+"!"+id.Value };
                    }
                    throw new Exception("未在安装包清单中找到此程序入口。");
                }
                directory=directory.Parent;
            }
            return null;
        }
        static string DebugPath(string name) {
            using(RegistryKey current=Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\PackagedAppXDebug\"+name)) {
                string value=current==null ? null : current.GetValue("") as string;
                if(!String.IsNullOrEmpty(value)) return value;
            }
            string key=@"Software\Classes\ActivatableClasses\Package\"+name+@"\DebugInformation";
            using(RegistryKey user=Registry.CurrentUser.OpenSubKey(key)) {
                string value=user==null ? null : user.GetValue("DebugPath") as string;
                if(!String.IsNullOrEmpty(value)) return value;
            }
            using(RegistryKey machine=Registry.LocalMachine.OpenSubKey(key)) return machine==null ? null : machine.GetValue("DebugPath") as string;
        }
        public static void Enable(Target target, PackageIdentity package) {
            string command=Data.Quote(SystemPolicy.Exe)+" package-gate "+target.id;
            if(command.Length>210) throw new Exception("IP Guard 安装路径过长，请安装到较短路径后启用 Desktop 防护。");
            string prior=DebugPath(package.fullName);
            if(!String.IsNullOrEmpty(prior)) throw new Exception("此安装包已有调试启动配置，请先解除现有配置。");
            using(RegistryKey marker=Registry.CurrentUser.CreateSubKey(Owned+"\\"+target.id)) {
                marker.SetValue("Owner",SystemPolicy.Owner); marker.SetValue("Package",package.fullName); marker.SetValue("Command",command);
            }
            IPackageDebugSettings settings=Debugger();
            try { Marshal.ThrowExceptionForHR(settings.EnableDebugging(package.fullName,command,IntPtr.Zero)); }
            catch { Registry.CurrentUser.DeleteSubKeyTree(Owned+"\\"+target.id,false); throw; }
            finally { Marshal.ReleaseComObject(settings); }
        }
        public static void Disable(string id) {
            string package, command;
            using(RegistryKey marker=Registry.CurrentUser.OpenSubKey(Owned+"\\"+id)) {
                if(marker==null) return;
                if(marker.GetValue("Owner") as string!=SystemPolicy.Owner) throw new Exception("安装包防护配置所有者已改变。");
                package=marker.GetValue("Package") as string; command=marker.GetValue("Command") as string;
            }
            if(String.IsNullOrEmpty(package) || String.IsNullOrEmpty(command)) throw new Exception("安装包防护记录损坏，请检查恢复日志。");
            string current=DebugPath(package);
            if(!String.IsNullOrEmpty(current) && !String.Equals(current,command,StringComparison.Ordinal)) throw new Exception("安装包调试入口已被其他工具修改，保留现有设置。");
            if(Registered(package)) {
                IPackageDebugSettings settings=Debugger();
                try { Marshal.ThrowExceptionForHR(settings.DisableDebugging(package)); }
                finally { Marshal.ReleaseComObject(settings); }
            } else {
                foreach(var entry in new[] {
                    new {root=Registry.CurrentUser,path=@"Software\Microsoft\Windows\CurrentVersion\PackagedAppXDebug\"+package,value=""},
                    new {root=Registry.CurrentUser,path=@"Software\Classes\ActivatableClasses\Package\"+package+@"\DebugInformation",value="DebugPath"},
                    new {root=Registry.LocalMachine,path=@"Software\Classes\ActivatableClasses\Package\"+package+@"\DebugInformation",value="DebugPath"}
                }) {
                    using(RegistryKey prior=entry.root.OpenSubKey(entry.path)) {
                        if(prior==null || !String.Equals(prior.GetValue(entry.value) as string,command,StringComparison.Ordinal)) continue;
                    }
                    using(RegistryKey key=entry.root.OpenSubKey(entry.path,true)) {
                        if(key!=null && String.Equals(key.GetValue(entry.value) as string,command,StringComparison.Ordinal)) key.DeleteValue(entry.value,false);
                    }
                }
            }
            Registry.CurrentUser.DeleteSubKeyTree(Owned+"\\"+id,false);
        }
        public static void Recover() {
            string[] ids;
            using(RegistryKey root=Registry.CurrentUser.OpenSubKey(Owned)) ids=root==null ? new string[0] : root.GetSubKeyNames();
            foreach(string id in ids) Disable(id);
        }
        public static void Activate(Target target) {
            PackageIdentity package=Find(target.path);
            if(package==null) throw new Exception("安装包入口已变更，请重新选择 Desktop 路径。");
            IApplicationActivationManager manager=(IApplicationActivationManager)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("45BA127D-10A8-46EA-8AB7-56EA9078943C"),true));
            try { uint pid; Marshal.ThrowExceptionForHR(manager.ActivateApplication(package.appUserModelId,target.arguments,2,out pid)); }
            finally { Marshal.ReleaseComObject(manager); }
        }
        public static Win32.ProcessInfo OpenTarget(Target target, uint pid, uint tid) {
            PackageIdentity package=Find(target.path);
            if(package==null) throw new Exception("启动请求缺少有效的安装包身份。");
            IntPtr process=Win32.OpenProcess(0x101101,false,pid), thread=IntPtr.Zero; bool valid=false;
            if(process==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                uint length=0; int result=GetPackageFullName(process,ref length,null);
                if(result!=122) throw new Exception("目标进程没有有效的安装包身份。");
                StringBuilder name=new StringBuilder((int)length);
                if(GetPackageFullName(process,ref length,name)!=0 || name.ToString()!=package.fullName) throw new Exception("目标进程安装包身份不匹配。");
                IntPtr token;
                Win32.Check(OpenProcessToken(process,8,out token));
                try { using(WindowsIdentity identity=new WindowsIdentity(token)) if(identity.User.Value!=SystemPolicy.Sid) throw new Exception("目标进程属于其他用户。"); }
                finally { Win32.CloseHandle(token); }
                using(Process other=Process.GetProcessById((int)pid)) using(Process current=Process.GetCurrentProcess())
                    if(other.SessionId!=current.SessionId) throw new Exception("目标进程不在当前 Windows 会话中。");
                valid=true;
                thread=Win32.OpenThread(0x802,false,tid);
                if(thread==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                if(Win32.GetProcessIdOfThread(thread)!=pid) throw new Exception("目标线程身份不匹配。");
                return new Win32.ProcessInfo { process=process, thread=thread, pid=pid, tid=tid };
            } catch {
                if(valid) Win32.TerminateProcess(process,1);
                if(thread!=IntPtr.Zero) Win32.CloseHandle(thread); Win32.CloseHandle(process); throw;
            }
        }
    }
}
