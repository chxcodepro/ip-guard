using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace IpGuard.ProcessNetwork {
    internal sealed partial class OwnedDriverRegistration {
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern ServiceHandle CreateService(ServiceHandle manager,string name,string display,uint access,uint type,uint start,uint error,string binary,string group,IntPtr tag,string dependencies,string account,string password);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool StartService(ServiceHandle service,uint count,IntPtr arguments);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool DeleteService(ServiceHandle service);
        internal static readonly string Home=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"IPGuard","CommandProtection");
        internal static string ResourceDriver {get {return Path.GetFullPath(Path.Combine(Path.GetDirectoryName(SystemPolicy.Exe),"../../drivers/fort/fortfw.sys"));}}
        internal static void SecureDirectory(string path) {
            Directory.CreateDirectory(path);
            if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0) throw new IOException("驱动目录包含重解析点，停止操作。");
            var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);
            foreach(var sid in new[] {WellKnownSidType.LocalSystemSid,WellKnownSidType.BuiltinAdministratorsSid})
                acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid,null),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid,null),FileSystemRights.ReadAndExecute,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
            Directory.SetAccessControl(path,acl);
        }
        public static OwnedDriverRegistration Install() {
            SystemPolicy.RequireAdmin();FortEnvironment.ReadPlatform().RequirePlatform();
            var existing=Read();
            if(existing!=null) {existing.Validate(false);return existing;}
            if(FindFortConflict()!=null) throw new InvalidOperationException("已有 Fort 安装，保留现有配置。");
            using(ServiceHandle manager=OpenSCManager(null,null,3)) {
                if(manager.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                using(ServiceHandle check=OpenService(manager,ServiceName,5)) {
                    if(!check.IsInvalid) throw new InvalidOperationException("fortfw 服务已存在且未由 IP Guard 注册，保留现有服务。");
                    if(Marshal.GetLastWin32Error()!=1060) throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                using(FileStream pinned=DriverBinaryTrust.VerifyAndPin(ResourceDriver)) {
                    SecureDirectory(Path.GetDirectoryName(Home));SecureDirectory(Home);SecureDirectory(Path.Combine(Home,"driver"));SecureDirectory(Path.Combine(Home,"recovery"));
                    string driver=Path.Combine(Home,"driver","fortfw.sys");File.Copy(ResourceDriver,driver,true);
                    string recovery=Path.Combine(Path.GetDirectoryName(SystemPolicy.Exe),"IpGuard.Recovery.exe");
                    File.Copy(recovery,Path.Combine(Home,"recovery","IpGuard.Recovery.exe"),true);
                    using(ServiceHandle service=CreateService(manager,ServiceName,"IP Guard Command Protection",7,1,3,1,@"\??\"+driver,null,IntPtr.Zero,null,null,null)) {
                        if(service.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(),"驱动服务注册失败。");
                    }
                    using(RegistryKey machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))
                    using(RegistryKey key=machine.CreateSubKey(Marker)) {
                        var acl=new RegistrySecurity();acl.SetAccessRuleProtection(true,false);
                        foreach(var sid in new[] {WellKnownSidType.LocalSystemSid,WellKnownSidType.BuiltinAdministratorsSid}) acl.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(sid,null),RegistryRights.FullControl,InheritanceFlags.ContainerInherit,PropagationFlags.None,AccessControlType.Allow));
                        acl.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid,null),RegistryRights.ReadKey,InheritanceFlags.ContainerInherit,PropagationFlags.None,AccessControlType.Allow));
                        key.SetAccessControl(acl);key.SetValue("Format",2);key.SetValue("OwnerSid",SystemPolicy.Sid);key.SetValue("DriverPath",driver);key.SetValue("RecoveryPending",0);key.Flush();
                    }
                }
            }
            var record=Read();KernelWatchdog.Prepare(record);return record;
        }
        public void StartOwnedService() {
            FortEnvironment.ReadPlatform().RequirePlatform();
            using(ServiceHandle manager=OpenSCManager(null,null,1))
            using(ServiceHandle service=OpenService(manager,ServiceName,0x15)) {
                if(service.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                uint state=Validate(service,false);
                if(state==4) return;
                if(RecoveryPending) throw new InvalidOperationException("驱动正在恢复，拒绝重新加载。");
                Win32.Check(StartService(service,0,IntPtr.Zero),"驱动加载失败");
                for(int i=0;i<100;i++) {ServiceStatus status;Win32.Check(QueryServiceStatus(service,out status));if(status.state==4) return;System.Threading.Thread.Sleep(100);}
                throw new TimeoutException("驱动加载超时，独立恢复已就绪。");
            }
        }
        internal void ResetRecovery() {
            ValidateStopped();
            using(ServiceHandle service=Open(true)) Win32.Check(ChangeServiceConfig(service,UInt32.MaxValue,3,UInt32.MaxValue,null,null,IntPtr.Zero,null,null,null,null));
            using(RegistryKey machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))
            using(RegistryKey key=machine.OpenSubKey(Marker,true)) {key.SetValue("RecoveryPending",0);key.Flush();}
        }
        public void Uninstall() {
            KernelRuntime.Rescue(this);KernelWatchdog.Remove(this);
            using(ServiceHandle manager=OpenSCManager(null,null,1))
            using(ServiceHandle service=OpenService(manager,ServiceName,0x10005)) {
                if(service.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                Validate(service,false,true);Win32.Check(DeleteService(service),"自有驱动服务移除失败");
            }
            using(RegistryKey machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64)) machine.DeleteSubKeyTree(Marker,false);
        }
    }
}
