using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace IpGuard.ProcessNetwork {
    internal sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid {
        public ServiceHandle() : base(true) { }
        [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr handle);
        protected override bool ReleaseHandle() {return CloseServiceHandle(handle);}
    }

    internal sealed partial class OwnedDriverRegistration {
        internal const string ServiceName="fortfw";
        internal const string Marker=@"SOFTWARE\IPGuard\ProcessNetwork";
        const string DriverFile="fortfw.sys";
        public readonly string OwnerSid,DriverPath;
        public readonly bool RecoveryPending;
        public readonly Guid RecoveryBootId,RecoveryOperation;

        [StructLayout(LayoutKind.Sequential)] struct ServiceConfig {
            public uint type,start,error;
            public IntPtr binaryPath,group;
            public uint tag;
            public IntPtr dependencies,account,display;
        }
        [StructLayout(LayoutKind.Sequential)] struct ServiceStatus {
            public uint type,state,accepted,error,specific,checkpoint,hint;
        }
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern ServiceHandle OpenSCManager(string machine,string database,uint access);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern ServiceHandle OpenService(ServiceHandle manager,string name,uint access);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryServiceConfig(ServiceHandle service,IntPtr config,uint size,out uint required);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool QueryServiceStatus(ServiceHandle service,out ServiceStatus status);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool ControlService(ServiceHandle service,uint control,out ServiceStatus status);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ChangeServiceConfig(ServiceHandle service,uint type,uint start,uint error,string binaryPath,string group,IntPtr tag,string dependencies,string account,string password,string display);

        internal OwnedDriverRegistration(string ownerSid,string driverPath,bool recoveryPending,Guid bootId,Guid recoveryOperation) {
            var sid=new SecurityIdentifier(ownerSid);
            if(sid.Value!=SystemPolicy.Sid && SystemPolicy.Sid!="S-1-5-18") throw new InvalidDataException("此驱动注册属于其他 Windows 账户。");
            DriverPath=LocalPath(driverPath);
            if(!String.Equals(Path.GetFileName(DriverPath),DriverFile,StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("自有驱动文件名无效。");
            if(recoveryPending && (bootId==Guid.Empty || recoveryOperation==Guid.Empty)) throw new InvalidDataException("恢复记录缺少启动与操作标识，保留封锁。");
            OwnerSid=sid.Value;RecoveryPending=recoveryPending;RecoveryBootId=bootId;RecoveryOperation=recoveryOperation;
        }

        internal static string LocalPath(string value) {
            if(String.IsNullOrEmpty(value) || value.Length>2048 || value.Length<4 || !Char.IsLetter(value[0]) || value[1]!=':' || value[2]!='\\' || value.IndexOf(':',2)>=0 || value.IndexOf('"')>=0)
                throw new InvalidDataException("驱动路径须为本机绝对路径。");
            foreach(char c in value) if(Char.IsControl(c)) throw new InvalidDataException("驱动路径包含无效字符。");
            return Path.GetFullPath(value);
        }

        internal static string ServicePath(string value) {
            if(value==null) throw new InvalidDataException("驱动服务路径缺失。");
            value=Environment.ExpandEnvironmentVariables(value).Trim();
            if(value.StartsWith("\"",StringComparison.Ordinal) && value.EndsWith("\"",StringComparison.Ordinal) && value.Length>1) value=value.Substring(1,value.Length-2);
            if(value.StartsWith(@"\??\",StringComparison.Ordinal)) value=value.Substring(4);
            return LocalPath(value);
        }

        public static OwnedDriverRegistration Read() {
            using(RegistryKey machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))
            using(RegistryKey key=machine.OpenSubKey(Marker)) {
                if(key==null) return null;
                object format=key.GetValue("Format"),pending=key.GetValue("RecoveryPending");
                string owner=key.GetValue("OwnerSid") as string,path=key.GetValue("DriverPath",null,RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                if(!(format is int) || (int)format!=2 || !(pending is int) || ((int)pending!=0 && (int)pending!=1) || owner==null || path==null) throw new InvalidDataException("进程网络驱动所有权记录无效，保留现有服务。");
                Guid bootId,operation;
                Guid.TryParse(key.GetValue("RecoveryBootId") as string,out bootId);Guid.TryParse(key.GetValue("RecoveryOperation") as string,out operation);
                return new OwnedDriverRegistration(owner,path,(int)pending==1,bootId,operation);
            }
        }

        ServiceHandle Open(bool change) {
            using(ServiceHandle manager=OpenSCManager(null,null,1)) {
                if(manager.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(),"无法连接本机服务管理器。");
                ServiceHandle service=OpenService(manager,ServiceName,change ? 7U : 5U);
                if(service.IsInvalid) {int error=Marshal.GetLastWin32Error();service.Dispose();throw new Win32Exception(error,"自有进程网络驱动服务不可用。");}
                return service;
            }
        }

        uint Validate(ServiceHandle service,bool requireRunning,bool requireDisabled=false,bool requireDemandStart=false) {
            uint required;
            bool sized=QueryServiceConfig(service,IntPtr.Zero,0,out required);
            int error=Marshal.GetLastWin32Error();
            if(sized || error!=122 || required<Marshal.SizeOf(typeof(ServiceConfig)) || required>65536) throw new InvalidDataException("驱动服务配置长度无效。");
            IntPtr buffer=Marshal.AllocHGlobal((int)required);
            try {
                Win32.Check(QueryServiceConfig(service,buffer,required,out required),"无法核对驱动服务配置");
                var config=(ServiceConfig)Marshal.PtrToStructure(buffer,typeof(ServiceConfig));
                string image=ServicePath(Marshal.PtrToStringUni(config.binaryPath));
                if(config.type!=1 || !String.Equals(image,DriverPath,StringComparison.OrdinalIgnoreCase) || (config.start!=3 && config.start!=4)) throw new InvalidDataException("服务与 IP Guard 所有权记录不匹配，保留现有服务。");
                if(requireDemandStart && config.start!=3) throw new InvalidOperationException("命令防护驱动已禁用，请手动恢复后重新加载。");
                ServiceStatus status;
                Win32.Check(QueryServiceStatus(service,out status),"无法核对驱动服务状态");
                if(requireRunning && (status.state!=4 || config.start!=3)) throw new InvalidOperationException("自有驱动尚未按需运行。");
                if(requireDisabled && (status.state!=1 || config.start!=4)) throw new InvalidOperationException("自有驱动须先禁用并在重启后停止，保留持久封锁。");
                return status.state;
            } finally {Marshal.FreeHGlobal(buffer);}
        }

        public uint Validate(bool requireRunning) {using(ServiceHandle service=Open(false)) return Validate(service,requireRunning);}
        internal void RequireStartable() {using(ServiceHandle service=Open(false)) Validate(service,false,false,true);}

        public static string FindFortConflict() {
            using(RegistryKey machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))
            using(RegistryKey services=machine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services")) {
                if(services==null) throw new InvalidDataException("本机服务注册表不可用。");
                foreach(string name in services.GetSubKeyNames()) {
                    if(String.Equals(name,ServiceName,StringComparison.OrdinalIgnoreCase)) continue;
                    using(RegistryKey service=services.OpenSubKey(name)) {
                        if(service==null) continue;
                        object type=service.GetValue("Type");
                        if(!(type is int) || ((int)type&1)==0) continue;
                        string image=service.GetValue("ImagePath",null,RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                        if(name.IndexOf("fortfirewall",StringComparison.OrdinalIgnoreCase)>=0 || (image!=null && image.IndexOf("fortfw",StringComparison.OrdinalIgnoreCase)>=0)) return name;
                    }
                }
            }
            return null;
        }

        public void RequireAttachable() {
            if(RecoveryPending) throw new InvalidOperationException("驱动尚待恢复，请在设置中确认恢复后重新加载。");
            string conflict=FindFortConflict();
            if(conflict!=null) throw new InvalidOperationException("检测到其他 Fort 组件，保留其运行状态："+conflict);
            Validate(true);
        }

        Guid SetPending() {
            Guid boot=BootIdentity.Read(),operation=Guid.NewGuid();
            using(RegistryKey machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))
            using(RegistryKey key=machine.OpenSubKey(Marker,true)) {
                var current=Read();
                if(key==null || current==null || current.OwnerSid!=OwnerSid || current.DriverPath!=DriverPath) throw new InvalidOperationException("驱动所有权已变化。");
                key.SetValue("RecoveryBootId",boot.ToString("D"));key.SetValue("RecoveryOperation",operation.ToString("D"));key.Flush();
                key.SetValue("RecoveryPending",1,RegistryValueKind.DWord);key.Flush();
            }
            return operation;
        }
        public Guid PrepareRecovery() {
            using(ServiceHandle service=Open(true)) {
                Validate(service,false);
                Guid operation=SetPending();
                // Preserve the recovery latch if disabling fails; future attachment must stay closed.
                Win32.Check(ChangeServiceConfig(service,UInt32.MaxValue,4,UInt32.MaxValue,null,null,IntPtr.Zero,null,null,null,null),"恢复标记已保留，但自有驱动禁用失败");
                return operation;
            }
        }
        public Guid BeginOrderlyStop() {
            using(Mutex mutex=OperationMutex()) {
                bool held;try {held=mutex.WaitOne(0);} catch(AbandonedMutexException) {held=true;}
                if(!held) throw new InvalidOperationException("驱动恢复正在进行。");
                try {var current=Read();if(current==null || current.RecoveryPending) throw new InvalidOperationException("恢复已准备，保留封锁。");Validate(true);return SetPending();}
                finally {mutex.ReleaseMutex();}
            }
        }
        public void ValidateStopped() {using(ServiceHandle service=Open(false)) if(Validate(service,false)!=1) throw new InvalidOperationException("自有驱动仍在运行，保留持久封锁。");}
        public void StopService() {
            using(ServiceHandle manager=OpenSCManager(null,null,1)) {
                if(manager.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                using(ServiceHandle service=OpenService(manager,ServiceName,0x25)) {
                    if(service.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                    if(Validate(service,false)==1) return;
                    ServiceStatus status;
                    if(!ControlService(service,1,out status)) {
                        int error=Marshal.GetLastWin32Error();
                        Win32.Check(QueryServiceStatus(service,out status),"无法复核驱动停止状态");
                        if(error!=1062 || status.state!=1) throw new Win32Exception(error,"自有 Fort 驱动未停止。");
                    }
                    for(int i=0;i<50;i++) {Win32.Check(QueryServiceStatus(service,out status));if(status.state==1) return;Thread.Sleep(100);}
                    throw new TimeoutException("驱动停止尚未完成，保留持久封锁，请使用独立恢复。");
                }
            }
        }
        public void CompleteRecovery(Guid operation) {
            var current=Read();
            if(current==null || current.OwnerSid!=OwnerSid || current.DriverPath!=DriverPath) throw new InvalidOperationException("驱动所有权已变化。");
            if(!current.RecoveryPending || current.RecoveryOperation!=operation) return;
            using(RegistryKey machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))
            using(RegistryKey key=machine.OpenSubKey(Marker,true)) {if(key==null) throw new InvalidDataException("自有记录缺失。");key.SetValue("RecoveryPending",0,RegistryValueKind.DWord);key.Flush();}
        }
        public static Mutex OperationMutex() {return new Mutex(false,@"Global\IPGuard-CommandProtection-Operation");}
    }
}
