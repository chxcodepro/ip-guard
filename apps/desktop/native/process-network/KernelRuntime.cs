using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32;

namespace IpGuard.ProcessNetwork {
    internal sealed class KernelRuntime : IDisposable {
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int type,IntPtr info,uint length,IntPtr returned);
        readonly string token=Guid.NewGuid().ToString("D");
        readonly OwnedDriverRegistration registration;
        Timer heartbeat;
        public string Error="";
        static string Journal {get {return Path.Combine(OwnedDriverRegistration.Home,"sessions.json");}}
        static RegistryKey Open(bool write) {
            using(RegistryKey machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64)) {
                RegistryKey key=machine.OpenSubKey(OwnedDriverRegistration.Marker,write);
                if(key==null) throw new InvalidOperationException("驱动所有权记录缺失。");return key;
            }
        }
        public KernelRuntime(OwnedDriverRegistration registration) {
            this.registration=registration;
            using(Mutex operation=OwnedDriverRegistration.OperationMutex()) {
            bool held;try {held=operation.WaitOne(0);} catch(AbandonedMutexException) {held=true;}
            if(!held) throw new InvalidOperationException("驱动恢复正在进行。");
            try {using(RegistryKey key=Open(true)) {
                if(IsActive(key) && OwnerAlive(key) && Fresh(key)) throw new InvalidOperationException("命令防护已由其他守护实例控制。");
                StopJobs(registration);StopOwner(key);
                WriteJobs(new string[0]);
                using(Process current=Process.GetCurrentProcess()) {
                    key.SetValue("RuntimeActive",0);key.SetValue("RuntimePid",current.Id);
                    key.SetValue("RuntimeStart",current.StartTime.ToFileTimeUtc(),RegistryValueKind.QWord);
                    key.SetValue("RuntimeExe",SystemPolicy.Exe);key.SetValue("RuntimeBoot",BootIdentity.Read().ToString("D"));
                    key.SetValue("RuntimeToken",token);key.SetValue("RuntimeHeartbeat",DateTime.UtcNow.Ticks,RegistryValueKind.QWord);
                    key.SetValue("RuntimeActive",1);key.Flush();
                }
            }} finally {operation.ReleaseMutex();}
            }
        }
        public void Ready() {heartbeat=new Timer(_=>Tick(),null,0,2000);}
        void Tick() {
            try {using(RegistryKey key=Open(true)) {
                if((key.GetValue("RuntimeToken") as string)!=token) throw new InvalidOperationException("命令防护所有权已撤销。");
                if((int)key.GetValue("RecoveryPending",0)!=0) throw new InvalidOperationException("命令防护已进入恢复。");
                key.SetValue("RuntimeHeartbeat",DateTime.UtcNow.Ticks,RegistryValueKind.QWord);
            }} catch(Exception error) {Error=error.GetBaseException().Message;}
        }
        public void WriteJobs(string[] names) {
            foreach(string name in names) ValidateJob(registration,name);
            string temp=Journal+".tmp";File.WriteAllText(temp,Data.Json().Serialize(names));
            if(File.Exists(Journal)) File.Replace(temp,Journal,null);else File.Move(temp,Journal);
        }
        static void ValidateJob(OwnedDriverRegistration registration,string name) {
            string prefix=@"Global\IPGuard-"+registration.OwnerSid+"-";Guid id;
            if(name==null || !name.StartsWith(prefix,StringComparison.Ordinal) || !Guid.TryParseExact(name.Substring(prefix.Length),"D",out id)) throw new InvalidDataException("受控进程树记录无效，保留网络封锁。");
        }
        internal static void StopJobs(OwnedDriverRegistration registration) {
            if(!File.Exists(Journal)) return;
            string source=File.ReadAllText(Journal);
            if(source.Length>65536) throw new InvalidDataException("进程树记录过大。");
            string[] names=Data.Json().Deserialize<string[]>(source);
            if(names==null) throw new InvalidDataException("进程树记录损坏。");
            foreach(string name in names) ValidateJob(registration,name);
            foreach(string name in names) {
                IntPtr job=Win32.OpenJobObject(0x0c,false,name);
                if(job==IntPtr.Zero) {if(System.Runtime.InteropServices.Marshal.GetLastWin32Error()==2) continue;throw new IOException("无法访问自有进程树，保留封锁。");}
                try {
                    Win32.Check(Win32.TerminateJobObject(job,1),"自有进程树停止失败");
                    IntPtr info=Marshal.AllocHGlobal(48);
                    try {
                        bool empty=false;
                        for(int i=0;i<50;i++) {Win32.Check(QueryInformationJobObject(job,1,info,48,IntPtr.Zero));if(Marshal.ReadInt32(info,40)==0) {empty=true;break;}Thread.Sleep(100);}
                        if(!empty) throw new TimeoutException("受控进程树仍未退出，保留网络封锁。");
                    } finally {Marshal.FreeHGlobal(info);}
                }
                finally {Win32.CloseHandle(job);}
            }
        }
        static bool IsActive(RegistryKey key) {return (int)key.GetValue("RuntimeActive",0)==1;}
        static bool Fresh(RegistryKey key) {
            object value=key.GetValue("RuntimeHeartbeat");
            return value is long && DateTime.UtcNow.Ticks-(long)value>=0 && DateTime.UtcNow.Ticks-(long)value<TimeSpan.FromSeconds(30).Ticks;
        }
        static Process Owner(RegistryKey key) {
            object pid=key.GetValue("RuntimePid"),start=key.GetValue("RuntimeStart");string exe=key.GetValue("RuntimeExe") as string;
            if(!(pid is int) || !(start is long) || exe==null) return null;
            Process process=null;
            try {process=Process.GetProcessById((int)pid);
                if(process.StartTime.ToFileTimeUtc()==(long)start && String.Equals(process.MainModule.FileName,exe,StringComparison.OrdinalIgnoreCase)) return process;
            } catch(ArgumentException) {} catch(InvalidOperationException) {} catch(System.ComponentModel.Win32Exception) {}
            if(process!=null) process.Dispose();return null;
        }
        static bool OwnerAlive(RegistryKey key) {using(Process owner=Owner(key)) return owner!=null;}
        static void StopOwner(RegistryKey key) {
            if(!IsActive(key)) return;
            using(Process owner=Owner(key)) if(owner!=null) {
                if(owner.Id==Process.GetCurrentProcess().Id) return;
                owner.Kill();if(!owner.WaitForExit(5000)) throw new TimeoutException("旧守护尚未退出。");
            }
        }
        static bool NeedsRescue() {
            using(RegistryKey key=Open(false)) {
                if((int)key.GetValue("RecoveryPending",0)!=0) return true;
                return IsActive(key) && (!OwnerAlive(key) || !Fresh(key) || (key.GetValue("RuntimeBoot") as string)!=BootIdentity.Read().ToString("D"));
            }
        }
        public static void Rescue(OwnedDriverRegistration registration,bool automatic=false) {
            Guid recovery;
            using(Mutex operation=OwnedDriverRegistration.OperationMutex()) {
                bool held;try {held=operation.WaitOne(0);} catch(AbandonedMutexException) {held=true;}
                if(!held) throw new InvalidOperationException("另一恢复操作正在进行。");
                try {
                    // Recheck under the same mutex as lease acquisition; an earlier timeout may already be obsolete.
                    if(automatic && !NeedsRescue()) return;
                    using(RegistryKey key=Open(true)) {StopJobs(registration);StopOwner(key);key.SetValue("RuntimeActive",0);key.Flush();}
                    recovery=registration.PrepareRecovery();
                }
                finally {operation.ReleaseMutex();}
            }
            registration.StopService();
            using(Mutex operation=OwnedDriverRegistration.OperationMutex()) {
                bool held;try {held=operation.WaitOne(0);} catch(AbandonedMutexException) {held=true;}
                if(!held) throw new InvalidOperationException("另一恢复操作正在进行，保留封锁。");
                try {registration.ValidateStopped();FortProvider.RemoveOwnedObjects(registration);File.WriteAllText(Journal,"[]");registration.CompleteRecovery(recovery);}
                finally {operation.ReleaseMutex();}
            }
        }
        public void Dispose() {
            if(heartbeat!=null) heartbeat.Dispose();
            using(RegistryKey key=Open(true)) if((key.GetValue("RuntimeToken") as string)==token) {key.SetValue("RuntimeActive",0);key.Flush();}
        }
        public void Abandon() {if(heartbeat!=null) heartbeat.Dispose();}
    }
    internal static class KernelWatchdog {
        public static void Remove(OwnedDriverRegistration registration) {
            dynamic service=Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service",true));service.Connect();
            try {service.GetFolder(@"\").DeleteTask("IPGuard.CommandProtection."+registration.OwnerSid,0);}
            catch(System.Runtime.InteropServices.COMException error) {if((uint)error.HResult!=0x80070002) throw;}
        }
        public static void Prepare(OwnedDriverRegistration registration) {
            SystemPolicy.RequireAdmin();
            string recovery=Path.Combine(OwnedDriverRegistration.Home,"recovery","IpGuard.Recovery.exe");
            if(!File.Exists(recovery)) throw new FileNotFoundException("独立恢复组件缺失。",recovery);
            dynamic service=Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service",true));service.Connect();
            dynamic folder=service.GetFolder(@"\"),task=service.NewTask(0);
            task.RegistrationInfo.Description="IP Guard command protection automatic recovery";
            task.Principal.UserId="SYSTEM";task.Principal.LogonType=5;task.Principal.RunLevel=1;
            task.Settings.Enabled=true;task.Settings.Hidden=true;task.Settings.StartWhenAvailable=true;task.Settings.DisallowStartIfOnBatteries=false;task.Settings.StopIfGoingOnBatteries=false;task.Settings.ExecutionTimeLimit="PT2M";
            task.Triggers.Create(8);
            dynamic timed=task.Triggers.Create(1);timed.StartBoundary=DateTime.Now.AddSeconds(40).ToString("s",CultureInfo.InvariantCulture);timed.Repetition.Interval="PT1M";
            dynamic action=task.Actions.Create(0);action.Path=recovery;action.Arguments="--automatic";action.WorkingDirectory=Path.GetDirectoryName(recovery);
            dynamic registered=folder.RegisterTaskDefinition("IPGuard.CommandProtection."+registration.OwnerSid,task,6,"SYSTEM",null,5,null);
            dynamic definition=registered.Definition;
            if(!(bool)registered.Enabled || definition.Actions.Count!=1 || !String.Equals((string)definition.Actions.Item(1).Path,recovery,StringComparison.OrdinalIgnoreCase) || (string)definition.Actions.Item(1).Arguments!="--automatic")
                throw new InvalidOperationException("独立恢复任务未就绪，保持驱动关闭。");
        }
    }
}
