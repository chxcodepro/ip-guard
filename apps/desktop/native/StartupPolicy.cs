using System;
using System.IO;
using System.Security.Principal;

namespace IpGuard {
    public sealed class StartupStatus {
        public bool enabled;
        public string state="unknown",message="等待检查启动项";
    }
    public static class StartupPolicy {
        static readonly object sync=new object();
        static StartupStatus cached;
        static DateTime expires;
        static string cachedExe;
        static bool cachedRequest;
        static dynamic Scheduler() {dynamic service=Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service",true));service.Connect();return service;}
        internal static bool MissingTask(Exception error) {return unchecked((uint)error.HResult)==0x80070002;}
        static bool SameUser(string value) {
            if(String.IsNullOrEmpty(value)) return false;
            string sid=value.StartsWith("S-1-",StringComparison.Ordinal) ? new SecurityIdentifier(value).Value : ((SecurityIdentifier)new NTAccount(value).Translate(typeof(SecurityIdentifier))).Value;
            return sid==SystemPolicy.Sid;
        }
        internal static StartupStatus Assess(bool requested,bool exists,bool enabled,bool valid,uint result,bool running) {
            if(!exists || !enabled) return requested ? new StartupStatus {state="error",message="启动项未生效，请重新开启。"} : new StartupStatus {state="off",message="未开启"};
            if(!valid) return new StartupStatus {state="error",message="启动路径或登录触发条件已变化，请重新设置。"};
            if(running) return new StartupStatus {enabled=true,state="running",message="已开启 · 后台正在运行"};
            if(result==0x41303) return new StartupStatus {enabled=true,state="waiting",message="已开启 · 等待下次登录"};
            if(result==0) return new StartupStatus {enabled=true,state="ready",message="已开启 · 登录后进入托盘"};
            return new StartupStatus {enabled=true,state="error",message="上次启动未完成（0x"+result.ToString("X8")+"），可重新设置。"};
        }
        public static StartupStatus Read(bool requested,string executable) {
            lock(sync) {
                if(cached!=null && cachedRequest==requested && cachedExe==executable && DateTime.UtcNow<expires) return cached;
                try {
                    dynamic folder=Scheduler().GetFolder(@"\"),task=null;
                    try {task=folder.GetTask(SystemPolicy.Owner);} catch(Exception error) {if(!MissingTask(error)) throw;}
                    if(task==null) cached=Assess(requested,false,false,false,0,false);
                    else {
                        dynamic definition=task.Definition;
                        bool triggerValid=false;
                        foreach(dynamic trigger in definition.Triggers) if((int)trigger.Type==9 && (bool)trigger.Enabled && SameUser((string)trigger.UserId)) triggerValid=true;
                        bool valid=File.Exists(executable) && definition.Actions.Count==1 && SameUser((string)definition.Principal.UserId) && (int)definition.Principal.LogonType==3 && (int)definition.Principal.RunLevel==1 && triggerValid;
                        if(valid) {
                            dynamic action=definition.Actions.Item(1);
                            valid=String.Equals(Path.GetFullPath((string)action.Path),Path.GetFullPath(executable),StringComparison.OrdinalIgnoreCase) &&
                                (string)action.Arguments=="--background" && String.Equals((string)action.WorkingDirectory,Path.GetDirectoryName(executable),StringComparison.OrdinalIgnoreCase);
                        }
                        cached=Assess(requested,true,(bool)task.Enabled,valid,unchecked((uint)(int)task.LastTaskResult),(int)task.State==4);
                    }
                } catch(Exception error) {cached=new StartupStatus {message="启动状态读取失败："+error.Message};}
                cachedExe=executable;cachedRequest=requested;expires=DateTime.UtcNow.AddSeconds(5);return cached;
            }
        }
        public static void Configure(bool enabled,string executable) {
            SystemPolicy.RequireAdmin();
            lock(sync) {
                dynamic service=Scheduler(),folder=service.GetFolder(@"\");
                if(!enabled) {
                    try {folder.DeleteTask(SystemPolicy.Owner,0);} catch(Exception error) {if(!MissingTask(error)) throw;}
                    cached=null;return;
                }
                if(String.IsNullOrEmpty(executable) || !Path.IsPathRooted(executable) || !File.Exists(executable) || !String.Equals(Path.GetExtension(executable),".exe",StringComparison.OrdinalIgnoreCase)) throw new Exception("开机启动需要已安装的桌面程序。");
                dynamic task=service.NewTask(0);task.RegistrationInfo.Description="IP Guard";
                task.Principal.UserId=SystemPolicy.Sid;task.Principal.LogonType=3;task.Principal.RunLevel=1;
                task.Settings.Enabled=true;task.Settings.StartWhenAvailable=true;
                task.Settings.DisallowStartIfOnBatteries=false;task.Settings.StopIfGoingOnBatteries=false;
                task.Settings.ExecutionTimeLimit="PT0S";task.Settings.MultipleInstances=2;
                dynamic trigger=task.Triggers.Create(9);trigger.UserId=SystemPolicy.Sid;trigger.Enabled=true;
                dynamic action=task.Actions.Create(0);action.Path=Path.GetFullPath(executable);action.Arguments="--background";action.WorkingDirectory=Path.GetDirectoryName(executable);
                folder.RegisterTaskDefinition(SystemPolicy.Owner,task,6,SystemPolicy.Sid,null,3,null);
                cached=null;
                var proof=Read(true,executable);if(!proof.enabled) throw new InvalidOperationException(proof.message);
            }
        }
    }
}
