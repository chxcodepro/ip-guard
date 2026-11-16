using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;

namespace IpGuard.ProcessNetwork {
    public sealed class KernelStatus {
        public bool installed,loaded,enabled,ready,supported;
        public string phase="not_installed",error="",version="Fort 3.20.9 / ABI 65";
        public int[] localPorts=new int[0];
    }
    internal sealed class KernelProtection {
        FortDevice device;
        ProcessNetworkController controller;
        ProtectedJobs jobs;
        KernelRuntime runtime;
        readonly Action<bool> setGate;
        readonly HashSet<string> roots=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        volatile string failure="";
        bool supported;
        bool starting;
        int[] activeLocalPorts=new int[0];
        public KernelProtection(Action<bool> setGate) {
            this.setGate=setGate;
            try {FortEnvironment.ReadPlatform().RequirePlatform();supported=true;} catch(Exception error) {failure=error.GetBaseException().Message;}
        }
        public bool Live {get {return failure=="" && (runtime==null || runtime.Error=="") && device!=null && controller!=null && (controller.Phase==ControllerPhase.Ready || controller.Phase==ControllerPhase.Paused);}}
        public KernelStatus Status(bool enabled) {
            var result=new KernelStatus {enabled=enabled,supported=supported,ready=Live,error=failure,localPorts=Live ? activeLocalPorts : new int[0]};
            if(result.error=="" && runtime!=null) result.error=runtime.Error;
            try {var record=OwnedDriverRegistration.Read();if(record!=null) {result.installed=true;result.loaded=record.Validate(false)==4;if(record.RecoveryPending && result.error=="") result.error="驱动需要恢复，请点击恢复后重试。";}}
            catch(Exception error) {result.error=error.GetBaseException().Message;}
            result.ready=Live && result.loaded && result.error=="";
            if(!result.ready) result.localPorts=new int[0];
            result.phase=result.error!="" ? "failed" : starting ? "starting" : result.ready ? "ready" : result.installed ? "disabled" : "not_installed";
            return result;
        }
        public void Install() {OwnedDriverRegistration.Install();failure="";}
        public void Start(EgressPolicy egress,IEnumerable<Target> targets,bool recover=false) {
            starting=true;
            try {
                setGate(false);
                var waiting=Stopwatch.StartNew();
                while(true) {
                    using(Mutex operation=OwnedDriverRegistration.OperationMutex()) {
                        bool held;try {held=operation.WaitOne(10000);} catch(AbandonedMutexException) {held=true;}
                        if(!held) throw new TimeoutException("命令防护恢复尚未完成，请稍后重试。");
                        try {
                            var record=OwnedDriverRegistration.Read();
                            Guid boot=BootIdentity.Read();
                            bool reboot=record!=null && KernelRuntime.IsPreviousBoot(boot);
                            // A recovery process releases this mutex while stopping the service; wait for its completion marker.
                            if(!reboot || !record.RecoveryPending || record.RecoveryBootId!=boot) {
                                StartCore(egress,targets,recover || reboot);return;
                            }
                        } finally {operation.ReleaseMutex();}
                    }
                    if(waiting.ElapsedMilliseconds>=15000) throw new TimeoutException("开机驱动恢复尚未完成，命令防护保持关闭，请稍后重试。");
                    Thread.Sleep(100);
                }
            } finally {starting=false;}
        }
        void StartCore(EgressPolicy egress,IEnumerable<Target> targets,bool recover) {
            if(Live) return;
            FortEnvironment.ReadPlatform().RequirePlatform();
            if(egress==null) throw new Exception("请先启用固定出口。");
            string[] paths=targets.Where(t=>t.enabled).Select(t=>{EgressPolicy.ValidateTarget(t);return ProcessTreeMetadata.CanonicalPath(t.path);}).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var policy=new FortPolicy(egress,paths,SystemPolicy.LocalDevPorts);policy.Configuration();
            var record=OwnedDriverRegistration.Read();if(record==null) throw new Exception("请先安装命令防护驱动。");
            if(record.RecoveryPending) {
                if(!recover) throw new Exception("命令防护已进入恢复，请在设置中确认恢复后重新加载。");
                KernelRuntime.Rescue(record);record=OwnedDriverRegistration.Read();
            }
            if(recover) {record.ResetRecovery();record=OwnedDriverRegistration.Read();}
            record.RequireStartable();
            KernelWatchdog.Prepare(record);
            KernelRuntime acquired=null;
            try {
                acquired=new KernelRuntime(record);runtime=acquired;
                if(record.Validate(false)==4) {record.StopService();FortProvider.RemoveOwnedObjects(record);}
                FortProvider.ArmOwned(record);record.StartOwnedService();device=FortDevice.AttachExisting();
                jobs=new ProtectedJobs(runtime.WriteJobs);
                controller=new ProcessNetworkController(device,policy,jobs,setGate);
                roots.Clear();foreach(string path in paths) roots.Add(path);
                activeLocalPorts=policy.LocalPorts;failure="";runtime.Ready();
            } catch(Exception error) {
                failure=error.Message;
                if(acquired==null) throw;
                runtime.Abandon();
                var errors=new List<Exception> {error};
                try {setGate(false);} catch(Exception gateError) {errors.Add(gateError);}
                if(device!=null) {device.Dispose();device=null;}
                // No protected launch is allowed until Start returns; failed initialization owns no live targets.
                try {
                    KernelRuntime.Rescue(record);
                    if(jobs!=null) jobs.Dispose();
                    runtime.Dispose();runtime=null;jobs=null;controller=null;roots.Clear();
                } catch(Exception recoveryError) {errors.Add(recoveryError);}
                if(errors.Count>1) {
                    failure="命令防护启动失败；同步恢复未完成："+String.Join("；",errors.Select(e=>e.Message));
                    throw new AggregateException(failure,errors);
                }
                failure="命令防护启动失败，已撤销本次网络封锁："+error.Message;
                throw new InvalidOperationException(failure,error);
            }
        }
        public void RequireRoot(string path) {
            string issue=HealthError();if(issue!="") throw new Exception(issue);
            if(!Live) throw new Exception(failure!="" ? failure : "命令进程树防护未就绪。");
            if(!roots.Contains(ProcessTreeMetadata.CanonicalPath(path))) throw new Exception("程序真实路径已变化，请关闭受控程序并重新加载命令防护。");
        }
        public void SetFailure(string error) {failure=error;setGate(false);}
        public void Register(string name,IntPtr job) {if(!Live) throw new Exception("命令防护未就绪。");jobs.Register(name,job);}
        public void Unregister(string name) {if(jobs!=null) jobs.Unregister(name);}
        public void Allow(bool allowed) {if(Live) controller.SetReady(allowed);}
        public void UpdateLocalPorts(EgressPolicy egress,int[] ports) {
            if(!Live) throw new InvalidOperationException("命令防护未就绪，暂无法更新本机端口。");
            var previous=new FortPolicy(egress,roots,activeLocalPorts);
            var next=new FortPolicy(egress,roots,ports);
            try {controller.Replace(previous,next);activeLocalPorts=next.LocalPorts;}
            catch(Exception error) {if(controller.Phase==ControllerPhase.Faulted) SetFailure("本机端口规则恢复失败："+error.GetBaseException().Message);throw;}
        }
        public string HealthError() {
            if(runtime!=null && runtime.Error!="") return runtime.Error;
            if(Live) {try {var record=OwnedDriverRegistration.Read();if(record==null || record.RecoveryPending || record.Validate(false)!=4) return "命令防护驱动已离线。";} catch(Exception error) {return error.GetBaseException().Message;}}
            return failure;
        }
        public void Stop() {
            setGate(false);
            if(controller==null || device==null || controller.Phase==ControllerPhase.Faulted) {
                if(runtime!=null) runtime.Abandon();
                if(device!=null) {device.Dispose();device=null;}
                var record=OwnedDriverRegistration.Read();
                if(record!=null && (runtime!=null || record.Validate(false)==4 || record.RecoveryPending)) {KernelRuntime.Rescue(record);}
                if(jobs!=null) jobs.Dispose();
                if(runtime!=null) runtime.Dispose();runtime=null;jobs=null;controller=null;roots.Clear();failure="";return;
            }
            try {
                if(controller.Phase==ControllerPhase.Ready || controller.Phase==ControllerPhase.Paused) controller.BeginDrain();
                for(int i=0;i<50 && controller.Phase==ControllerPhase.Draining && !controller.CompleteDrain();i++) Thread.Sleep(100);
                if(controller.Phase!=ControllerPhase.Stopped) throw new Exception("受控程序仍未退出，保留命令防护。");
                runtime.Abandon();
                device.ReleaseAfterDrain(controller);jobs.Dispose();runtime.WriteJobs(new string[0]);runtime.Dispose();
                device=null;controller=null;jobs=null;runtime=null;failure="";roots.Clear();
            } catch(Exception error) {failure=error.Message;if(runtime!=null) runtime.Abandon();throw;}
        }
    }
}
