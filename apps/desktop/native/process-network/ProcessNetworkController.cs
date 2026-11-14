using System;

namespace IpGuard.ProcessNetwork {
    internal interface IFortDevice {
        FortEnvironment Environment {get;}
        void Send(FortRequest request);
    }
    internal enum ControllerPhase { Paused,Ready,Draining,Faulted,Stopped }
    internal sealed class ProcessNetworkController {
        readonly object sync=new object();
        readonly IProtectedJobs jobs;
        readonly IFortDevice device;
        readonly Action<bool> setGate;
        ControllerPhase phase=ControllerPhase.Paused;
        public ProcessNetworkController(IFortDevice device,FortPolicy policy,IProtectedJobs jobs,Action<bool> setGate) {
            if(device==null || policy==null || jobs==null || setGate==null) throw new ArgumentNullException();
            this.device=device;this.jobs=jobs;this.setGate=setGate;setGate(false);
            try {
                device.Environment.RequireSupported();
                if(jobs.HasActiveProcesses) throw new InvalidOperationException("请先关闭受控程序，再配置进程树防护。");
                FortRequest configuration=policy.Configuration();
                device.Send(FortPolicy.Validation());device.Send(configuration);
            } catch(Exception error) {Fail(error);throw;}
        }
        public ControllerPhase Phase {get {lock(sync) return phase;}}
        void Fail(Exception cause) {
            phase=ControllerPhase.Faulted;
            try {setGate(false);} catch(Exception gateError) {throw new AggregateException("固定通道关闭失败，保留驱动封锁并进入独立恢复。",cause,gateError);}
        }
        public void SetReady(bool ready) {
            lock(sync) {
                if(phase!=ControllerPhase.Paused && phase!=ControllerPhase.Ready) throw new InvalidOperationException("当前状态拒绝恢复联网。");
                try {setGate(ready);phase=ready ? ControllerPhase.Ready : ControllerPhase.Paused;} catch(Exception error) {Fail(error);throw;}
            }
        }
        public void DriverFault(Exception cause) {if(cause==null) throw new ArgumentNullException("cause");lock(sync) {if(phase!=ControllerPhase.Stopped) Fail(cause);}}
        public void BeginDrain() {
            lock(sync) {
                if(phase!=ControllerPhase.Ready && phase!=ControllerPhase.Paused) throw new InvalidOperationException("当前状态须进入独立恢复。");
                try {jobs.Seal();setGate(false);phase=ControllerPhase.Draining;} catch(Exception error) {Fail(error);throw;}
            }
        }
        public bool CompleteDrain() {
            lock(sync) {
                if(phase!=ControllerPhase.Draining) throw new InvalidOperationException("请先停止新启动。");
                try {if(jobs.HasActiveProcesses) return false;phase=ControllerPhase.Stopped;return true;} catch(Exception error) {Fail(error);throw;}
            }
        }
        internal void VerifyDrained(IFortDevice owner) {
            lock(sync) if(!Object.ReferenceEquals(device,owner) || phase!=ControllerPhase.Stopped || jobs.HasActiveProcesses) throw new InvalidOperationException("此设备的受控进程尚未完成排空。");
        }
    }
}
