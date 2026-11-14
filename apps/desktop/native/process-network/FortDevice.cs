using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace IpGuard.ProcessNetwork {
    internal sealed class FortDevice : IFortDevice,IDisposable {
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(SafeFileHandle handle,uint code,byte[] input,uint inputSize,IntPtr output,uint outputSize,out uint returned,IntPtr overlapped);
        readonly SafeFileHandle handle;
        readonly object output=new object();
        readonly FortEnvironment environment;
        readonly OwnedDriverRegistration registration;
        readonly object releaseSync=new object();
        Guid stopOperation;
        bool released;
        bool disposed;
        FortDevice(SafeFileHandle handle,FortEnvironment environment,OwnedDriverRegistration registration) {this.handle=handle;this.environment=environment;this.registration=registration;}
        public FortEnvironment Environment {get {return environment;}}
        static OwnedDriverRegistration Snapshot() {
            using(Mutex operation=OwnedDriverRegistration.OperationMutex()) {
                bool held;try {held=operation.WaitOne(0);} catch(AbandonedMutexException) {held=true;}
                if(!held) throw new InvalidOperationException("驱动所有权正在变更。");
                try {var record=OwnedDriverRegistration.Read();if(record==null) throw new InvalidOperationException("尚未部署自有 Fort 驱动。");record.RequireAttachable();return record;}
                finally {operation.ReleaseMutex();}
            }
        }
        public static FortDevice AttachExisting() {
            SystemPolicy.RequireAdmin();var record=Snapshot();var environment=FortEnvironment.Read();environment.RequireSupported();
            using(FileStream pinned=DriverBinaryTrust.VerifyAndPin(record.DriverPath)) {
                SafeFileHandle handle=CreateFile(@"\\.\fortfw",0xc0000000,0,IntPtr.Zero,3,0x80,IntPtr.Zero);
                if(handle.IsInvalid) {int error=Marshal.GetLastWin32Error();handle.Dispose();throw new Win32Exception(error,"未取得自有 Fort 设备的独占控制。");}
                try {
                    var current=Snapshot();
                    if(current.OwnerSid!=record.OwnerSid || current.DriverPath!=record.DriverPath) throw new InvalidOperationException("接入期间驱动所有权变化。");
                    return new FortDevice(handle,environment,record);
                } catch {handle.Dispose();throw;}
            }
        }
        public void Send(FortRequest request) {
            if(request==null) throw new ArgumentNullException("request");
            lock(output) {
                if(disposed) throw new ObjectDisposedException("FortDevice");
                byte[] data=request.CopyPayload();uint returned;
                Win32.Check(DeviceIoControl(handle,request.Code,data,(uint)data.Length,IntPtr.Zero,0,out returned,IntPtr.Zero),"Fort 驱动配置未确认");
            }
        }
        public void ReleaseAfterDrain(ProcessNetworkController controller) {
            if(controller==null) throw new ArgumentNullException("controller");
            controller.VerifyDrained(this);
            lock(releaseSync) {
                if(released) return;
                var record=OwnedDriverRegistration.Read();
                if(record==null || record.OwnerSid!=registration.OwnerSid || record.DriverPath!=registration.DriverPath) throw new InvalidOperationException("释放期间驱动所有权变化。");
                record.Validate(false);
                if(!record.RecoveryPending) stopOperation=record.BeginOrderlyStop();
                Dispose();record.StopService();
                using(Mutex mutex=OwnedDriverRegistration.OperationMutex()) {
                    bool held;try {held=mutex.WaitOne(0);} catch(AbandonedMutexException) {held=true;}
                    if(!held) throw new InvalidOperationException("恢复操作正在进行，保留持久封锁。");
                    try {
                        record.ValidateStopped();FortProvider.RemoveOwnedObjects(record);
                        if(stopOperation!=Guid.Empty) record.CompleteRecovery(stopOperation);
                        released=true;
                    } finally {mutex.ReleaseMutex();}
                }
            }
        }
        public void Dispose() {lock(output) {if(!disposed) {disposed=true;handle.Dispose();}}}
    }
}
