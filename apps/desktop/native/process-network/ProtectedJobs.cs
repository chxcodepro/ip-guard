using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace IpGuard.ProcessNetwork {
    internal interface IProtectedJobs {
        void Seal();
        bool HasActiveProcesses {get;}
    }
    internal sealed class ProtectedJobs : IProtectedJobs,IDisposable {
        [StructLayout(LayoutKind.Sequential)] struct Accounting {
            public long user,kernel,periodUser,periodKernel;
            public uint faults,total,active,terminated;
        }
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool DuplicateHandle(IntPtr sourceProcess,IntPtr source,IntPtr targetProcess,out IntPtr target,uint access,bool inherit,uint options);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(SafeWaitHandle job,int type,out Accounting accounting,uint size,IntPtr returned);
        readonly object sync=new object();
        readonly Dictionary<string,SafeWaitHandle> jobs=new Dictionary<string,SafeWaitHandle>(StringComparer.Ordinal);
        readonly Action<string[]> publish;
        bool sealedRegistry,disposed;
        public ProtectedJobs(Action<string[]> publish=null) {this.publish=publish;}
        void Publish() {if(publish!=null) {var names=new string[jobs.Count];jobs.Keys.CopyTo(names,0);publish(names);}}
        void RequireOpen() {if(disposed) throw new ObjectDisposedException("ProtectedJobs");}
        static bool Active(SafeWaitHandle job) {
            Accounting info;
            Win32.Check(QueryInformationJobObject(job,1,out info,(uint)Marshal.SizeOf(typeof(Accounting)),IntPtr.Zero),"无法核对受控进程树");return info.active!=0;
        }
        public void Register(string session,IntPtr job) {
            if(String.IsNullOrWhiteSpace(session) || job==IntPtr.Zero || job==new IntPtr(-1)) throw new ArgumentException("受控 Job 注册无效。");
            lock(sync) {
                RequireOpen();
                if(sealedRegistry || jobs.ContainsKey(session)) throw new InvalidOperationException("当前状态拒绝新增受控会话。");
                IntPtr copy;Win32.Check(DuplicateHandle(new IntPtr(-1),job,new IntPtr(-1),out copy,4,false,0),"无法保留受控 Job");
                var owned=new SafeWaitHandle(copy,true);
                try {if(Active(owned)) throw new InvalidOperationException("请在根进程启动前注册空 Job。");jobs.Add(session,owned);Publish();}
                catch {jobs.Remove(session);owned.Dispose();throw;}
            }
        }
        public void Unregister(string session) {
            lock(sync) {
                RequireOpen();SafeWaitHandle job;
                if(!jobs.TryGetValue(session,out job)) throw new InvalidOperationException("受控会话未注册。");
                if(Active(job)) throw new InvalidOperationException("受控进程仍在运行，保留归属记录。");
                jobs.Remove(session);job.Dispose();Publish();
            }
        }
        public void Seal() {lock(sync) {RequireOpen();sealedRegistry=true;}}
        public bool HasActiveProcesses {get {lock(sync) {RequireOpen();foreach(var job in jobs.Values) if(Active(job)) return true;return false;}}}
        public void Dispose() {
            lock(sync) {if(disposed) return;if(HasActiveProcesses) throw new InvalidOperationException("受控进程仍在运行。");foreach(var job in jobs.Values) job.Dispose();jobs.Clear();disposed=true;}
        }
    }
}
