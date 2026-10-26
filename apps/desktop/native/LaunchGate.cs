using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace IpGuard {
    public sealed class GateMessage {
        public string type,name,expectedIp,currentIp,job,error,code;
        public ProbeProgress data;
        public bool? allow;
    }
    public static class LaunchGate {
        sealed class Lease : IDisposable {
            readonly object sync=new object();
            long verified=Stopwatch.GetTimestamp();
            public IntPtr job;
            public volatile bool stopped;
            public Lease(IntPtr handle) { job=handle; }
            public bool Alive() { return !stopped && Stopwatch.GetTimestamp()-Interlocked.Read(ref verified)<Stopwatch.Frequency*1.8; }
            public void Begin(StreamReader reader) { Interlocked.Exchange(ref verified,Stopwatch.GetTimestamp()); Task.Run(()=>Read(reader)); }
            void Read(StreamReader reader) {
                try { string line; while((line=reader.ReadLine())=="lease") Interlocked.Exchange(ref verified,Stopwatch.GetTimestamp()); }
                catch(IOException) { }
                catch(ObjectDisposedException) { }
                finally { Stop(); }
            }
            public void Dispose() { lock(sync) { stopped=true; if(job!=IntPtr.Zero) { Win32.TerminateJobObject(job,1); Win32.CloseHandle(job); job=IntPtr.Zero; } } }
            void Stop() { stopped=true; lock(sync) if(job!=IntPtr.Zero) Win32.TerminateJobObject(job,1); }
        }
        static string ReadTimed(StreamReader reader,int timeout) {
            Task<string> read=Task.Run(()=>reader.ReadLine());
            if(!read.Wait(timeout) || read.Result==null) throw new Exception("守护程序未响应，启动已拦截。");
            if(read.Result.Length>16384) throw new Exception("启动校验响应无效。"); return read.Result;
        }
        static uint Argument(string[] args,string flag) {
            int index=Array.IndexOf(args,flag); uint value;
            if(index<0 || index+1>=args.Length || !UInt32.TryParse(args[index+1],out value) || value==0) throw new Exception("安装包启动参数无效。"); return value;
        }
        public static int Run(string[] args,bool packaged) {
            LaunchWindow.ConfigureApplication();
            using(LaunchWindow window=new LaunchWindow("正在连接受保护程序")) {
                Thread worker=new Thread(()=>Execute(args,packaged,window));
                window.Shown+=(sender,eventArgs)=>worker.Start();
                Application.Run(window); window.Cancel(); worker.Join();
            }
            return 0;
        }
        static void Execute(string[] args,bool packaged,LaunchWindow window) {
            Win32.ProcessInfo info=new Win32.ProcessInfo(); string ip="",expected=""; bool processOwned=false;
            try {
                if(args.Length<(packaged ? 6 : 4)) throw new Exception("启动参数无效。");
                string sid=packaged ? SystemPolicy.Sid : args[1], id=packaged ? args[1] : args[2]; Guid parsed;
                if(sid!=SystemPolicy.Sid || !Guid.TryParseExact(id,"D",out parsed)) throw new Exception("启动标识无效。");
                Config config=Data.Load(); Target target=config.apps.SingleOrDefault(t=>t.id==id);
                if(target==null || !target.enabled) throw new Exception("该程序尚未启用防护。");
                expected=config.settings.expectedIp; window.Context(target.name,expected);
                string exe=target.path;
                if(packaged) { info=PackagePolicy.OpenTarget(target,Argument(args,"-p"),Argument(args,"-tid")); processOwned=true; }
                else if(!String.Equals(Path.GetFullPath(args[3]),target.path,StringComparison.OrdinalIgnoreCase)) throw new Exception("启动路径与受保护程序不匹配。");
                using(NamedPipeClientStream pipe=new NamedPipeClientStream(".","IPGuard-"+sid,PipeDirection.InOut,PipeOptions.Asynchronous)) {
                    Action cancel=()=>pipe.Dispose(); window.CancelRequested+=cancel;
                    try {
                        window.Progress(new ProbeProgress("connection","连接守护","running","等待本机启动校验"));
                        try { pipe.Connect(4000); } catch(TimeoutException) { throw new Exception("请先运行 IP Guard，再启动受保护程序。"); }
                        window.Progress(new ProbeProgress("connection","连接守护","ok","守护连接已建立"));
                        using(StreamReader reader=new StreamReader(pipe,new UTF8Encoding(false),false,1024,true)) using(StreamWriter writer=new PipeWriter(pipe)) {
                            writer.WriteLine(Data.Json().Serialize(new { id=id,path=exe,package=packaged,pid=info.pid,tid=info.tid }));
                            GateMessage result=null;
                            for(int n=0;n<64;n++) {
                                GateMessage message=Data.Json().Deserialize<GateMessage>(ReadTimed(reader,15000));
                                if(message==null) throw new Exception("启动校验响应无效。");
                                if(message.type=="context") { expected=message.expectedIp ?? expected; window.Context(message.name ?? target.name,expected); }
                                else if(message.type=="progress" && message.data!=null) window.Progress(message.data);
                                else { result=message; break; }
                            }
                            if(result==null || result.allow==null) throw new Exception("启动校验未完成。");
                            ip=result.currentIp ?? ""; expected=result.expectedIp ?? expected;
                            if(result.allow!=true) {
                                if(result.code==FirewallDisabledException.Code) throw new FirewallDisabledException(result.error);
                                throw new Exception(result.error ?? "启动已阻断。");
                            }
                            if(result.job==null || !result.job.StartsWith("Local\\IPGuard-")) throw new Exception("守护许可无效。");
                            IntPtr handle=Win32.OpenJobObject(0x0d,false,result.job);
                            if(handle==IntPtr.Zero) throw new Exception("无法接管受保护进程树。");
                            using(Lease lease=new Lease(handle)) {
                                if(packaged) Win32.Check(Win32.DebugActiveProcess(info.pid),"无法接管安装包进程");
                                else {
                                    Win32.StartupInfo startup=new Win32.StartupInfo(); startup.cb=Marshal.SizeOf(startup);
                                    string command=String.Join(" ",args.Skip(3).Select(Data.Quote));
                                    Win32.Check(Win32.CreateProcess(exe,new StringBuilder(command),IntPtr.Zero,IntPtr.Zero,false,0x6,IntPtr.Zero,Environment.CurrentDirectory,ref startup,out info),"无法创建受保护程序"); processOwned=true;
                                }
                                Win32.Check(Win32.DebugSetProcessKillOnExit(true));
                                Win32.Check(Win32.AssignProcessToJobObject(lease.job,info.process),"无法建立进程树防护");
                                writer.WriteLine("started");
                                if(ReadTimed(reader,5000)!="run") throw new Exception("启动许可已撤销。");
                                lease.Begin(reader); window.Success(ip,expected);
                                if(!window.WaitForRelease(lease.Alive)) throw new Exception("启动许可已撤销，程序保持停止。");
                                if(Win32.ResumeThread(info.thread)==UInt32.MaxValue) throw new Exception("恢复目标进程失败。");
                                MonitorProcess(info,lease);
                            }
                        }
                    } finally { window.CancelRequested-=cancel; }
                }
            } catch(Exception error) { window.Block(error.GetBaseException().Message,ip,expected,error.GetBaseException() is FirewallDisabledException); }
            finally {
                if(processOwned) { Win32.TerminateProcess(info.process,1); Win32.CloseHandle(info.thread); Win32.CloseHandle(info.process); }
                window.End();
            }
        }
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int type,IntPtr info,uint length,IntPtr returned);
        static bool JobHasProcesses(IntPtr job) {
            IntPtr p=Marshal.AllocHGlobal(48);
            try { Win32.Check(QueryInformationJobObject(job,1,p,48,IntPtr.Zero)); return Marshal.ReadInt32(p,40)>0; }
            finally { Marshal.FreeHGlobal(p); }
        }
        static void MonitorProcess(Win32.ProcessInfo info,Lease lease) {
            while(!lease.stopped) {
                if(!lease.Alive()) throw new Exception("守护连接超时，受保护程序已结束。");
                Win32.DebugEvent debug;
                if(!Win32.WaitForDebugEvent(out debug,200)) continue;
                if((debug.code==3 || debug.code==6) && debug.info.file!=IntPtr.Zero && debug.info.file!=new IntPtr(-1)) Win32.CloseHandle(debug.info.file);
                uint status=0x00010002;
                if(debug.code==1 && debug.info.exception!=0x80000003 && debug.info.exception!=0x80000004) status=0x80010001;
                Win32.Check(Win32.ContinueDebugEvent(debug.pid,debug.tid,status));
                if(debug.code==5 && debug.pid==info.pid) {
                    while(!lease.stopped && JobHasProcesses(lease.job)) { if(!lease.Alive()) throw new Exception("守护连接超时，受保护程序已结束。"); Thread.Sleep(200); }
                    break;
                }
            }
        }
    }
}
