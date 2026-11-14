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
        public string type,name,currentIp,job,error,code;
        public string[] expectedIps;
        public ProbeProgress data;
        public bool? allow;
        public bool inherit;
        public bool commandProtection;
        public bool otherModel;
        public string scopeReason;
        public EgressPolicy enhancementPolicy;
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
            if(!packaged && InheritedLaunch(args)) return Execute(args,false,null,true,null);
            ModelEvidence evidence=null;
            if(!packaged && args.Length>=4 && args[1]==SystemPolicy.Sid) {
                Config settings=Data.Load();Target target=settings.apps.SingleOrDefault(t=>t.id==args[2]);
                if(target!=null && target.enabled && ClaudeCodeScope.IsCli(target)) {
                    evidence=!target.enhanced && target.apiScope=="other" ? new ModelEvidence {unknown=true} : ClaudeCodeScope.Read(args.Skip(3).ToArray());
                    if(ClaudeCodeScope.Decide(target,target.enhanced,evidence).Other) return Execute(args,false,null,false,evidence);
                }
            }
            LaunchWindow.ConfigureApplication();
            using(LaunchWindow window=new LaunchWindow("正在连接受保护程序")) {
                int exitCode=1;
                Thread worker=new Thread(()=>exitCode=Execute(args,packaged,window,false,evidence));
                window.Shown+=(sender,eventArgs)=>{TerminalProcess.BindCancel(window.CancelFromTerminal); worker.Start();};
                try { Application.Run(window); window.Cancel(); worker.Join(); }
                finally { TerminalProcess.UnbindCancel(); }
                return exitCode;
            }
        }
        static bool InheritedLaunch(string[] args) {
            Guid id;
            if(args.Length<4 || args[1]!=SystemPolicy.Sid || !Guid.TryParseExact(args[2],"D",out id)) return false;
            try {
                using(NamedPipeClientStream pipe=new NamedPipeClientStream(".","IPGuard-"+SystemPolicy.Sid,PipeDirection.InOut,PipeOptions.Asynchronous)) {
                    pipe.Connect(300);
                    using(StreamReader reader=new StreamReader(pipe,new UTF8Encoding(false),false,1024,true)) using(StreamWriter writer=new PipeWriter(pipe)) {
                        writer.WriteLine(Data.Json().Serialize(new { action="scope",id=args[2] }));
                        Task<string> response=Task.Run(()=>reader.ReadLine());
                        if(!response.Wait(1500) || response.Result==null || response.Result.Length>16384) return false;
                        GateMessage result=Data.Json().Deserialize<GateMessage>(response.Result);
                        return result!=null && result.inherit;
                    }
                }
            } catch(IOException) { return false; }
            catch(UnauthorizedAccessException) { return false; }
            catch(TimeoutException) { return false; }
            catch(InvalidOperationException) { return false; }
            catch(AggregateException) { return false; }
            catch(ArgumentException) { return false; }
        }
        static int Execute(string[] args,bool packaged,LaunchWindow window,bool inherited,ModelEvidence modelEvidence) {
            Win32.ProcessInfo info=new Win32.ProcessInfo(); string ip=""; string[] expected=new string[0]; bool processOwned=false;
            try {
                if(args.Length<(packaged ? 6 : 4)) throw new Exception("启动参数无效。");
                string sid=packaged ? SystemPolicy.Sid : args[1], id=packaged ? args[1] : args[2]; Guid parsed;
                if(sid!=SystemPolicy.Sid || !Guid.TryParseExact(id,"D",out parsed)) throw new Exception("启动标识无效。");
                Config config=Data.Load(); Target target=config.apps.SingleOrDefault(t=>t.id==id);
                if(target==null || !target.enabled) throw new Exception("该程序尚未启用防护。");
                expected=config.settings.expectedIps.ToArray(); if(window!=null) window.Context(target.name,expected);
                string exe=target.path;
                if(packaged) { info=PackagePolicy.OpenTarget(target,Argument(args,"-p"),Argument(args,"-tid")); processOwned=true; }
                using(NamedPipeClientStream pipe=new NamedPipeClientStream(".","IPGuard-"+sid,PipeDirection.InOut,PipeOptions.Asynchronous)) {
                    Action cancel=()=>pipe.Dispose(); if(window!=null) window.CancelRequested+=cancel; else TerminalProcess.BindCancel(cancel);
                    try {
                        if(window!=null) window.Progress(new ProbeProgress("connection","连接守护","running","等待本机启动校验"));
                        try { pipe.Connect(4000); } catch(TimeoutException) { throw new Exception("请先运行 IP Guard，再启动受保护程序。"); }
                        if(window!=null) window.Progress(new ProbeProgress("connection","连接守护","ok","守护连接已建立"));
                        using(StreamReader reader=new StreamReader(pipe,new UTF8Encoding(false),false,1024,true)) using(StreamWriter writer=new PipeWriter(pipe)) {
                            writer.WriteLine(Data.Json().Serialize(new { id=id,path=exe,package=packaged,pid=info.pid,tid=info.tid,inherit=inherited,modelEvidence=modelEvidence }));
                            GateMessage result=null;
                            for(int n=0;n<64;n++) {
                                GateMessage message=Data.Json().Deserialize<GateMessage>(ReadTimed(reader,BuildInfo.ProbeTimeoutMs+5000));
                                if(message==null) throw new Exception("启动校验响应无效。");
                                if(message.type=="context") { expected=message.expectedIps ?? expected; if(window!=null) window.Context(message.name ?? target.name,expected); }
                                else if(message.type=="progress" && message.data!=null) { if(window!=null) window.Progress(message.data); }
                                else { result=message; break; }
                            }
                            if(result==null || result.allow==null) throw new Exception("启动校验未完成。");
                            ip=result.currentIp ?? ""; expected=result.expectedIps ?? expected;
                            if(result.allow!=true) {
                                if(result.code==FirewallDisabledException.Code) throw new FirewallDisabledException(result.error);
                                throw new Exception(result.error ?? "启动已阻断。");
                            }
                            if(result.otherModel) {Console.Error.WriteLine("IP Guard · "+result.scopeReason+" · 正在启动，使用原网络");exe=ClaudeCodeScope.PrepareOtherImage(target);}
                            string jobPrefix=result.commandProtection ? "Global\\IPGuard-"+sid+"-" : "Local\\IPGuard-";
                            if(result.job==null || !result.job.StartsWith(jobPrefix,StringComparison.Ordinal)) throw new Exception("守护许可无效。");
                            EgressPolicy route=result.otherModel ? null : result.enhancementPolicy ?? config.egress;
                            using(ClaudeProxySettings launchSettings=!packaged && route!=null && ClaudeCodeScope.IsCli(target)
                                ? new ClaudeProxySettings(args.Skip(3).ToArray(),route) : null) {
                            IntPtr handle=Win32.OpenJobObject(0x0d,false,result.job);
                            if(handle==IntPtr.Zero) throw new Exception("无法接管受保护进程树。");
                            using(Lease lease=new Lease(handle)) {
                                if(packaged) Win32.Check(Win32.DebugActiveProcess(info.pid),"无法接管安装包进程");
                                else {
                                    string command=String.Join(" ",(launchSettings==null ? args.Skip(3).ToArray() : launchSettings.Arguments).Select(Data.Quote));
                                    using(EgressEnvironment environment=new EgressEnvironment(route,result.otherModel)) {
                                    if(TerminalProcess.IsConsole(exe)) {
                                        TerminalProcess.Attach();
                                        using(TerminalProcess terminal=new TerminalProcess()) info=terminal.Start(exe,command,environment.pointer,environment.flags,result.commandProtection);
                                    } else {
                                        Win32.StartupInfo startup=new Win32.StartupInfo(); startup.cb=Marshal.SizeOf(startup);
                                        Win32.Check(Win32.CreateProcess(exe,new StringBuilder(command),IntPtr.Zero,IntPtr.Zero,false,(result.commandProtection ? 0x5U : 0x6U)|environment.flags,environment.pointer,Environment.CurrentDirectory,ref startup,out info),"无法创建受保护程序");
                                    }
                                    }
                                    processOwned=true;
                                }
                                Win32.Check(Win32.DebugSetProcessKillOnExit(true));
                                if(result.commandProtection) ProcessTreeMetadata.PrepareRoot(info.pid);
                                Win32.Check(Win32.AssignProcessToJobObject(lease.job,info.process),"无法建立进程树防护");
                                writer.WriteLine("started");
                                if(ReadTimed(reader,5000)!="run") throw new Exception("启动许可已撤销。");
                                lease.Begin(reader); if(window!=null) window.Success(ip,expected);
                                if(window!=null ? !window.WaitForRelease(lease.Alive) : !lease.Alive()) throw new Exception("启动许可已撤销，程序保持停止。");
                                TerminalProcess.MarkStarted();
                                if(Win32.ResumeThread(info.thread)==UInt32.MaxValue) throw new Exception("恢复目标进程失败。");
                                try {MonitorProcess(info,lease,result.commandProtection);}
                                catch(Exception error) {
                                    if(result.commandProtection) try {writer.WriteLine(Data.Json().Serialize(new {type="command-blocked",error=error.GetBaseException().Message}));} catch(IOException) {}
                                    throw;
                                }
                                uint exitCode; Win32.Check(Win32.GetExitCodeProcess(info.process,out exitCode)); return exitCode==259 ? 1 : unchecked((int)exitCode);
                            }
                            }
                        }
                    } finally { if(window!=null) window.CancelRequested-=cancel; else TerminalProcess.UnbindCancel(); }
                }
            } catch(Exception error) { if(window!=null) window.Block(error.GetBaseException().Message,ip,expected,error.GetBaseException() is FirewallDisabledException); else Console.Error.WriteLine("IP Guard · "+error.GetBaseException().Message); return 1; }
            finally {
                if(processOwned) { Win32.TerminateProcess(info.process,1); Win32.CloseHandle(info.thread); Win32.CloseHandle(info.process); }
                if(window!=null) window.End();
            }
        }
        static void MonitorProcess(Win32.ProcessInfo info,Lease lease,bool protectChildren) {
            DebugProcessTree.Run(info,lease.job,()=>!lease.stopped,lease.Alive,protectChildren);
        }
    }
}
