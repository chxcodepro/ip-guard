using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using IpGuard;
using IpGuard.ProcessNetwork;

public static class ReviewClient {
    static string SendUdp() {
        try {using(var udp=new UdpClient()) {byte[] bytes={1,2,3};udp.Send(bytes,bytes.Length,new IPEndPoint(IPAddress.Loopback,Int32.Parse(Environment.GetEnvironmentVariable("REVIEW_UDP"))));}return "SENT";}
        catch(SocketException) {return "BLOCKED";}
    }
    static string Exchange(bool proxy,bool ipv6) {
        try {
            using(var socket=new Socket(ipv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp)) {
                int port=Int32.Parse(Environment.GetEnvironmentVariable(proxy ? "REVIEW_PROXY" : ipv6 ? "REVIEW_V6" : "REVIEW_DIRECT"));
                IAsyncResult result=socket.BeginConnect(ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback,port,null,null);
                if(!result.AsyncWaitHandle.WaitOne(1800)) return "BLOCKED";socket.EndConnect(result);socket.ReceiveTimeout=1800;
                byte[] bytes=new byte[8];return socket.Receive(bytes)>0 ? "OK" : "BLOCKED";
            }
        } catch(SocketException) {return "BLOCKED";}
    }
    public static int Main(string[] args) {
        if(args.Length==0 || args[0]=="one") return Exchange(false,false)=="OK" ? 0 : 7;
        if(args[0]=="v6") return Exchange(false,true)=="OK" ? 0 : 7;
        if(args[0]=="udp") return SendUdp()=="SENT" ? 0 : 7;
        string name=Environment.GetEnvironmentVariable("REVIEW_PIPE")+"-"+Process.GetCurrentProcess().Id;
        using(var pipe=new NamedPipeServerStream(name,PipeDirection.InOut,1)) {
            pipe.WaitForConnection();var reader=new StreamReader(pipe);var writer=new StreamWriter(pipe) {AutoFlush=true};
            for(string command;(command=reader.ReadLine())!=null;) {
                if(command=="exit") {writer.WriteLine("BYE");return 0;}
                if(command=="proxy" || command=="direct" || command=="ipv6") writer.WriteLine(Exchange(command=="proxy",command=="ipv6"));
                else if(command=="udp") {
                    writer.WriteLine(SendUdp());
                } else if(command=="child") {
                    using(Process child=Process.Start(new ProcessStartInfo(Environment.GetEnvironmentVariable("REVIEW_CHILD"),"one") {UseShellExecute=false,CreateNoWindow=true})) {if(!child.WaitForExit(6000)) {child.Kill();throw new Exception("child timeout");}writer.WriteLine(child.ExitCode==0 ? "OK" : "BLOCKED");}
                } else if(command=="missing") {NativeEmpty.Start(Environment.GetEnvironmentVariable("REVIEW_CHILD"));writer.WriteLine("UNEXPECTED");}
                else writer.WriteLine("UNKNOWN");
            }
        }
        return 0;
    }
}
static class NativeEmpty {
    [StructLayout(LayoutKind.Sequential)] struct Unicode {public ushort length,maximum;public IntPtr buffer;}
    [DllImport("ntdll.dll")] static extern int RtlCreateProcessParametersEx(out IntPtr parameters,ref Unicode image,IntPtr dll,IntPtr cwd,IntPtr command,IntPtr environment,IntPtr title,IntPtr desktop,IntPtr shell,IntPtr runtime,uint flags);
    [DllImport("ntdll.dll")] static extern void RtlDestroyProcessParameters(IntPtr parameters);
    [DllImport("ntdll.dll")] static extern int NtCreateUserProcess(out IntPtr process,out IntPtr thread,uint processAccess,uint threadAccess,IntPtr pa,IntPtr ta,uint processFlags,uint threadFlags,IntPtr parameters,IntPtr createInfo,IntPtr attributes);
    [DllImport("kernel32.dll")] static extern IntPtr GetEnvironmentStrings();
    [DllImport("kernel32.dll")] static extern bool FreeEnvironmentStrings(IntPtr environment);
    public static void Start(string path) {
        string image=@"\??\"+path;IntPtr imageText=Marshal.StringToHGlobalUni(image),parameters=IntPtr.Zero,info=Marshal.AllocHGlobal(88),attributes=Marshal.AllocHGlobal(40),environment=GetEnvironmentStrings();
        IntPtr process=IntPtr.Zero,thread=IntPtr.Zero;
        try {
            var name=new Unicode {length=(ushort)(image.Length*2),maximum=(ushort)(image.Length*2+2),buffer=imageText};
            if(RtlCreateProcessParametersEx(out parameters,ref name,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,environment,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,1)<0) throw new Exception("RTL parameters failed");
            for(int i=0;i<16;i++) Marshal.WriteByte(parameters,0x70+i,0);
            for(int i=0;i<88;i++) Marshal.WriteByte(info,i,0);Marshal.WriteInt64(info,88);
            for(int i=0;i<40;i++) Marshal.WriteByte(attributes,i,0);
            Marshal.WriteInt64(attributes,40);Marshal.WriteInt64(attributes,8,0x20005);Marshal.WriteInt64(attributes,16,name.length);Marshal.WriteIntPtr(attributes,24,imageText);
            int result=NtCreateUserProcess(out process,out thread,0x1fffff,0x1fffff,IntPtr.Zero,IntPtr.Zero,0,1,parameters,info,attributes);
            if(result<0) throw new Exception("NT create failed: "+result.ToString("X8"));
            Win32.ResumeThread(thread);
            using(Process child=Process.GetProcessById((int)GetPid(process))) {if(!child.WaitForExit(5000)) child.Kill();}
        } finally {if(thread!=IntPtr.Zero) Win32.CloseHandle(thread);if(process!=IntPtr.Zero) Win32.CloseHandle(process);if(parameters!=IntPtr.Zero) RtlDestroyProcessParameters(parameters);FreeEnvironmentStrings(environment);Marshal.FreeHGlobal(imageText);Marshal.FreeHGlobal(info);Marshal.FreeHGlobal(attributes);}
    }
    [DllImport("kernel32.dll",EntryPoint="GetProcessId")] static extern uint GetPid(IntPtr process);
}
public static class KernelReview {
    static volatile bool proxyAllowed=true;
    static int directCount,udpCount;
    static TcpListener proxy,direct,v6;
    static UdpClient udp;
    static int StartTcp(bool allowed,bool ipv6) {
        var listener=new TcpListener(ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback,0);listener.Start();
        if(allowed) proxy=listener;else if(ipv6) v6=listener;else direct=listener;
        Task.Run(()=>{while(true) {try {var client=listener.AcceptTcpClient();if(!allowed) Interlocked.Increment(ref directCount);using(client) {if(!allowed || proxyAllowed) {byte[] data=Encoding.ASCII.GetBytes("ok\n");client.GetStream().Write(data,0,data.Length);}}} catch(SocketException) {break;}catch(ObjectDisposedException) {break;}}});
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
    static void Check(bool ok,string name) {Console.WriteLine((ok ? "PASS " : "FAIL ")+name);if(!ok) throw new Exception(name);}
    sealed class Session : IDisposable {
        public uint Pid;public Exception Error;
        readonly ManualResetEvent created=new ManualResetEvent(false);
        Thread thread;NamedPipeClientStream pipe;StreamReader reader;StreamWriter writer;
        public Session(KernelProtection protection,string exe) {
            thread=new Thread(()=>{
                Win32.ProcessInfo info=new Win32.ProcessInfo();IntPtr job=IntPtr.Zero;string name="Global\\IPGuard-"+SystemPolicy.Sid+"-"+Guid.NewGuid().ToString("D");
                try {
                    job=Win32.NewJob(name);protection.Register(name,job);
                    Win32.StartupInfo startup=new Win32.StartupInfo();startup.cb=Marshal.SizeOf(startup);
                    Win32.Check(Win32.CreateProcess(exe,new StringBuilder(Data.Quote(exe)+" server"),IntPtr.Zero,IntPtr.Zero,false,0x08000005,IntPtr.Zero,Path.GetDirectoryName(exe),ref startup,out info));
                    Pid=info.pid;Win32.Check(Win32.DebugSetProcessKillOnExit(true));Win32.Check(Win32.AssignProcessToJobObject(job,info.process));
                    ProcessTreeMetadata.PrepareRoot(info.pid);Win32.ResumeThread(info.thread);created.Set();
                    DebugProcessTree.Run(info,job,()=>true,()=>true,true);
                } catch(Exception error) {Error=error;created.Set();}
                finally {
                    if(info.process!=IntPtr.Zero) {Win32.TerminateProcess(info.process,1);Win32.DebugActiveProcessStop(info.pid);Win32.CloseHandle(info.thread);Win32.CloseHandle(info.process);}
                    if(job!=IntPtr.Zero) {try {protection.Unregister(name);} catch(Exception error) {Console.WriteLine("journal: "+error.Message);}Win32.CloseHandle(job);}
                }
            });thread.IsBackground=true;thread.Start();
            if(!created.WaitOne(10000) || Error!=null) throw new Exception("root start",Error);
            pipe=new NamedPipeClientStream(".",Environment.GetEnvironmentVariable("REVIEW_PIPE")+"-"+Pid,PipeDirection.InOut);pipe.Connect(5000);reader=new StreamReader(pipe);writer=new StreamWriter(pipe) {AutoFlush=true};
        }
        public string Send(string command) {writer.WriteLine(command);Task<string> result=Task.Run(()=>reader.ReadLine());if(!result.Wait(10000)) throw new TimeoutException(command);return result.Result;}
        public void Dispose() {if(pipe!=null) {try {if(thread.IsAlive) Send("exit");}catch(IOException) {}pipe.Dispose();}if(!thread.Join(5000)) throw new Exception("debug worker did not exit");}
    }
    public static int Main(string[] args) {
        if(args.Length!=1 || (args[0]!="--install-only" && args[0]!="--verify")) return 2;
        KernelProtection protection=null;bool installed=false;
        try {
            if(args[0]=="--install-only") {OwnedDriverRegistration.Install();Console.WriteLine("INSTALL_ONLY: driver stopped; independent recovery task prepared");return 0;}
            SystemPolicy.RequireAdmin();
            string folder=Path.GetDirectoryName(SystemPolicy.Exe),root=Path.Combine(folder,"claude.exe"),child=Path.Combine(folder,"child.exe");
            Environment.SetEnvironmentVariable("REVIEW_PIPE","IPGuard.KernelReview."+Guid.NewGuid().ToString("N"));
            int proxyPort=StartTcp(true,false),directPort=StartTcp(false,false),v6Port=StartTcp(false,true);
            udp=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));Task.Run(()=>{while(true) {try {IPEndPoint endpoint=null;udp.Receive(ref endpoint);Interlocked.Increment(ref udpCount);}catch {break;}}});
            Environment.SetEnvironmentVariable("REVIEW_PROXY",proxyPort.ToString());Environment.SetEnvironmentVariable("REVIEW_DIRECT",directPort.ToString());Environment.SetEnvironmentVariable("REVIEW_V6",v6Port.ToString());Environment.SetEnvironmentVariable("REVIEW_UDP",((IPEndPoint)udp.Client.LocalEndPoint).Port.ToString());Environment.SetEnvironmentVariable("REVIEW_CHILD",child);
            using(Process baseline=Process.Start(new ProcessStartInfo(root,"one") {UseShellExecute=false,CreateNoWindow=true})) {Check(baseline.WaitForExit(5000) && baseline.ExitCode==0,"unfiltered direct TCP positive control");}
            using(Process baseline=Process.Start(new ProcessStartInfo(root,"v6") {UseShellExecute=false,CreateNoWindow=true})) {Check(baseline.WaitForExit(5000) && baseline.ExitCode==0,"unfiltered IPv6 positive control");}
            using(Process baseline=Process.Start(new ProcessStartInfo(root,"udp") {UseShellExecute=false,CreateNoWindow=true})) {Check(baseline.WaitForExit(5000) && baseline.ExitCode==0,"unfiltered UDP positive control");}
            Thread.Sleep(200);Check(udpCount>0,"UDP receiver positive control");Interlocked.Exchange(ref udpCount,0);
            int before=directCount;
            installed=OwnedDriverRegistration.Read()!=null;
            protection=new KernelProtection(allowed=>proxyAllowed=allowed);
            var egress=new EgressPolicy {id=Guid.NewGuid().ToString("D"),label="isolated review",port=proxyPort};
            protection.Start(egress,new[] {new Target {id=Guid.NewGuid().ToString("D"),name="isolated fixture",path=root,enabled=true}},true);protection.Allow(true);
            using(var session=new Session(protection,root)) {
                Check(session.Send("proxy")=="OK","fixed proxy accepted");
                Check(session.Send("direct")=="BLOCKED","direct TCP blocked");Check(session.Send("ipv6")=="BLOCKED","IPv6 blocked");
                Check(session.Send("child")=="BLOCKED","child first network request blocked");
                session.Send("udp");Thread.Sleep(200);Check(udpCount==0,"UDP blocked");
                protection.Allow(false);Check(session.Send("proxy")=="BLOCKED","pause closes proxy forwarding");
                using(Process same=Process.GetProcessById((int)session.Pid)) Check(!same.HasExited,"pause retains process");
                protection.Allow(true);Check(session.Send("proxy")=="OK","same process resumes via fixed proxy");
                Check(directCount==before,"no guarded direct packets arrived");
            }
            using(var missing=new Session(protection,root)) {
                try {missing.Send("missing");}catch(IOException) {}
                Thread.Sleep(400);Check(missing.Error!=null && missing.Error.Message.Contains("元数据"),"missing metadata refused before user code");
            }
            protection.Stop();protection=null;
            Check(OwnedDriverRegistration.Read().Validate(false)==1,"normal cleanup stops driver");
            Console.WriteLine("REVIEW_COMPLETE");return 0;
        } catch(Exception error) {Console.Error.WriteLine(error);return 1;}
        finally {
            if(proxy!=null) proxy.Stop();if(direct!=null) direct.Stop();if(v6!=null) v6.Stop();if(udp!=null) udp.Close();
            try {if(protection!=null) protection.Stop();if(installed) {var record=OwnedDriverRegistration.Read();if(record!=null) record.Uninstall();}}
            catch(Exception error) {Console.Error.WriteLine("AUTOMATIC RECOVERY REMAINS ARMED: "+error.Message);}
        }
    }
}
