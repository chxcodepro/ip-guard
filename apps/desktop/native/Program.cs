using System;
using System.IO;
using System.Text;
using System.Threading;

namespace IpGuard {
    public static class Program {
        [MTAThread] public static int Main(string[] args) {
            if(args.Length>0 && args[0].StartsWith("chrome-extension://",StringComparison.Ordinal)) return BrowserHost.Run(args[0]);
            try {
                if(args.Length>0 && (args[0]=="guard" || args[0]=="version")) {
                    Console.SetIn(new StreamReader(Console.OpenStandardInput(),new UTF8Encoding(false)));
                    Console.SetOut(new StreamWriter(Console.OpenStandardOutput(),new UTF8Encoding(false)) { AutoFlush=true });
                    Console.SetError(new StreamWriter(Console.OpenStandardError(),new UTF8Encoding(false)) { AutoFlush=true });
                }
                if(args.Length>0 && args[0]=="version") {
                    Console.WriteLine(Data.Json().Serialize(new { version=BuildInfo.Version,protocol=BuildInfo.Protocol })); return 0;
                }
                if(args.Length>0 && (args[0]=="gate" || args[0]=="package-gate")) {
                    int result=1; Exception failure=null;
                    Thread ui=new Thread(()=>{try { result=LaunchGate.Run(args,args[0]=="package-gate"); } catch(Exception e) { failure=e; }});
                    ui.SetApartmentState(ApartmentState.STA); ui.Start(); ui.Join();
                    if(failure!=null) throw failure;
                    return result;
                }
                if(args.Length==2 && args[0]=="restore-startup") {
                    SystemPolicy.RequireAdmin(); Config saved=Data.Load();
                    if(saved.autostart) SystemPolicy.Autostart(true,args[1]); return 0;
                }
                bool own;
                using(Mutex mutex=new Mutex(true,"Global\\"+SystemPolicy.Owner,out own)) {
                    if(!own) throw new Exception("IP Guard 正在运行，请先从托盘退出。");
                    if(args.Length>0 && args[0]=="recover") { SystemPolicy.Recover(); return 0; }
                    if(args.Length==0 || args[0]!="guard") throw new Exception("请通过 IP Guard 桌面程序启动。");
                    Console.WriteLine(Data.Json().Serialize(new { type="hello",version=BuildInfo.Version,protocol=BuildInfo.Protocol,sid=SystemPolicy.Sid })); Console.Out.Flush();
                    string line=Console.ReadLine();
                    var initialize=line==null ? null : Data.Json().Deserialize<System.Collections.Generic.Dictionary<string,object>>(line);
                    if(initialize==null || initialize["action"] as string!="initialize" || initialize["version"] as string!=BuildInfo.Version || Convert.ToInt32(initialize["protocol"])!=BuildInfo.Protocol) throw new Exception("界面与原生组件版本不匹配，请完整升级后启动。");
                    new Guard().Run();
                }
                return 0;
            } catch(Exception e) {
                string error=e.GetBaseException().Message;
                if(args.Length>0 && args[0]=="guard") { Console.WriteLine(Data.Json().Serialize(new { type="fatal",error=error })); Console.Out.Flush(); }
                else Win32.MessageBox(IntPtr.Zero,error,"IP Guard",0x10);
                return 1;
            }
        }
    }
}
