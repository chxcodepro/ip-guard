using System;
using System.IO;

namespace IpGuard.ProcessNetwork {
    internal static class RecoveryProgram {
        public static int Main(string[] args) {
            string action=args.Length==0 ? "--status" : args[0];
            if(args.Length>1 || (action!="--status" && action!="--repair" && action!="--automatic")) {Console.Error.WriteLine("--status | --repair | --automatic");return 2;}
            try {
                var record=OwnedDriverRegistration.Read();if(record==null) {Console.WriteLine("尚未安装命令进程树驱动。");return 0;}
                if(action=="--status") {Console.WriteLine("fortfw · "+record.Validate(false)+(record.RecoveryPending ? " · 待恢复" : ""));return 0;}
                SystemPolicy.RequireAdmin();
                KernelRuntime.Rescue(record,action=="--automatic");Console.WriteLine("恢复检查完成；需要恢复时已停止受控进程、停用驱动并清理自有规则。");return 0;
            } catch(Exception error) {
                string message=DateTimeOffset.Now.ToString("o")+" "+error.Message;
                Console.Error.WriteLine(message);
                try {File.AppendAllText(Path.Combine(OwnedDriverRegistration.Home,"recovery.log"),message+Environment.NewLine);} catch(Exception logError) {Console.Error.WriteLine(logError.Message);}
                return 1;
            }
        }
    }
}
