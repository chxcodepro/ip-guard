using System;
using System.IO;
using System.Linq;

namespace IpGuard {
    public static class ClaudeChrome {
        public const string HomeUrl="https://claude.ai/";
        public static string Exe { get {return Path.Combine(Data.DirectoryPath,@"browser\Application\chrome.exe");} }
        public static bool IsPath(string path) {return String.Equals(Path.GetFullPath(path),Exe,StringComparison.OrdinalIgnoreCase);}
        public static void RequireClosed() {
            if(!File.Exists(Exe)) return;
            try {using(FileStream file=new FileStream(Exe,FileMode.Open,FileAccess.ReadWrite,FileShare.None)) {}}
            catch(IOException) {throw new Exception("请先关闭专用 Chrome 窗口后重试。");}
        }
        public static string Command(EgressPolicy policy,string url) {
            if(policy==null) throw new Exception("请先启用独立固定出口，再启动专用 Chrome。");
            if(url!=HomeUrl && url!=BuildInfo.ClaudeChromeStoreUrl) throw new Exception("专用 Chrome 启动地址无效。");
            string[] args={Exe,"--user-data-dir="+Path.Combine(Data.DirectoryPath,@"browser\User Data"),"--profile-directory=Default","--proxy-server="+policy.Url,"--proxy-bypass-list=<-loopback>","--disable-quic","--no-first-run","--no-default-browser-check",url};
            return String.Join(" ",args.Select(Data.Quote));
        }
    }
}
