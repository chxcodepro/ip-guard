using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows.Forms;

namespace IpGuard {
    public sealed class ProtectionNotice {
        public string kind,currentIp,expectedIp;
        public string[] apps;
        static ProtectionNotice Parse(string line) {
            if(line.Length>16384) throw new InvalidDataException("防护提醒数据过长");
            ProtectionNotice data=Data.Json().Deserialize<ProtectionNotice>(line);
            if(data==null || !new[]{"ip_changed","ip_unavailable","guard_offline"}.Contains(data.kind) || data.apps==null || data.apps.Length==0 || data.apps.Length>30 || data.apps.Any(name=>String.IsNullOrWhiteSpace(name) || name.Length>100)) throw new InvalidDataException("防护提醒格式无效");
            if(data.currentIp==null || data.expectedIp==null || (data.currentIp!="" && !Data.PublicV4(data.currentIp)) || (data.expectedIp!="" && !Data.PublicV4(data.expectedIp))) throw new InvalidDataException("防护提醒地址无效");
            return data;
        }
        public static int Run() {
            ProtectionNotice initial;
            try { string first=Console.ReadLine();if(first==null) return 0;initial=Parse(first); }
            catch(Exception error) { Console.Error.WriteLine(error.GetBaseException().Message);return 1; }
            int result=0;
            Thread ui=new Thread(()=>{
                try {
                    LaunchWindow.ConfigureApplication();
                    using(LaunchWindow window=new LaunchWindow(initial)) {
                        Thread input=new Thread(()=>{
                            try { string line;while((line=Console.ReadLine())!=null) window.ShowProtectionNotice(Parse(line)); }
                            catch(Exception error) { result=1;Console.Error.WriteLine(error.GetBaseException().Message); }
                            finally { window.CloseFromOwner(); }
                        });
                        input.IsBackground=true;window.Shown+=(sender,args)=>input.Start();Application.Run(window);
                    }
                } catch(Exception error) { result=1;Console.Error.WriteLine(error.GetBaseException().Message); }
            });
            ui.SetApartmentState(ApartmentState.STA);ui.Start();ui.Join();return result;
        }
    }
}
