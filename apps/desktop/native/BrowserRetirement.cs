using System;
using System.IO;
using System.Linq;

namespace IpGuard {
    // Deployed browser entries need their own filters removed before the remaining roots start.
    internal static class BrowserRetirement {
        internal static bool IsBrowser(string path) {
            string image=Path.GetFileName(path);
            return new[] {"chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","vivaldi.exe","iexplore.exe"}.Contains(image,StringComparer.OrdinalIgnoreCase);
        }
        internal static bool Detach(Config config,Action<Target> release) {
            Target[] retired=config.apps.Where(t=>IsBrowser(t.path)).ToArray();
            if(retired.Length==0) return false;
            foreach(Target target in retired) release(target);
            config.apps.RemoveAll(t=>IsBrowser(t.path));
            config.commandProtection=config.apps.Any(t=>t.enabled && t.enhanced);
            return true;
        }
        internal static void Remove(Config config) {
            Target[] retired=config.apps.Where(t=>IsBrowser(t.path)).ToArray();
            if(retired.Length>0) {
                SystemPolicy.RequireAdmin();
                string backup=Data.ConfigPath+".before-browser-removal.bak";
                if(File.Exists(Data.ConfigPath) && !File.Exists(backup)) File.Copy(Data.ConfigPath,backup);
                Detach(config,target=>{
                    SystemPolicy.Unintercept(target);
                    SystemPolicy.RemoveFirewall(target);
                });
                Data.Save(config);
            }
        }

    }
}
