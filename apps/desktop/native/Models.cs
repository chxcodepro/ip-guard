using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Web.Script.Serialization;

namespace IpGuard {
    public sealed class Settings {
        public List<string> expectedIps = new List<string>();
        public int intervalSeconds = 2;
    }
    public sealed class Target {
        public string id;
        public string name;
        public string path;
        public string arguments = "";
        public string apiScope = "auto";
        [ScriptIgnore] public bool cli;
        public bool enabled;
        public bool enhanced;
    }
    public sealed class Config {
        public EgressPolicy egress;
        public Settings settings = new Settings();
        public List<Target> apps = new List<Target>();
        public bool autostart;
        public bool rulesLocked;
        public bool commandProtection;
        public string ipSource = "claude-ai";
        public string networkAdapterId="", networkAdapterName="";
    }
    public static class Data {
        public static readonly string DirectoryPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "IPGuard");
        public static readonly string ConfigPath = Path.Combine(DirectoryPath, "settings.json");
        public static JavaScriptSerializer Json() { return new JavaScriptSerializer { MaxJsonLength = 1048576 }; }
        public static Config Load() {
            if (!File.Exists(ConfigPath)) return new Config();
            string source = File.ReadAllText(ConfigPath);
            Config c = Json().Deserialize<Config>(source);
            if (c == null || c.settings == null || c.apps == null) throw new Exception("配置文件损坏，请恢复 settings.json.bak 或执行恢复工具。");
            var fields=Json().Deserialize<Dictionary<string,object>>(source);
            var settings=fields["settings"] as Dictionary<string,object>;
            if(settings==null) throw new Exception("防护规则格式无效，请恢复配置备份。");
            bool legacyIp=!settings.ContainsKey("expectedIps");
            if(legacyIp) {
                object value;
                if(!settings.TryGetValue("expectedIp",out value) || !(value is string)) throw new Exception("允许地址配置无效，请恢复配置备份。");
                string ip=(string)value;
                c.settings.expectedIps=ip=="" ? new List<string>() : new List<string> {ip};
            }
            bool legacyLock=!fields.ContainsKey("rulesLocked");
            bool migrate=legacyIp || legacyLock || !fields.ContainsKey("ipSource");
            var originalApps=fields["apps"] as System.Collections.IList;
            if(originalApps==null || originalApps.Count!=c.apps.Count) throw new Exception("程序列表格式无效。");
            for(int i=0;i<c.apps.Count;i++) {
                var original=originalApps[i] as Dictionary<string,object>;
                if(original==null || c.apps[i]==null) throw new Exception("程序配置格式无效。");
                if(!original.ContainsKey("apiScope")) {c.apps[i].apiScope=c.apps[i].enabled ? "claude" : "auto";migrate=true;}
            }
            if (legacyLock) c.rulesLocked = c.settings.expectedIps!=null && c.settings.expectedIps.Count>0;
            if(c.ipSource!="claude-ai") throw new Exception("IP 来源配置无效，请恢复配置备份。");
            Validate(c.settings,!c.rulesLocked);
            if(c.egress!=null) c.egress.Validate();
            foreach (Target t in c.apps) Validate(t, false);
            if (c.apps.Select(t => t.id).Distinct(StringComparer.OrdinalIgnoreCase).Count() != c.apps.Count) throw new Exception("配置中有重复程序。");
            migrate=MigrateModelTest(c,fields) || migrate;
            migrate=MigrateEnhancement(c,originalApps) || migrate;
            if (migrate) Save(c);
            return c;
        }
        internal static bool MigrateModelTest(Config config,Dictionary<string,object> fields) {
            object previous;if(!fields.TryGetValue("protectAllModels",out previous)) return false;
            if(!(previous is bool)) throw new Exception("旧模型测试配置无效，请恢复配置备份。");
            // The old test overrode each entry; retain its effective scope before removing the field.
            if((bool)previous) foreach(Target target in config.apps) target.apiScope="claude";
            return true;
        }
        internal static bool MigrateEnhancement(Config config,System.Collections.IList originals) {
            bool changed=false;
            for(int i=0;i<config.apps.Count;i++) {
                var fields=originals[i] as Dictionary<string,object>;
                if(fields==null) throw new Exception("程序增强配置格式无效。");
                object value;
                if(!fields.TryGetValue("enhanced",out value)) {
                    config.apps[i].enhanced=config.commandProtection && config.apps[i].enabled;changed=true;
                } else {
                    if(!(value is bool)) throw new Exception("程序增强开关格式无效。");
                    config.apps[i].enhanced=(bool)value;
                }
            }
            bool enabled=config.apps.Any(t=>t.enabled && t.enhanced);
            if(config.commandProtection!=enabled) {config.commandProtection=enabled;changed=true;}
            return changed;
        }
        public static void Save(Config c) {
            Directory.CreateDirectory(DirectoryPath);
            string temp = ConfigPath + ".tmp";
            File.WriteAllText(temp, Json().Serialize(c), new UTF8Encoding(false));
            if (File.Exists(ConfigPath)) File.Replace(temp, ConfigPath, ConfigPath + ".bak");
            else File.Move(temp, ConfigPath);
        }
        public static bool PublicV4(string value) {
            IPAddress ip;
            if (!IPAddress.TryParse(value, out ip) || ip.AddressFamily != AddressFamily.InterNetwork || ip.ToString() != value) return false;
            byte[] b = ip.GetAddressBytes();
            return !(b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224 ||
                (b[0] == 100 && b[1] >= 64 && b[1] <= 127) || (b[0] == 169 && b[1] == 254) ||
                (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && (b[1] == 168 || (b[1] == 0 && (b[2] == 0 || b[2] == 2)))) ||
                (b[0] == 198 && (b[1] == 18 || b[1] == 19 || (b[1] == 51 && b[2] == 100))) ||
                (b[0] == 203 && b[1] == 0 && b[2] == 113));
        }
        public static void Validate(Settings s,bool allowEmpty=false) {
            if (s == null) throw new Exception("请输入有效的防护规则。");
            if(s.expectedIps==null || (!allowEmpty && s.expectedIps.Count==0) || s.expectedIps.Count>BuildInfo.MaxAllowedIps || s.expectedIps.Any(ip=>!PublicV4(ip))) throw new Exception("请填写 1–"+BuildInfo.MaxAllowedIps+" 个有效的公网 IPv4 地址。");
            if(s.expectedIps.Distinct().Count()!=s.expectedIps.Count) throw new Exception("允许的公网 IPv4 地址有重复项。");
            if (s.intervalSeconds < 1 || s.intervalSeconds > 60) throw new Exception("检测间隔应为 1–60 秒。");
        }
        public static void Validate(Target t, bool exists) {
            Guid id;
            if (t == null || !Guid.TryParseExact(t.id, "D", out id)) throw new Exception("程序标识无效。");
            if(t.apiScope!="auto" && t.apiScope!="claude" && t.apiScope!="other") throw new Exception("请选择有效的 API 会话类型。");
            if (String.IsNullOrWhiteSpace(t.name) || t.name.Length > 100) throw new Exception("请输入程序名称。");
            if (String.IsNullOrWhiteSpace(t.path) || t.path.Length > 1024 || !Path.IsPathRooted(t.path) || t.path.IndexOf('"') >= 0 || Path.GetExtension(t.path).ToLowerInvariant() != ".exe") throw new Exception("请选择 EXE 的完整路径。");
            t.path = Path.GetFullPath(t.path);
            if (t.path.StartsWith(@"\\") || (exists && !File.Exists(t.path))) throw new Exception("请选择本机存在的 EXE 文件。");
            t.cli=ClaudeCodeScope.IsCli(t);
            if (t.arguments == null || t.arguments.Length > 4096 || t.arguments.IndexOf('\0') >= 0) throw new Exception("启动参数无效。");
            if(exists && BrowserRetirement.IsBrowser(t.path)) throw new Exception("浏览器防护已移除，请选择 Claude npm、原生版或 Desktop。");
            string name = Path.GetFileName(t.path).ToLowerInvariant();
            if(name=="ipguard.terminal.exe") throw new Exception("启动门卫保留原启动方式。");
            string[] critical = { "ipguard.native.exe", "ip guard.exe", "explorer.exe", "winlogon.exe", "csrss.exe", "services.exe", "lsass.exe", "svchost.exe", "smss.exe", "wininit.exe", "dwm.exe", "taskmgr.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe", "reg.exe", "netsh.exe", "schtasks.exe", "rundll32.exe" };
            if (critical.Contains(name)) throw new Exception("请选择普通应用；系统与恢复工具保留原有启动方式。");
        }
        public static string Quote(string value) {
            StringBuilder b = new StringBuilder("\""); int slashes = 0;
            foreach (char c in value) {
                if (c == '\\') { slashes++; continue; }
                if (c == '"') b.Append('\\', slashes * 2 + 1); else b.Append('\\', slashes);
                b.Append(c); slashes = 0;
            }
            b.Append('\\', slashes * 2); return b.Append('"').ToString();
        }
    }
}
