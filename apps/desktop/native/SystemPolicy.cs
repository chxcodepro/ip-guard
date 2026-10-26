using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using Microsoft.Win32;

namespace IpGuard {
    public sealed class FirewallDisabledException : Exception {
        public const string Code = "firewall_disabled";
        public const string Help = "1. 在管理界面中点击“Windows Defender 防火墙属性”。\n2. 分别打开“域配置文件”“专用配置文件”“公用配置文件”选项卡。\n3. 将各自的“防火墙状态”设为“启用（推荐）”，点击“确定”。\n4. 回到 IP Guard，重新开启程序防护或启动程序。\n\n远程桌面和局域网共享如有需要，请保留相应的入站放行规则。";
        public FirewallDisabledException(string message) : base(message) { }
    }
    public static class SystemPolicy {
        public static readonly string Sid = WindowsIdentity.GetCurrent().User.Value;
        public static readonly string Owner = "IPGuard." + Sid;
        public static readonly string PipeName = "IPGuard-" + Sid;
        public static readonly string Exe = Process.GetCurrentProcess().MainModule.FileName;
        const string Ifeo = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        public static bool Admin { get { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); } }
        public static void RequireAdmin() { if (!Admin) throw new Exception("请以管理员身份运行 IP Guard。"); }
        static RegistryView[] Views { get { return new[] { RegistryView.Registry64, RegistryView.Registry32 }; } }
        public static void Intercept(Target app) {
            RequireAdmin(); Data.Validate(app, true);
            PackageIdentity package=PackagePolicy.Find(app.path);
            if(package!=null) { Unintercept(app); PackagePolicy.Enable(app,package); return; }
            foreach (RegistryView view in Views) {
                using (RegistryKey root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view))
                using (RegistryKey parent = root.CreateSubKey(Ifeo + "\\" + Path.GetFileName(app.path))) {
                    if (parent.GetValue("Debugger") != null) throw new Exception("该程序已有 IFEO Debugger，请先处理现有拦截配置。");
                    string childName = "IPGuard_" + app.id;
                    foreach (string otherName in parent.GetSubKeyNames()) {
                        using (RegistryKey other = parent.OpenSubKey(otherName)) {
                            if (otherName != childName && (other.GetValue("FilterFullPath") == null || String.Equals(other.GetValue("FilterFullPath") as string, app.path, StringComparison.OrdinalIgnoreCase))) throw new Exception("该程序已有冲突的 IFEO 过滤项。");
                            if (otherName != childName && !otherName.StartsWith("IPGuard_") && Convert.ToInt32(parent.GetValue("UseFilter",0)) == 0) throw new Exception("该程序存在尚未启用的外部过滤项，请先检查 IFEO。");
                        }
                    }
                    if (parent.GetValue("IPGuardPreviousUseFilter") == null) parent.SetValue("IPGuardPreviousUseFilter", parent.GetValue("UseFilter") == null ? -1 : Convert.ToInt32(parent.GetValue("UseFilter")), RegistryValueKind.DWord);
                    using (RegistryKey child = parent.CreateSubKey(childName)) {
                        object existingOwner = child.GetValue("IPGuardOwner");
                        if (existingOwner != null && (string)existingOwner != Owner) throw new Exception("该拦截项属于其他用户。");
                        child.SetValue("IPGuardOwner", Owner);
                        child.SetValue("FilterFullPath", app.path);
                        child.SetValue("Debugger", Data.Quote(Exe) + " gate " + Sid + " " + app.id);
                    }
                    parent.SetValue("UseFilter", 1, RegistryValueKind.DWord);
                }
            }
        }
        public static void Unintercept(Target app) {
            RequireAdmin();
            PackagePolicy.Disable(app.id);
            foreach (RegistryView view in Views) {
                using (RegistryKey root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view))
                using (RegistryKey parent = root.OpenSubKey(Ifeo + "\\" + Path.GetFileName(app.path), true)) {
                    if (parent == null) continue;
                    string name = "IPGuard_" + app.id;
                    using (RegistryKey child = parent.OpenSubKey(name)) {
                        if (child != null && child.GetValue("IPGuardOwner") as string != Owner) throw new Exception("拦截项所有者已改变，请手动检查。");
                    }
                    parent.DeleteSubKeyTree(name, false); RestoreFilter(parent);
                }
            }
        }
        static void RestoreFilter(RegistryKey parent) {
            if (parent.GetSubKeyNames().Any(n => n.StartsWith("IPGuard_", StringComparison.Ordinal))) return;
            object previous = parent.GetValue("IPGuardPreviousUseFilter");
            if (previous == null) return;
            if (Convert.ToInt32(parent.GetValue("UseFilter", 0)) == 1) {
                if (Convert.ToInt32(previous) == -1) parent.DeleteValue("UseFilter", false);
                else parent.SetValue("UseFilter", Convert.ToInt32(previous), RegistryValueKind.DWord);
            }
            parent.DeleteValue("IPGuardPreviousUseFilter", false);
        }
        static dynamic Firewall() { return Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)); }
        public static void FirewallHealthy() {
            dynamic p = Firewall();
            if ((int)p.LocalPolicyModifyState != 0) throw new Exception("系统策略覆盖了本地防火墙规则，请检查组织策略。");
            List<string> disabled = new List<string>();
            foreach (var profile in new[] { new { id=1,name="域" }, new { id=2,name="专用" }, new { id=4,name="公用" } })
                if (!p.FirewallEnabled[profile.id]) disabled.Add(profile.name);
            if (disabled.Count > 0) throw new FirewallDisabledException("Windows 防火墙的" + String.Join("、", disabled) + "配置文件已关闭。");
        }
        public static void OpenFirewall() {
            Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory,"wf.msc")) { UseShellExecute = true });
        }
        static string RuleName(Target app, string kind) { return Owner + "." + app.id + "." + kind; }
        static void RemoveRules(dynamic policy, Target app, params string[] kinds) {
            foreach(string kind in kinds) {
                string name=RuleName(app,kind); dynamic rule;
                try { rule=policy.Rules.Item(name); }
                catch(FileNotFoundException) { continue; }
                if((string)rule.Grouping==Owner && String.Equals((string)rule.ApplicationName,app.path,StringComparison.OrdinalIgnoreCase)) policy.Rules.Remove(name);
            }
        }
        public static void Block(Target app, bool blocked) {
            RequireAdmin();
            dynamic policy = Firewall();
            RemoveRules(policy,app,"v6out","v6in");
            foreach (string kind in new[] { "out", "in" }) {
                string name = RuleName(app, kind); dynamic rule;
                try { rule = policy.Rules.Item(name); }
                catch (FileNotFoundException) {
                    rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", true));
                    rule.Name = name; rule.Grouping = Owner; rule.ApplicationName = app.path;
                    rule.Direction = kind.EndsWith("out") ? 2 : 1; rule.Action = 0;
                    rule.Protocol = 256; rule.Profiles = 7; rule.InterfaceTypes = "All";
                    rule.Enabled = true; policy.Rules.Add(rule);
                }
                if ((string)rule.Grouping != Owner || !String.Equals((string)rule.ApplicationName, app.path, StringComparison.OrdinalIgnoreCase)) throw new Exception("防火墙规则发生冲突。");
                if((bool)rule.Enabled!=blocked) rule.Enabled = blocked;
            }
        }
        public static void RemoveFirewall(Target app) {
            RemoveRules(Firewall(),app,"out","in","v6out","v6in");
        }
        public static void Autostart(bool enable, string appExe) {
            RequireAdmin();
            dynamic service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service", true)); service.Connect();
            dynamic folder = service.GetFolder("\\"); string name = Owner;
            if (!enable) {
                try { folder.DeleteTask(name, 0); }
                catch (System.Runtime.InteropServices.COMException e) { if ((uint)e.HResult != 0x80070002) throw; }
                return;
            }
            if (!File.Exists(appExe) || Path.GetExtension(appExe).ToLowerInvariant() != ".exe") throw new Exception("开机启动需要已安装的桌面程序。");
            dynamic task = service.NewTask(0); task.RegistrationInfo.Description = "IP Guard";
            task.Principal.UserId = Sid; task.Principal.LogonType = 3; task.Principal.RunLevel = 1;
            task.Settings.Enabled = true; task.Settings.StartWhenAvailable = true;
            task.Settings.DisallowStartIfOnBatteries = false; task.Settings.StopIfGoingOnBatteries = false;
            task.Settings.ExecutionTimeLimit = "PT0S"; task.Settings.MultipleInstances = 2;
            dynamic trigger = task.Triggers.Create(9); trigger.UserId = Sid; trigger.Enabled = true;
            dynamic action = task.Actions.Create(0); action.Path = appExe; action.Arguments = "--background"; action.WorkingDirectory = Path.GetDirectoryName(appExe);
            folder.RegisterTaskDefinition(name, task, 6, Sid, null, 3, null);
        }
        public static void Recover() {
            RequireAdmin();
            PackagePolicy.Recover();
            foreach (RegistryView view in Views) {
                using (RegistryKey root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view))
                using (RegistryKey ifeo = root.OpenSubKey(Ifeo, true)) {
                    if (ifeo == null) continue;
                    foreach (string image in ifeo.GetSubKeyNames()) using (RegistryKey parent = ifeo.OpenSubKey(image, true)) {
                        foreach (string name in parent.GetSubKeyNames()) {
                            bool own;
                            using (RegistryKey child = parent.OpenSubKey(name)) own = child.GetValue("IPGuardOwner") as string == Owner;
                            if (own) parent.DeleteSubKeyTree(name, false);
                        }
                        RestoreFilter(parent);
                    }
                }
            }
            dynamic p = Firewall(); List<string> remove = new List<string>();
            foreach (dynamic r in p.Rules) if ((string)r.Grouping == Owner) remove.Add((string)r.Name);
            foreach (string n in remove) p.Rules.Remove(n);
            Autostart(false, null);
            Config c = new Config();
            if (File.Exists(Data.ConfigPath)) File.Copy(Data.ConfigPath, Data.ConfigPath + ".recovery.bak", true);
            Data.Save(c);
        }
    }
}
