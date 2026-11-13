using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Web.Script.Serialization;
using Microsoft.Win32;

namespace IpGuard {
    public sealed class EgressPolicy {
        public string id,label;
        public int port;
        [ScriptIgnore] public string Url { get {return "http://127.0.0.1:"+port;} }
        public void Validate() {
            Guid parsed;
            if(!Guid.TryParseExact(id,"D",out parsed) || String.IsNullOrWhiteSpace(label) || label.Length>100 || port<1024 || port>65535) throw new Exception("固定出口配置无效。");
        }
        public static void ValidateTarget(Target target) {
            if(ClaudeChrome.IsPath(target.path)) return;
            if(PackagePolicy.IsClaudeDesktop(target.path)) {
                FileVersionInfo version=FileVersionInfo.GetVersionInfo(target.path);
                if(new Version(version.FileMajorPart,version.FileMinorPart,Math.Max(0,version.FileBuildPart))<new Version(1,44121,1)) throw new Exception("此 Claude Desktop 版本尚未支持固定代理策略，请先升级 Desktop。");
            } else if(!String.Equals(Path.GetFileName(target.path),"claude.exe",StringComparison.OrdinalIgnoreCase) || !TerminalProcess.IsConsole(target.path)) throw new Exception("固定出口目前支持 Claude Desktop、npm Claude 与原生 claude.exe。");
        }
    }
    public sealed class EgressEnvironment : IDisposable {
        public IntPtr pointer;
        public uint flags;
        public EgressEnvironment(EgressPolicy policy) {
            if(policy==null) return;
            var values=new SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase);
            foreach(DictionaryEntry item in Environment.GetEnvironmentVariables()) values[(string)item.Key]=(string)item.Value;
            values["HTTP_PROXY"]=policy.Url; values["HTTPS_PROXY"]=policy.Url; values["ALL_PROXY"]=policy.Url; values["NO_PROXY"]="";
            pointer=Marshal.StringToHGlobalUni(String.Join("\0",values.Select(entry=>entry.Key+"="+entry.Value))+"\0\0");flags=0x400;
        }
        public void Dispose() {if(pointer!=IntPtr.Zero) {Marshal.FreeHGlobal(pointer);pointer=IntPtr.Zero;}}
    }
    public static class DesktopProxyPolicy {
        const string Policy=@"SOFTWARE\Policies\Claude", Owned=@"SOFTWARE\IPGuard\DesktopFixedProxy";
        public static void Apply(string url) {
            if(url==null) {Restore();return;}
            using(RegistryKey machine=Registry.LocalMachine.OpenSubKey(Policy)) if(machine!=null && (machine.ValueCount>0 || machine.SubKeyCount>0)) throw new Exception("Claude 已受计算机策略管理，请先由管理员配置专用出口。");
            using(RegistryKey settings=Registry.CurrentUser.CreateSubKey(Policy)) using(RegistryKey owned=Registry.CurrentUser.CreateSubKey(Owned)) {
                if(!String.IsNullOrEmpty(settings.GetValue("egressProxyPacUrl") as string)) throw new Exception("Claude 已设置 PAC 策略，请先移除冲突后再启用固定出口。");
                string previousOwned=owned.GetValue("url") as string;
                string previousUrl=owned.GetValue("previousUrl") as string;
                object current=settings.GetValue("egressProxyUrl");
                if(previousOwned!=null && (current as string)!=previousOwned && (current as string)!=previousUrl) throw new Exception("Claude 代理策略已被外部修改，请先关闭固定出口再重新配置。");
                if(previousOwned==null) {
                    if(current!=null && !(current is string)) throw new Exception("Claude 现有代理策略类型无效，已保留原值。");
                    owned.SetValue("existed",current==null ? 0 : 1,RegistryValueKind.DWord);
                    owned.SetValue("previous",current as string ?? "",RegistryValueKind.String);
                }
                owned.SetValue("previousUrl",current as string ?? "",RegistryValueKind.String);
                owned.SetValue("url",url,RegistryValueKind.String);owned.Flush();
                settings.SetValue("egressProxyUrl",url,RegistryValueKind.String);
            }
        }
        public static void Restore() {
            using(RegistryKey owned=Registry.CurrentUser.OpenSubKey(Owned)) {
                if(owned==null) return;
                string url=owned.GetValue("url") as string;
                string previousUrl=owned.GetValue("previousUrl") as string;
                using(RegistryKey settings=Registry.CurrentUser.OpenSubKey(Policy,true)) if(settings!=null && url!=null && ((settings.GetValue("egressProxyUrl") as string)==url || (!String.IsNullOrEmpty(previousUrl) && (settings.GetValue("egressProxyUrl") as string)==previousUrl))) {
                    if((int)owned.GetValue("existed",0)==1) settings.SetValue("egressProxyUrl",(string)owned.GetValue("previous",""),RegistryValueKind.String);
                    else settings.DeleteValue("egressProxyUrl",false);
                }
            }
            Registry.CurrentUser.DeleteSubKeyTree(Owned,false);
        }
    }
}
