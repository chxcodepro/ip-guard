using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Web.Script.Serialization;

namespace IpGuard {
    internal sealed class ClaudeProxySettings : IDisposable {
        internal readonly string[] Arguments;
        string file;
        static JavaScriptSerializer Json() {return new JavaScriptSerializer {MaxJsonLength=2097152};}
        internal static int SettingsIndex(string[] args) {
            int found=-1;
            for(int i=1;i<args.Length;i++) {
                string arg=args[i];if(arg=="--") break;
                if(!arg.StartsWith("-",StringComparison.Ordinal)) continue;
                int equal=arg.IndexOf('=');string name=equal<0 ? arg : arg.Substring(0,equal);
                if(name=="--settings") {
                    if(found>=0) throw new InvalidDataException("启动参数包含重复 --settings，请合并为一份设置后重试。");
                    if(equal<0 && i+1>=args.Length) throw new InvalidDataException("--settings 缺少设置值。");
                    found=i;if(equal<0) i++;
                } else if(equal<0 && ClaudeCodeScope.TakesValue(name)) {
                    if(i+1<args.Length) i++;
                } else if(equal<0 && !ClaudeCodeScope.IsSwitch(name) &&
                    !new[] {"--resume","-r","--continue","-c","--fork-session"}.Contains(name) && i+1<args.Length &&
                    (args[i+1]=="--settings" || args[i+1].StartsWith("--settings=",StringComparison.Ordinal))) {
                    // shortcut: unknown option arity is ambiguous here; extend the shared grammar when that CLI option is supported.
                    throw new InvalidDataException("无法区分 "+name+" 的参数值与 --settings，请使用 "+name+"=值 的形式后重试。");
                }
            }
            return found;
        }
        internal static string Merge(string source,EgressPolicy policy) {
            Dictionary<string,object> settings;
            try {settings=source==null ? new Dictionary<string,object>() : Json().Deserialize<Dictionary<string,object>>(source);}
            catch(ArgumentException) {throw new InvalidDataException("--settings JSON 格式无效，请检查启动参数。");}
            catch(InvalidOperationException) {throw new InvalidDataException("--settings JSON 格式无效，请检查启动参数。");}
            if(settings==null) throw new InvalidDataException("--settings 须为 JSON 对象。");
            object existing;
            var environment=new Dictionary<string,object>(StringComparer.Ordinal);
            if(settings.TryGetValue("env",out existing)) {
                var original=existing as Dictionary<string,object>;
                if(original==null || original.Any(entry=>!(entry.Value is string))) throw new InvalidDataException("--settings 的 env 须为字符串对象。");
                foreach(var entry in original) environment.Add(entry.Key,entry.Value);
            }
            var proxy=EgressEnvironment.ProxyVariables(policy);
            foreach(string key in environment.Keys.Where(key=>proxy.Keys.Contains(key,StringComparer.OrdinalIgnoreCase)).ToArray()) environment.Remove(key);
            foreach(var entry in proxy) environment[entry.Key]=entry.Value;
            settings["env"]=environment;
            return Json().Serialize(settings);
        }
        internal static string[] Replace(string[] args,int index,string path) {
            if(args.Length==0 || String.IsNullOrEmpty(args[0])) throw new InvalidDataException("CLI 启动参数缺失。");
            var result=args.ToList();
            if(index>=0) {
                bool inline=args[index].StartsWith("--settings=",StringComparison.Ordinal);
                result.RemoveRange(index,inline ? 1 : 2);
            }
            result.InsertRange(1,new[] {"--settings",path});
            return result.ToArray();
        }
        internal ClaudeProxySettings(string[] args,EgressPolicy policy) {
            int index=SettingsIndex(args);
            string source=null;
            if(index>=0) {
                string selected=args[index].StartsWith("--settings=",StringComparison.Ordinal) ? args[index].Substring("--settings=".Length) : args[index+1];
                source=selected.TrimStart().StartsWith("{",StringComparison.Ordinal) ? selected : ClaudeCodeScope.ReadSettingsFile(selected,2097152);
                if(source==null) throw new FileNotFoundException("--settings 文件不存在，请检查启动参数。");
            }
            string merged=Merge(source,policy);
            string directory=Path.Combine(Data.DirectoryPath,"session-settings");
            foreach(string folder in new[] {Data.DirectoryPath,directory}) {
                Directory.CreateDirectory(folder);
                if((File.GetAttributes(folder)&FileAttributes.ReparsePoint)!=0) throw new IOException("会话设置目录包含链接，请检查后重试。");
            }
            string temporary=Path.Combine(directory,Guid.NewGuid().ToString("N")+".json");
            var access=new FileSecurity();
            var owner=new SecurityIdentifier(SystemPolicy.Sid);
            access.SetAccessRuleProtection(true,false);access.SetOwner(owner);
            access.AddAccessRule(new FileSystemAccessRule(owner,FileSystemRights.FullControl,AccessControlType.Allow));
            access.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),FileSystemRights.FullControl,AccessControlType.Allow));
            bool created=false;
            try {
                using(var stream=new FileStream(temporary,FileMode.CreateNew,FileSystemRights.Write,FileShare.Read,4096,FileOptions.None,access)) {
                    created=true;using(var writer=new StreamWriter(stream,new UTF8Encoding(false))) writer.Write(merged);
                }
                file=temporary;Arguments=Replace(args,index,temporary);
            } catch {if(created) File.Delete(temporary);throw;}
        }
        public void Dispose() {
            if(file==null) return;
            try {File.Delete(file);file=null;}
            catch(IOException) {Console.Error.WriteLine("IP Guard · 会话设置清理失败，请在关闭 Claude 后清理 session-settings 目录。");}
            catch(UnauthorizedAccessException) {Console.Error.WriteLine("IP Guard · 会话设置清理权限不足，请在关闭 Claude 后清理 session-settings 目录。");}
        }
    }
}
