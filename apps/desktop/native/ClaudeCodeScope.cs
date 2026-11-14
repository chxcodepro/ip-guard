using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace IpGuard {
    public sealed class ModelEvidence {
        public string apiBase="",model="";
        public bool cloud,unknown;
    }
    public sealed class ModelDecision {
        public string kind,reason;
        public bool Other {get {return kind=="other";}}
        public ModelDecision(string kind,string reason) {this.kind=kind;this.reason=reason;}
    }
    public static class ClaudeCodeScope {
        static readonly string[] Variables={"ANTHROPIC_BASE_URL","ANTHROPIC_MODEL","ANTHROPIC_DEFAULT_MODEL","ANTHROPIC_DEFAULT_SONNET_MODEL","ANTHROPIC_DEFAULT_OPUS_MODEL","ANTHROPIC_DEFAULT_HAIKU_MODEL","CLAUDE_CODE_USE_BEDROCK","CLAUDE_CODE_USE_VERTEX","CLAUDE_CODE_USE_FOUNDRY"};
        public static bool IsCli(Target target) {
            if(!String.Equals(Path.GetFileName(target.path),"claude.exe",StringComparison.OrdinalIgnoreCase) || !File.Exists(target.path)) return false;
            try {return TerminalProcess.IsConsole(target.path);} catch(IOException) {return false;} catch(UnauthorizedAccessException) {return false;}
        }
        static bool Flag(string value) {return !String.IsNullOrEmpty(value) && value!="0" && !String.Equals(value,"false",StringComparison.OrdinalIgnoreCase);}
        internal static bool LocalGateway(ModelEvidence evidence) {
            Uri uri;System.Net.IPAddress ip;
            if(evidence==null || !Uri.TryCreate(evidence.apiBase,UriKind.Absolute,out uri)) return false;
            if(uri.IsLoopback) return true;
            if(!System.Net.IPAddress.TryParse(uri.DnsSafeHost.Trim('[',']'),out ip)) return false;
            if(ip.IsIPv4MappedToIPv6) ip=ip.MapToIPv4();
            if(ip.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork) return !Data.PublicV4(ip.ToString());
            return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || (ip.GetAddressBytes()[0]&0xfe)==0xfc || ip.Equals(System.Net.IPAddress.IPv6Any);
        }
        internal static ModelDecision Classify(string selection,bool strict,ModelEvidence evidence) {
            if(strict) return new ModelDecision("claude","严格命令过滤已启用");
            if(selection=="claude") return new ModelDecision("claude","当前会话执行基础 IPv4 防护");
            if(selection=="other") return new ModelDecision("other","按原有会话范围使用原网络");
            if(selection!="auto" || evidence==null || evidence.unknown) return new ModelDecision("unknown","未能自动识别 API 配置，当前按锁定的出口保护");
            if(evidence.model==null || evidence.model.Length>200 || evidence.model.Any(Char.IsControl)) return new ModelDecision("unknown","模型标识无效，按 Claude 保护");
            if(evidence.cloud) return new ModelDecision("claude","云提供商 Claude 会话");
            if(String.IsNullOrEmpty(evidence.apiBase)) return new ModelDecision("claude","Claude 官方 API");
            Uri address;
            if(evidence.apiBase.Length>2048 || !Uri.TryCreate(evidence.apiBase,UriKind.Absolute,out address) || (address.Scheme!="http" && address.Scheme!="https") || address.UserInfo!="" || address.Query!="" || address.Fragment!="") return new ModelDecision("unknown","API 地址未能识别，按 Claude 保护");
            string host=address.DnsSafeHost.TrimEnd('.').ToLowerInvariant();
            if(host=="api.anthropic.com") return new ModelDecision("claude","Claude 官方 API");
            if(host=="api.deepseek.com" && address.Scheme=="https") return new ModelDecision("other","DeepSeek API 会话");
            string model=evidence.model.ToLowerInvariant();
            if(model.Contains("claude") || new[] {"sonnet","opus","haiku","opusplan"}.Any(alias=>model==alias || model.StartsWith(alias+"[",StringComparison.Ordinal))) return new ModelDecision("claude","网关 Claude 模型："+evidence.model);
            string[] others={"deepseek","gpt-","gemini","qwen","glm-","kimi","minimax","llama","mistral","moonshot"};
            if(model.Split('/').Any(part=>others.Any(prefix=>part.StartsWith(prefix,StringComparison.Ordinal)))) return new ModelDecision("other","其他模型会话："+evidence.model);
            return new ModelDecision("unknown","网关模型未能识别，当前按锁定的出口保护");
        }
        static readonly string[] SelectedOptions={"--model","--settings","--setting-sources"};
        static readonly string[] SwitchOptions={"-p","--print","-h","--help","-v","--version","--verbose","--ide","--strict-mcp-config","--no-session-persistence","--dangerously-skip-permissions","--allow-dangerously-skip-permissions"};
        static readonly string[] ValueOptions={"--system-prompt","--append-system-prompt","--system-prompt-file","--append-system-prompt-file","--json-schema","--output-format","--input-format","--permission-mode","--session-id","--name","--max-turns","--max-budget-usd"};
        internal static bool TakesValue(string name) {return SelectedOptions.Contains(name) || ValueOptions.Contains(name);}
        internal static bool IsSwitch(string name) {return SwitchOptions.Contains(name);}
        internal static Dictionary<string,string> Options(string[] args) {
            var result=new Dictionary<string,string>(StringComparer.Ordinal);
            for(int i=1;i<args.Length;i++) {
                string arg=args[i];if(arg=="--") break;
                if(!arg.StartsWith("-",StringComparison.Ordinal)) continue;
                int separator=arg.IndexOf('=');string name=separator<0 ? arg : arg.Substring(0,separator);
                if(IsSwitch(name) && separator<0) continue;
                if(!TakesValue(name)) throw new InvalidDataException("启动选项需手动标记 API 类型。");
                if(separator<0 && i+1>=args.Length) throw new InvalidDataException("缺少启动选项值。");
                if(SelectedOptions.Contains(name)) {
                    if(result.ContainsKey(name)) throw new InvalidDataException("启动选项重复。");
                    result.Add(name,separator<0 ? args[i+1] : arg.Substring(separator+1));
                }
                if(separator<0) i++;
            }
            return result;
        }
        static string Option(Dictionary<string,string> options,string name) {string value;return options.TryGetValue(name,out value) ? value : null;}
        static void Apply(string json,Dictionary<string,string> environment,ref string model) {
            if(json.Length>1048576) throw new InvalidDataException("设置文件过大。");
            var settings=Data.Json().Deserialize<Dictionary<string,object>>(json);
            if(settings==null) throw new InvalidDataException("设置格式无效。");
            object value;
            if(settings.TryGetValue("model",out value)) {if(!(value is string)) throw new InvalidDataException("模型设置无效。");model=(string)value;}
            if(settings.TryGetValue("env",out value)) {
                var values=value as Dictionary<string,object>;if(values==null) throw new InvalidDataException("环境设置无效。");
                if(values.Keys.Any(key=>String.Equals(key,"CLAUDE_CONFIG_DIR",StringComparison.OrdinalIgnoreCase))) throw new InvalidDataException("设置目录覆盖须手动标记。");
                var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach(var entry in values) if(Variables.Contains(entry.Key,StringComparer.OrdinalIgnoreCase)) {
                    if(!seen.Add(entry.Key) || !(entry.Value is string)) throw new InvalidDataException("环境变量格式无效。");environment[entry.Key]=(string)entry.Value;
                }
            }
        }
        internal static string ReadSettingsFile(string file,int maxBytes=1048576) {
            file=Path.GetFullPath(file);
            if(file.StartsWith(@"\\",StringComparison.Ordinal) || new DriveInfo(Path.GetPathRoot(file)).DriveType==DriveType.Network) throw new InvalidDataException("远程设置须手动标记。");
            // Metadata inspection must not connect to a linked or remote settings location before the IP gate.
            var parents=new Stack<string>();for(var parent=new DirectoryInfo(Path.GetDirectoryName(file));parent!=null;parent=parent.Parent) parents.Push(parent.FullName);
            try {
                foreach(string parent in parents) if((File.GetAttributes(parent)&FileAttributes.ReparsePoint)!=0) throw new InvalidDataException("链接设置目录须手动标记。");
                FileAttributes attributes=File.GetAttributes(file);if((attributes&FileAttributes.ReparsePoint)!=0) throw new InvalidDataException("链接设置文件须手动标记。");
            } catch(FileNotFoundException) {return null;} catch(DirectoryNotFoundException) {return null;}
            if(new FileInfo(file).Length>maxBytes) throw new InvalidDataException("设置文件过大。");
            return File.ReadAllText(file);
        }
        static bool ApplyFile(string file,Dictionary<string,string> environment,ref string model) {
            string json=ReadSettingsFile(file);
            if(json==null) return false;
            Apply(json,environment,ref model);return true;
        }
        static string ProjectRoot(string cwd) {
            for(var current=new DirectoryInfo(cwd);current!=null;current=current.Parent) if(Directory.Exists(Path.Combine(current.FullName,".git")) || File.Exists(Path.Combine(current.FullName,".git"))) return current.FullName;
            return cwd;
        }
        static bool Managed() {
            string home=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"ClaudeCode");
            if(File.Exists(Path.Combine(home,"managed-settings.json")) || Directory.Exists(Path.Combine(home,"managed-settings.d"))) return true;
            foreach(RegistryHive hive in new[] {RegistryHive.LocalMachine,RegistryHive.CurrentUser}) using(RegistryKey root=RegistryKey.OpenBaseKey(hive,RegistryView.Registry64)) using(RegistryKey key=root.OpenSubKey(@"SOFTWARE\Policies\ClaudeCode")) if(key!=null && key.GetValueNames().Any(name=>String.Equals(name,"Settings",StringComparison.OrdinalIgnoreCase))) return true;
            return false;
        }
        public static ModelEvidence Read(string[] args) {
            try {
                string entry=Environment.GetEnvironmentVariable("CLAUDE_CODE_ENTRYPOINT") ?? "";
                string[] changedSources={"--worktree","-w","--bare","--cwd","--cd","--directory","--workspace","-C"};
                if(Managed() || entry.IndexOf("sdk",StringComparison.OrdinalIgnoreCase)>=0 || !String.IsNullOrEmpty(Environment.GetEnvironmentVariable("CLAUDE_CODE_REMOTE_SESSION_ID")) || args.Any(arg=>changedSources.Any(flag=>arg==flag || arg.StartsWith(flag+"=",StringComparison.Ordinal)))) return new ModelEvidence {unknown=true};
                var options=Options(args);
                var env=Variables.ToDictionary(key=>key,key=>Environment.GetEnvironmentVariable(key) ?? "",StringComparer.OrdinalIgnoreCase);
                string config=Environment.GetEnvironmentVariable("CLAUDE_CONFIG_DIR");
                if(String.IsNullOrEmpty(config)) config=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),".claude");
                string sources=Option(options,"--setting-sources");var enabled=new HashSet<string>((sources ?? "user,project,local").Split(new[] {','},StringSplitOptions.RemoveEmptyEntries));
                if(enabled.Any(source=>source!="user" && source!="project" && source!="local")) return new ModelEvidence {unknown=true};
                string model="",project=Path.Combine(ProjectRoot(Environment.CurrentDirectory),".claude");
                if(enabled.Contains("user")) ApplyFile(Path.Combine(config,"settings.json"),env,ref model);
                if(enabled.Contains("project")) ApplyFile(Path.Combine(project,"settings.json"),env,ref model);
                if(enabled.Contains("local")) ApplyFile(Path.Combine(project,"settings.local.json"),env,ref model);
                string extra=Option(options,"--settings");if(extra!=null) {
                    if(extra.TrimStart().StartsWith("{",StringComparison.Ordinal)) Apply(extra,env,ref model);
                    else if(!ApplyFile(extra,env,ref model)) return new ModelEvidence {unknown=true};
                }
                if(!String.IsNullOrEmpty(env["ANTHROPIC_MODEL"])) model=env["ANTHROPIC_MODEL"];
                if(String.IsNullOrEmpty(model)) model=env["ANTHROPIC_DEFAULT_MODEL"];
                string cliModel=Option(options,"--model");if(cliModel!=null) model=cliModel;
                foreach(string alias in new[] {"sonnet","opus","haiku"}) if(model==alias && !String.IsNullOrEmpty(env["ANTHROPIC_DEFAULT_"+alias.ToUpperInvariant()+"_MODEL"])) model=env["ANTHROPIC_DEFAULT_"+alias.ToUpperInvariant()+"_MODEL"];
                string origin=env["ANTHROPIC_BASE_URL"];if(!String.IsNullOrEmpty(origin)) {
                    Uri uri;if(origin.Length>2048 || !Uri.TryCreate(origin,UriKind.Absolute,out uri) || (uri.Scheme!="https" && uri.Scheme!="http") || uri.UserInfo!="" || uri.Query!="" || uri.Fragment!="") return new ModelEvidence {unknown=true};
                    origin=uri.GetLeftPart(UriPartial.Authority);
                }
                return new ModelEvidence {apiBase=origin,model=model,cloud=Variables.Where(key=>key.StartsWith("CLAUDE_CODE_USE_",StringComparison.Ordinal)).Any(key=>Flag(env[key]))};
            } catch(IOException) {return new ModelEvidence {unknown=true};}
            catch(UnauthorizedAccessException) {return new ModelEvidence {unknown=true};}
            catch(ArgumentException) {return new ModelEvidence {unknown=true};}
            catch(InvalidOperationException) {return new ModelEvidence {unknown=true};}
            catch(System.Security.SecurityException) {return new ModelEvidence {unknown=true};}
        }
        public static ModelDecision Decide(Target target,bool strict,ModelEvidence evidence) {return IsCli(target) ? Classify(target.apiScope,strict,evidence) : new ModelDecision("claude","受保护程序");}
        public static string PrepareOtherImage(Target target) {
            var source=new FileInfo(ProcessTreeMetadata.CanonicalPath(target.path));source.Refresh();
            string generation=source.LastWriteTimeUtc.Ticks+"-"+source.Length;
            string home=Path.Combine(Data.DirectoryPath,"model-sessions",target.id),directory=Path.Combine(home,generation),image=Path.Combine(directory,"claude.exe");
            using(var mutex=new System.Threading.Mutex(false,@"Local\IPGuard-ModelCopy-"+SystemPolicy.Sid+"-"+target.id)) {
                bool held;try {held=mutex.WaitOne(15000);} catch(System.Threading.AbandonedMutexException) {held=true;}
                if(!held) throw new IOException("CLI 会话副本正在准备，请稍后再试。");
                try {
                    foreach(string folder in new[] {Data.DirectoryPath,Path.Combine(Data.DirectoryPath,"model-sessions"),home,directory}) {
                        Directory.CreateDirectory(folder);if((File.GetAttributes(folder)&FileAttributes.ReparsePoint)!=0) throw new IOException("CLI 会话目录包含重解析点，停止启动。");
                    }
                    if(File.Exists(image)) {var existing=new FileInfo(image);if((existing.Attributes&FileAttributes.ReparsePoint)!=0 || existing.Length!=source.Length) throw new IOException("CLI 会话副本无效，请关闭该会话后删除缓存文件再试："+image);return image;}
                    string temp=Path.Combine(directory,"copy-"+Guid.NewGuid().ToString("N")+".tmp");
                    try {
                        using(var input=new FileStream(source.FullName,FileMode.Open,FileAccess.Read,FileShare.Read)) using(var output=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None)) {
                            if(input.Length!=source.Length) throw new IOException("CLI 正在更新，请稍后重试。");input.CopyTo(output);
                        }
                        File.Move(temp,image);
                    } finally {if(File.Exists(temp)) File.Delete(temp);}
                    foreach(string old in Directory.GetDirectories(home)) {
                        if(old==directory || !System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(old),@"^\d+-\d+$") || (File.GetAttributes(old)&FileAttributes.ReparsePoint)!=0) continue;
                        try {File.Delete(Path.Combine(old,"claude.exe"));Directory.Delete(old);}
                        // Running older sessions retain their mapped image until they exit.
                        catch(IOException) {} catch(UnauthorizedAccessException) {}
                    }
                    return image;
                } finally {mutex.ReleaseMutex();}
            }
        }
    }
}
