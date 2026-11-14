using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace IpGuard {
    public sealed class Session {
        public string appId;
        public string name;
        public IntPtr job;
        public int epoch;
        public volatile bool stopped;
        public bool otherModel;
        public bool enhanced;
    }
    public sealed class Guard {
        readonly object state = new object(), actions = new object(), output = new object();
        readonly List<Session> sessions = new List<Session>();
        readonly HashSet<string> staleDesktopPaths=new HashSet<string>();
        readonly List<object> logs = new List<object>();
        readonly Config config;
        readonly EgressPolicy enhancementPolicy;
        EgressPolicy EnhancementRoute {get {return config.egress ?? enhancementPolicy;}}
        readonly string desktopExe;
        StartupStatus startup=new StartupStatus();
        readonly WifiWatch wifi;
        readonly ClaudeProbe probe;
        readonly ProcessNetwork.KernelProtection commandGuard;
        string commandBlockId="",commandBlockReason="",commandBlockAppId="";
        readonly BlockingCollection<Dictionary<string,object>> commands=new BlockingCollection<Dictionary<string,object>>();
        AdapterInfo[] adapters=new AdapterInfo[0];
        AdapterInfo watchedAdapter=new AdapterInfo { id="",name="正在检测网卡",exists=false };
        bool healthy, pendingBlock, checking;
        bool enhancementReady;
        string enhancementReason="等待增强出口复核";
        string enhancementPhase="idle";
        volatile bool quit;
        string currentIp = "", reason = "请先锁定允许的公网 IPv4", checkedAt = "", topology = "";
        int epoch,networkRevision;
        string networkIssue="idle";
        int probeRound,probeAttempt;
        string probePhase="idle";
        int checkRequested;
        string detection = "";
        string egressIssue = "";
        long lastVerified;
        DateTime nextCheck = DateTime.MinValue;
        public Guard(string desktopExe,EgressPolicy enhancementPolicy=null) { this.desktopExe=desktopExe;this.enhancementPolicy=enhancementPolicy; config = Data.Load(); SystemPolicy.FixedProxyPort=config.egress==null ? 0 : config.egress.port;SystemPolicy.EnhancedProxyPort=EnhancementRoute==null ? 0 : EnhancementRoute.port; wifi = new WifiWatch(why => Observe(why, true)); probe=new ClaudeProbe(Emit); commandGuard=new ProcessNetwork.KernelProtection(allowed=>Publish()); RefreshAdapters(); }
        void RequireCommandChangesClosed(string except=null) {
            if(!config.commandProtection) return;
            foreach(Target app in config.apps.Where(t=>t.enabled && t.enhanced && t.id!=except)) RequireClosed(app);
            if(sessions.Any(s=>!s.stopped && s.enhanced && s.appId!=except)) throw new Exception("请先停止已开启增强的程序，再更改过滤配置。");
        }
        void LoadCommandGuard(bool recover=false) {
            if(!config.commandProtection) return;
            try {commandGuard.Start(EnhancementRoute,config.apps.Where(t=>t.enhanced),recover);commandGuard.Allow(healthy && enhancementReady);}
            catch(Exception error) {commandGuard.SetFailure(error.Message);throw;}
        }
        void Emit(object message) { lock(output) { Console.WriteLine(Data.Json().Serialize(message)); Console.Out.Flush(); } }
        void Log(string level, string message) {
            object entry = new { time = DateTimeOffset.Now.ToString("o"), level = level, message = message };
            lock(state) { logs.Insert(0, entry); if(logs.Count > 200) logs.RemoveAt(logs.Count-1); }
            try {
                Directory.CreateDirectory(Data.DirectoryPath);
                string file = Path.Combine(Data.DirectoryPath, "events.jsonl");
                lock(output) {
                    if (File.Exists(file) && new FileInfo(file).Length > 1048576) { File.Copy(file, file + ".1", true); File.Delete(file); }
                    File.AppendAllText(file, Data.Json().Serialize(entry) + Environment.NewLine, new UTF8Encoding(false));
                }
            } catch (Exception e) { Console.Error.WriteLine("日志写入失败: " + e.Message); }
        }
        public object Snapshot() {
            lock(state) return new {
                egress = config.egress,
                enhancementReady=enhancementReady,enhancementReason=enhancementReason,enhancementPhase=enhancementPhase,
                driver=commandGuard.Status(config.commandProtection),commandBlockId=commandBlockId,commandBlockReason=commandBlockReason,commandBlockAppId=commandBlockAppId,
                online = true,
                admin = SystemPolicy.Admin, ready = healthy, currentIp = currentIp, adapter = NetworkProbe.Adapter,
                checking=checking, networkIssue=networkIssue, nativeVersion=BuildInfo.Version, ipSource=BuildInfo.Endpoint,
                probe=new {round=probeRound,attempt=probeAttempt,phase=probePhase},
                networkAdapters=adapters, watchedAdapter=watchedAdapter, networkAdapterId=config.networkAdapterId,
                lastChecked = checkedAt, reason = reason, running = sessions.Where(s => !s.stopped && !s.otherModel).Select(s => s.appId).Distinct().ToArray(),
                otherModelRunning=sessions.Where(s=>!s.stopped && s.otherModel).Select(s=>s.appId).Distinct().ToArray(),
                detection = detection,
                autostart = config.autostart, startup=startup,rulesLocked = config.rulesLocked, settings = config.settings,
                apps = config.apps.Select(t=>new {id=t.id,name=t.name,path=t.path,arguments=t.arguments,apiScope=t.apiScope,enhanced=t.enhanced,isClaudeCode=t.cli,enabled=t.enabled,pathIssue=PathIssue(t)}).ToArray(), logs = logs.ToArray()
            };
        }
        void Publish() { Emit(new { type = "snapshot", data = Snapshot() }); }
        void Observe(string message, bool networkChanged = false) {
            bool changed;
            lock(state) {
                changed = detection != message; detection = message;
                if(networkChanged) {networkRevision++;Interlocked.Exchange(ref checkRequested,1);}
            }
            if(networkChanged && config.rulesLocked) PauseNetwork("网络发生变化，已暂停联网，正在复核 IPv4","checking");
            if(networkChanged) lock(state) {enhancementReady=false;enhancementReason="网络已变化，等待增强出口复核";enhancementPhase="idle";}
            if(changed) { Log("info",message); Publish(); }
        }
        public void Trip(string why, bool preserveIp = false,string issue="idle") {
            bool changed;
            lock(state) {
                changed = healthy || reason != why || sessions.Any(s => !s.stopped && !s.otherModel);
                healthy = false; reason = why; networkIssue=issue;epoch++; pendingBlock = pendingBlock || changed;
                if(config.commandProtection) commandGuard.Allow(false);
                if(!preserveIp) currentIp = "";
                foreach(Session s in sessions.Where(s=>!s.otherModel)) { s.stopped = true; Win32.TerminateJobObject(s.job, 1); }
            }
            if(changed) { Log("warning", why); Publish(); }
        }
        void TripEnhanced(string why) {
            lock(state) {
                if(commandBlockReason==why) return;
                commandGuard.Allow(false);
                foreach(Target target in config.apps.Where(t=>t.enabled && t.enhanced)) {
                    StopTarget(target.id);SystemPolicy.Block(target,true);
                }
                commandBlockId=Guid.NewGuid().ToString("D");commandBlockReason=why;
                commandBlockAppId=config.apps.Where(t=>t.enabled && t.enhanced).Select(t=>t.id).FirstOrDefault() ?? "";
                Log("warning","增强过滤失效，已停止增强会话 · "+why);Publish();
            }
        }
        bool BlockPending() {
            lock(state) {
                if(!pendingBlock || !SystemPolicy.Admin) return true;
                pendingBlock=false;bool success=true;
                foreach(Target t in config.apps.Where(t=>t.enabled && (!healthy || !sessions.Any(s=>s.appId==t.id && !s.stopped && !s.otherModel)) && (PathIssue(t)=="" || sessions.Any(s=>s.appId==t.id && !s.stopped && !s.otherModel)))) {
                    try {SystemPolicy.Block(t,true);}
                    catch(Exception e) {pendingBlock=true;success=false;Log("error","封锁失败 · "+t.name+" · "+e.Message);}
                }
                return success;
            }
        }
        void PauseNetwork(string why,string issue,bool preserveIp=false) {
            bool changed;
            lock(state) {
                if(issue=="checking" && (networkIssue=="ip_changed" || networkIssue=="ip_unavailable")) issue=networkIssue;
                changed=healthy || networkIssue!=issue;
                healthy=false;reason=why;networkIssue=issue;pendingBlock=true;
                if(config.commandProtection) commandGuard.Allow(false);
                if(!preserveIp) currentIp="";
                if(!BlockPending()) {Trip("应用连接过滤失效，为保护连接已结束受控程序",true,"enforcement_failed");return;}
            }
            if(changed) Log(issue=="checking" ? "info" : "warning",why);
            Publish();
        }
        bool Check(Action<ProbeProgress> progress = null) {
            DateTime started=DateTime.UtcNow;
            Interlocked.Exchange(ref checkRequested,0);
            int startEpoch,startNetwork; lock(state) {startEpoch=epoch;startNetwork=networkRevision;}
            lock(state) {
                probeRound=probePhase=="failed" && networkIssue!="idle" ? probeRound+1 : 1;
                probeAttempt=0;probePhase="checking";checking=true;
            }
            Publish();
            try {
                ClaudeProbeResult result=probe.Read(item=>{
                    if(item.step=="attempt") {
                        if(item.attempt<1 || item.attempt>BuildInfo.ProbeAttempts) throw new Exception("IPv4 检测次数无效。");
                        lock(state) probeAttempt=item.attempt;
                        Publish();return;
                    }
                    if(progress!=null) progress(item);
                    if(item.step=="reconnect") {
                        if(item.status=="running") lock(state) {
                            if(networkIssue=="idle" || networkIssue=="checking") PauseNetwork("IPv4 获取暂未成功，已暂停联网，"+item.detail,"checking");
                        }
                        Observe(item.status=="running" ? "IPv4 获取暂未成功，"+item.detail : item.status=="ok" ? "IPv4 检测已恢复" : "IPv4 三次检测未通过");
                    }
                }); string ip=result.ip;
                lock(state) {
                    if(startNetwork!=networkRevision || startEpoch!=epoch) return false;
                    currentIp=ip;checkedAt=result.checkedAt;NetworkProbe.Adapter=result.adapter ?? "";
                }
                if(!config.rulesLocked) { lock(state) { healthy=false; reason="IP 未锁定，请先锁定允许的公网 IPv4"; } return false; }
                if(config.egress!=null && egressIssue!="") {lock(state) probePhase="failed";PauseNetwork("固定出口策略未就绪 · "+egressIssue,"ip_unavailable");return false;}
                if(progress!=null) {
                    try {
                        TimeZoneInfo zone=TimeZoneInfo.Local;
                        TimeSpan offset=zone.GetUtcOffset(DateTime.Now);
                        progress(new ProbeProgress("timezone","本机时区",zone.Id=="China Standard Time" ? "warning" : "info","UTC"+(offset<TimeSpan.Zero ? "-" : "+")+offset.Duration().ToString(@"hh\:mm")+" · "+(zone.IsDaylightSavingTime(DateTime.Now) ? zone.DaylightName : zone.StandardName)));
                    } catch(Exception) { progress(new ProbeProgress("timezone","本机时区","unknown","未取得时区信息")); }
                    bool matches=config.settings.expectedIps.Contains(ip);
                    progress(new ProbeProgress("match","锁定地址",matches ? "ok" : "error",matches ? "IPv4 命中允许列表" : "IPv4 未在允许列表中"));
                }
                if(!config.settings.expectedIps.Contains(ip)) { lock(state) probePhase="failed";PauseNetwork("公网 IPv4 未在允许列表中，已暂停联网，程序保持运行","ip_changed",true);return false; }
                lock(state) {
                    if(startEpoch!=epoch || startNetwork!=networkRevision) return false;
                    foreach(Target t in config.apps.Where(t=>t.enabled && sessions.Any(s=>s.appId==t.id && !s.stopped && !s.otherModel))) SystemPolicy.Block(t,t.enhanced && !commandGuard.Live);
                    bool resumed=networkIssue!="idle" && sessions.Any(s=>!s.stopped && !s.otherModel);
                    healthy=true;reason="";networkIssue="idle";probePhase="passed";lastVerified=Stopwatch.GetTimestamp();
                    if(config.commandProtection) commandGuard.Allow(enhancementReady);
                    if(resumed) Log("info","IPv4 已命中允许列表，受保护程序已恢复联网");
                }
                return true;
            } catch(Exception e) {
                lock(state) { checkedAt=DateTimeOffset.Now.ToString("o");probePhase="failed"; }
                PauseNetwork("公网 IPv4 校验失败，已暂停联网 · "+e.GetBaseException().Message,"ip_unavailable");return false;
            } finally { lock(state) {checking=false;if(probePhase=="checking") probePhase="failed";} nextCheck = Interlocked.Exchange(ref checkRequested,0)==1 ? DateTime.MinValue : started.AddSeconds(config.settings.intervalSeconds); Publish(); }
        }
        Target Find(string id) {
            Target t = config.apps.SingleOrDefault(a => a.id == id);
            if(t == null) throw new Exception("找不到该程序。"); return t;
        }
        static void RequireClosed(Target t) {
            foreach(Process p in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(t.path))) using(p) {
                try { if(String.Equals(p.MainModule.FileName, t.path, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("请先关闭 " + t.name + " 的所有进程。"); }
                catch(System.ComponentModel.Win32Exception) { throw new Exception("请先关闭同名进程，再启用防护。"); }
            }
        }
        void StopTarget(string id) {
            lock(state) foreach(Session s in sessions.Where(s => s.appId == id)) { s.stopped = true; Win32.TerminateJobObject(s.job, 1); }
        }
        string PathIssue(Target target) {
            return PackagePolicy.IsClaudeDesktop(target.path) && (staleDesktopPaths.Contains(target.id) || !File.Exists(target.path)) ? "安装目录已更新，请先更新路径" : "";
        }
        void Relocate(Target previous,string path) {
            lock(state) {
            RequireCommandChangesClosed();
            if(!PackagePolicy.IsClaudeDesktop(previous.path)) throw new Exception("请选择已添加的 Claude Desktop。");
            Target next=new Target {id=previous.id,name=previous.name,path=path,arguments=previous.arguments,apiScope=previous.apiScope,enabled=previous.enabled,enhanced=previous.enhanced};
            Data.Validate(next,true);
            if(!PackagePolicy.IsClaudeDesktop(next.path) || PackagePolicy.Find(next.path)==null) throw new Exception("请选择已注册的 Claude Desktop 安装入口。");
            if(String.Equals(previous.path,next.path,StringComparison.OrdinalIgnoreCase)) { Log("info",previous.name+" · 路径已是最新");return; }
            if(config.apps.Any(t=>t.id!=previous.id && String.Equals(t.path,next.path,StringComparison.OrdinalIgnoreCase))) throw new Exception("新版路径已在程序列表中，请使用已有程序。");
            if(previous.enabled) { RequireClosed(next);SystemPolicy.FirewallHealthy(); }
            List<Target> apps=config.apps.Select(t=>t.id==previous.id ? next : t).ToList();
            bool installing=false;
            if(config.commandProtection) commandGuard.Stop();
            try {
                if(previous.enabled) {
                    SystemPolicy.Block(previous,true);StopTarget(previous.id);
                    SystemPolicy.Unintercept(previous);SystemPolicy.RemoveFirewall(previous);
                    installing=true;
                    SystemPolicy.Block(next,true);SystemPolicy.Intercept(next);
                }
                Data.Save(new Config {settings=config.settings,apps=apps,autostart=config.autostart,egress=config.egress,rulesLocked=config.rulesLocked,networkAdapterId=config.networkAdapterId,networkAdapterName=config.networkAdapterName,commandProtection=config.commandProtection});
                lock(state) {config.apps=apps;staleDesktopPaths.Remove(previous.id);}
            } catch(Exception error) {
                if(previous.enabled) {
                    List<Action> recovery=new List<Action>();List<string> failures=new List<string>();
                    if(installing) {recovery.Add(()=>SystemPolicy.Unintercept(next));recovery.Add(()=>SystemPolicy.RemoveFirewall(next));}
                    recovery.Add(()=>SystemPolicy.Block(previous,true));
                    if(File.Exists(previous.path)) recovery.Add(()=>{
                        try {PackagePolicy.Find(previous.path);SystemPolicy.Intercept(previous);}
                        catch(PackageUnavailableException) { }
                    });
                    foreach(Action operation in recovery) {try {operation();}catch(Exception restore) {failures.Add(restore.GetBaseException().Message);}}
                    if(failures.Count>0) {
                        lock(state) staleDesktopPaths.Add(previous.id);
                        Publish();
                        throw new Exception("路径迁移失败，原防护恢复也遇到错误。请运行恢复工具后重新配置。"+String.Join("；",failures));
                    }
                }
                throw new Exception("路径迁移失败，原配置已保留。"+error.GetBaseException().Message);
            }
            Log("info",next.name+" · 已更新安装路径，保留原防护配置");
            LoadCommandGuard();
            }
        }
        void Protect(Target t, bool enabled) {
            lock(state) {
            if(t.enhanced) {RequireCommandChangesClosed(t.id);StopTarget(t.id);if(config.commandProtection) commandGuard.Stop();}
            bool canUseOtherModel=ClaudeCodeScope.IsCli(t) && t.apiScope!="claude" && !t.enhanced;
            if(enabled && !config.rulesLocked && !canUseOtherModel) throw new Exception("请先锁定允许的公网 IPv4，再启用程序防护。");
            SystemPolicy.RequireAdmin(); StopTarget(t.id);
            if(enabled) {
                Data.Validate(config.settings,canUseOtherModel); Data.Validate(t, true); RequireClosed(t); SystemPolicy.FirewallHealthy();
                if(config.egress!=null) {
                    EgressPolicy.ValidateTarget(t);
                }
                try {
                    EgressPolicy route=t.enhanced ? EnhancementRoute : config.egress;
                    if(route!=null && PackagePolicy.IsClaudeDesktop(t.path)) {DesktopProxyPolicy.Apply(route.Url);egressIssue="";}
                    SystemPolicy.Block(t, true);SystemPolicy.Intercept(t);t.enabled = true;Data.Save(config);
                }
                catch {
                    SystemPolicy.Unintercept(t);SystemPolicy.RemoveFirewall(t);t.enabled = false;
                    if(config.egress!=null && !config.apps.Any(a=>a.enabled && PackagePolicy.IsClaudeDesktop(a.path))) DesktopProxyPolicy.Restore();
                    throw;
                }
            } else {
                SystemPolicy.Unintercept(t); SystemPolicy.RemoveFirewall(t); t.enabled = false; Data.Save(config);
                if(!config.apps.Any(a=>a.enabled && (a.enhanced || config.egress!=null) && PackagePolicy.IsClaudeDesktop(a.path))) DesktopProxyPolicy.Restore();
            }
            Log("info", t.name + (enabled ? " · 已接管启动" : " · 已解除防护"));
            config.commandProtection=config.apps.Any(a=>a.enabled && a.enhanced);Data.Save(config);
            if(t.enhanced && config.commandProtection) LoadCommandGuard();
            }
        }
        object Command(Dictionary<string,object> input) {
            string action = input["action"] as string;
            lock(actions) {
                if(action == "status") return Snapshot();
                if(action == "check") { Check(); return Snapshot(); }
                if(action=="enhancement:state") {
                    object ready,detail,phase;
                    if(!input.TryGetValue("ready",out ready) || !(ready is bool) ||
                       !input.TryGetValue("reason",out detail) || !(detail is string) || ((string)detail).Length>1024 ||
                       !input.TryGetValue("phase",out phase) || !(phase is string) || !new[] {"idle","checking","passed","blocked","failed"}.Contains((string)phase) ||
                       ((bool)ready && (string)phase!="passed")) throw new Exception("增强出口状态格式无效。");
                    lock(state) {enhancementReady=(bool)ready;enhancementReason=(string)detail;enhancementPhase=(string)phase;
                        if(config.commandProtection) commandGuard.Allow(healthy && enhancementReady);}
                    return Snapshot();
                }
                if(action=="proxy:changed") {Observe("上游代理发生变化，正在复核出口",true);Check();return Snapshot();}
                SystemPolicy.RequireAdmin();
                if(action=="kernel:install") {
                    commandGuard.Install();Log("info","命令进程树驱动已安装，尚未加载");
                } else if(action=="kernel:repair") {
                    TripEnhanced("命令防护正在恢复，增强会话已停止");
                    commandGuard.Stop();LoadCommandGuard(true);Log("info","命令进程树防护已恢复");Check();
                } else if(action == "egress:pause") {
                    PauseNetwork("固定出口正在重启，已暂停联网","checking");
                } else if(action == "egress:set") {
                    if(config.commandProtection) throw new Exception("请先关闭命令进程树防护，再修改固定出口。");
                    if(config.rulesLocked || sessions.Any(s=>!s.stopped && !s.otherModel)) throw new Exception("请先取消 IP 锁定并停止受保护程序，再修改固定出口。");
                    EgressPolicy next=input["egress"]==null ? null : Data.Json().Deserialize<EgressPolicy>(Data.Json().Serialize(input["egress"]));
                    if(next!=null) {
                        next.Validate();
                        foreach(Target app in config.apps.Where(a=>a.enabled)) {EgressPolicy.ValidateTarget(app);RequireClosed(app);}
                    }
                    EgressPolicy previous=config.egress;
                    try {
                        bool desktop=config.apps.Any(a=>a.enabled && PackagePolicy.IsClaudeDesktop(a.path));
                        DesktopProxyPolicy.Apply(next!=null && desktop ? next.Url : null);
                        SystemPolicy.FixedProxyPort=next==null ? 0 : next.port;
                        SystemPolicy.EnhancedProxyPort=next!=null ? next.port : enhancementPolicy==null ? 0 : enhancementPolicy.port;
                        foreach(Target app in config.apps.Where(a=>a.enabled)) SystemPolicy.Block(app,true);
                        Data.Save(new Config {settings=config.settings,apps=config.apps,autostart=config.autostart,egress=next,rulesLocked=false,networkAdapterId=config.networkAdapterId,networkAdapterName=config.networkAdapterName,commandProtection=config.commandProtection});
                        lock(state) {config.egress=next;egressIssue="";networkRevision++;healthy=false;currentIp="";}
                    } catch {
                        SystemPolicy.FixedProxyPort=previous==null ? 0 : previous.port;
                        SystemPolicy.EnhancedProxyPort=previous!=null ? previous.port : enhancementPolicy==null ? 0 : enhancementPolicy.port;
                        bool desktop=config.apps.Any(a=>a.enabled && PackagePolicy.IsClaudeDesktop(a.path));
                        DesktopProxyPolicy.Apply(previous!=null && desktop ? previous.Url : null);
                        throw;
                    }
                    Log("info",next==null ? "已关闭独立固定出口" : "已固定独立节点 · "+next.label);
                } else if(action == "lock") {
                    if(config.rulesLocked) throw new Exception("IP 已锁定，请先取消锁定再修改。");
                    Settings s = Data.Json().Deserialize<Settings>(Data.Json().Serialize(input["settings"])); Data.Validate(s);
                    Data.Save(new Config { settings=s, apps=config.apps, autostart=config.autostart, egress=config.egress, rulesLocked=true, networkAdapterId=config.networkAdapterId, networkAdapterName=config.networkAdapterName,commandProtection=config.commandProtection });
                    lock(state) { config.settings = s; config.rulesLocked = true; healthy = false; currentIp = ""; reason = "正在校验锁定的公网 IPv4"; }
                    Log("info", "允许的公网 IPv4 已锁定"); Check();
                } else if(action == "unlock") {
                    if(!config.rulesLocked) return Snapshot();
                    Data.Save(new Config { settings=config.settings, apps=config.apps, autostart=config.autostart, egress=config.egress, rulesLocked=false, networkAdapterId=config.networkAdapterId, networkAdapterName=config.networkAdapterName,commandProtection=config.commandProtection });
                    lock(state) { config.rulesLocked = false; healthy = false; }
                    Trip("IP 已取消锁定，受保护程序已停止，请重新锁定"); BlockPending();
                } else if(action == "adapter:set") {
                    string id=input["adapterId"] as string;
                    AdapterInfo chosen=id=="" ? null : NetworkProbe.Adapters().SingleOrDefault(n=>n.id==id);
                    if(id==null || (id!="" && chosen==null)) throw new Exception("所选网卡当前不存在，请重新选择。");
                    lock(state) { config.networkAdapterId=id; config.networkAdapterName=chosen==null ? "" : chosen.name; }
                    Data.Save(config); RefreshAdapters();

                } else if(action == "browser:register") {
                    BrowserHost.Register();
                } else if(action == "add") {
                    Target t = Data.Json().Deserialize<Target>(Data.Json().Serialize(input["app"])); Data.Validate(t, true);
                    if(config.apps.Count >= 30) throw new Exception("最多添加 30 个程序。");
                    if(config.apps.Any(a => a.id == t.id || String.Equals(a.path,t.path,StringComparison.OrdinalIgnoreCase))) throw new Exception("该程序已在列表中。");
                    t.enabled = false; lock(state) config.apps.Add(t); Data.Save(config); Log("info", t.name + " · 已添加");
                } else if(action == "autostart") {
                    bool enabled = (bool)input["enabled"]; StartupPolicy.Configure(enabled,desktopExe);
                    startup=StartupPolicy.Read(enabled,desktopExe);
                    lock(state) config.autostart = enabled; Data.Save(config); Log("info", enabled ? "已开启登录后启动" : "已关闭登录后启动");
                } else {
                    Target t = Find(input["targetId"] as string);
                    if(action=="enhance") {
                        bool enabled=(bool)input["enabled"];
                        if(enabled==t.enhanced) return Snapshot();
                        if(enabled && (!t.enabled || !config.rulesLocked)) throw new Exception("请先锁定 IP 并开启该程序的基础防护。");
                        if(enabled && config.egress!=null) throw new Exception("请先关闭历史独立出口，再使用当前代理增强。");
                        if(enabled && enhancementPolicy==null) throw new Exception("通用代理通道尚未就绪。");
                        if(sessions.Any(s=>!s.stopped && s.enhanced && s.appId!=t.id)) throw new Exception("请先停止其他增强会话，再调整过滤范围。");
                        StopTarget(t.id);RequireClosed(t);
                        if(config.commandProtection) commandGuard.Stop();
                        if(enabled) EgressPolicy.ValidateTarget(t);
                        t.enhanced=enabled;
                        config.commandProtection=config.apps.Any(a=>a.enabled && a.enhanced);
                        Data.Save(config);
                        if(PackagePolicy.IsClaudeDesktop(t.path)) {
                            if(enabled) DesktopProxyPolicy.Apply(EnhancementRoute.Url);
                            else if(config.egress!=null) DesktopProxyPolicy.Apply(config.egress.Url);
                            else DesktopProxyPolicy.Restore();
                        }
                        SystemPolicy.Block(t,true);
                        if(config.commandProtection) LoadCommandGuard(true);
                        Log("info",t.name+(enabled ? " · 已开启当前代理增强" : " · 已关闭增强，基础 IP 防护保留"));
                    }
                    else if(action == "protect") Protect(t, (bool)input["enabled"]);
                    else if(action == "relocate") Relocate(t,input["path"] as string);
                    else if(action == "edit") {
                        Target changed=new Target { id=t.id,path=t.path,enabled=t.enabled,name=input["name"] as string,arguments=input["arguments"] as string,apiScope=t.apiScope,enhanced=t.enhanced };
                        Data.Validate(changed,false);
                        List<Target> next=config.apps.Select(a=>a.id==t.id ? changed : a).ToList();
                        Data.Save(new Config { settings=config.settings,apps=next,autostart=config.autostart,egress=config.egress,rulesLocked=config.rulesLocked,networkAdapterId=config.networkAdapterId,networkAdapterName=config.networkAdapterName,commandProtection=config.commandProtection });
                        lock(state) config.apps=next;
                        Log("info",changed.name+" · 启动配置已更新");
                    }
                    else if(action == "remove") { if(t.enabled) Protect(t, false); lock(state) {config.apps.Remove(t);staleDesktopPaths.Remove(t.id);} Data.Save(config); }
                    else if(action == "stop") { lock(state) {StopTarget(t.id); SystemPolicy.Block(t,true);} Log("info", t.name + " · 已停止并封锁"); }
                    else if(action == "start") {
                        bool cli=ClaudeCodeScope.IsCli(t);
                        if(t.enhanced && !cli) commandGuard.RequireRoot(t.path);
                        if(PathIssue(t)!="") throw new Exception(PathIssue(t));
                        if(!config.rulesLocked && (!cli || t.apiScope=="claude" || t.enhanced)) throw new Exception("请先锁定允许的公网 IPv4。");
                        if(!t.enabled) throw new Exception("请先启用该程序的防护。");
                        Data.Validate(t, true);
                        if(PackagePolicy.Find(t.path)!=null) Background(() => {
                            try { PackagePolicy.Activate(t); }
                            catch(Exception e) { Log("warning", t.name + " · 安装包激活未完成 · " + e.GetBaseException().Message); Publish(); }
                        });
                        else Process.Start(new ProcessStartInfo(t.path, t.arguments) { UseShellExecute = true, WorkingDirectory = Path.GetDirectoryName(t.path) });
                    } else throw new Exception("未知操作。");
                }
                return Snapshot();
            }
        }
        void Loop() {
            while(!quit) {
                try {
                    if(Monitor.TryEnter(actions)) {
                        try {
                            BlockPending();
                            if(config.commandProtection) {string error=commandGuard.HealthError();if(error!="") TripEnhanced(error);}
                            if(DateTime.UtcNow >= nextCheck || Interlocked.CompareExchange(ref checkRequested,0,0)==1) {
                                Check();
                            }
                        } finally { Monitor.Exit(actions); }
                    }
                } catch(Exception e) { Observe("守护状态检测异常 · " + e.GetBaseException().Message); }
                Thread.Sleep(500);
            }
        }
        void WatchNetwork() {
            while(!quit) {
                try {
                    RefreshAdapters();
                    string now = NetworkProbe.Fingerprint(); string prior;
                    lock(state) { prior=topology; topology=now; }
                    if(prior!="" && now!=prior) Observe("网卡或路由发生变化",true);
                    bool expired;lock(state) expired=healthy && !VerificationFresh();
                    if(expired) PauseNetwork("公网检测结果已过期，已暂停联网，程序保持运行","ip_unavailable");
                    wifi.Ensure();
                } catch(Exception e) { Observe("网络状态检测异常 · " + e.Message); }
                Thread.Sleep(500);
            }
        }
        void RefreshAdapters() {
            try {
                AdapterInfo[] current=NetworkProbe.Adapters(); string id,name;
                lock(state) { id=config.networkAdapterId; name=config.networkAdapterName; }
                AdapterInfo selected=NetworkProbe.Watched(current,id,name);
                lock(state) { adapters=current; watchedAdapter=selected; }
            } catch(NetworkInformationException e) {
                lock(state) watchedAdapter=new AdapterInfo { id=config.networkAdapterId,name="网卡检测失败",error=e.Message };
            }
        }
        void WatchStartup() {
            while(!quit) {
                bool requested;lock(state) requested=config.autostart;
                StartupStatus result=StartupPolicy.Read(requested,desktopExe);
                bool changed;lock(state) {changed=startup.enabled!=result.enabled || startup.state!=result.state || startup.message!=result.message;startup=result;}
                if(changed) Publish();
                for(int i=0;i<10 && !quit;i++) Thread.Sleep(500);
            }
        }
        PipeSecurity PipeAcl() {
            PipeSecurity acl = new PipeSecurity(); acl.SetAccessRuleProtection(true,false);
            foreach(SecurityIdentifier sid in new[] { WindowsIdentity.GetCurrent().User, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null), new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null) }) acl.AddAccessRule(new PipeAccessRule(sid,PipeAccessRights.FullControl,AccessControlType.Allow));
            return acl;
        }
        void Listen() {
            while(!quit) {
                NamedPipeServerStream pipe = null;
                try {
                    pipe = new NamedPipeServerStream(SystemPolicy.PipeName,PipeDirection.InOut,64,PipeTransmissionMode.Byte,PipeOptions.Asynchronous,4096,4096,PipeAcl());
                    pipe.WaitForConnection(); NamedPipeServerStream connected = pipe;
                    Background(() => GateSession(connected));
                } catch(Exception e) { if(pipe != null) pipe.Dispose(); if(!quit) { Observe("启动门卫异常 · " + e.Message); Thread.Sleep(1000); } }
            }
        }
        static void Background(Action action) { Thread thread = new Thread(() => action()); thread.IsBackground = true; thread.Start(); }
        bool CanInherit(NamedPipeServerStream pipe,string appId) {
            uint pid;
            Win32.Check(Win32.GetNamedPipeClientProcessId(pipe.SafePipeHandle,out pid),"无法核对启动来源");
            IntPtr process=Win32.OpenProcess(0x1000,false,pid);
            if(process==IntPtr.Zero) return false;
            try {
                lock(state) {
                    if(!config.rulesLocked) return false;
                    foreach(Session session in sessions.Where(s=>s.appId==appId && !s.stopped && !s.otherModel && s.epoch==epoch)) {
                        bool inside;
                        Win32.Check(Win32.IsProcessInJob(process,session.job,out inside),"无法核对受保护进程树");
                        if(inside) return true;
                    }
                    return false;
                }
            } finally { Win32.CloseHandle(process); }
        }
        bool VerificationFresh() {
            return lastVerified!=0 && Stopwatch.GetTimestamp()-lastVerified<=Stopwatch.Frequency*(config.settings.intervalSeconds+(checking ? BuildInfo.ProbeTimeoutMs/1000+2 : 8));
        }
        static void RequireCliGateSource(NamedPipeServerStream pipe) {
            uint pid;Win32.Check(Win32.GetNamedPipeClientProcessId(pipe.SafePipeHandle,out pid));
            using(Process client=Process.GetProcessById((int)pid)) {
                string path=client.MainModule.FileName,terminal=Path.Combine(Path.GetDirectoryName(SystemPolicy.Exe),"IpGuard.Terminal.exe");
                if(!String.Equals(path,SystemPolicy.Exe,StringComparison.OrdinalIgnoreCase) && !String.Equals(path,terminal,StringComparison.OrdinalIgnoreCase)) throw new Exception("API 会话来源无效，请通过受保护的 CLI 入口启动。");
            }
        }
        void GateSession(NamedPipeServerStream pipe) {
            Session session = null; Target target = null;
            try {
            using(pipe) using(StreamReader reader = new StreamReader(pipe,new UTF8Encoding(false),false,1024,true)) using(StreamWriter writer = new PipeWriter(pipe)) {
                try {
                    Task<string> read = Task.Run(() => reader.ReadLine());
                    if(!read.Wait(5000)) throw new Exception("启动请求超时。");
                    string line = read.Result;
                    if(line == null || line.Length > 8192) throw new Exception("启动请求无效。");
                    var request = Data.Json().Deserialize<Dictionary<string,object>>(line);
                    if(request.ContainsKey("action") && request["action"] as string=="scope") {
                        writer.WriteLine(Data.Json().Serialize(new { inherit=CanInherit(pipe,request["id"] as string) }));
                        return;
                    }
                    bool inherited=request.ContainsKey("inherit") && request["inherit"] is bool && (bool)request["inherit"];
                    bool other=false;
                    lock(actions) {
                        target = Find(request["id"] as string);
                        if(!target.enabled || !String.Equals(target.path,request["path"] as string,StringComparison.OrdinalIgnoreCase)) throw new Exception("该程序未启用启动防护。");
                        if(PathIssue(target)!="") throw new Exception(PathIssue(target));
                        ModelEvidence evidence=null;
                        if(ClaudeCodeScope.IsCli(target)) {
                            RequireCliGateSource(pipe);object raw;
                            if(request.TryGetValue("modelEvidence",out raw)) evidence=Data.Json().Deserialize<ModelEvidence>(Data.Json().Serialize(raw));
                        }
                        ModelDecision decision=inherited ? new ModelDecision("claude","继承受保护会话") : ClaudeCodeScope.Decide(target,target.enhanced,evidence);
                        if(!inherited && ClaudeCodeScope.IsCli(target)) Log("info",target.name+" · "+decision.reason);
                        other=decision.Other;
                        if(target.enhanced && !other) {
                            if(!enhancementReady) throw new Exception(enhancementReason);
                            commandGuard.RequireRoot(target.path);
                        }
                        writer.WriteLine(Data.Json().Serialize(new { type="context", name=target.name, expectedIps=config.settings.expectedIps }));
                        if(!config.rulesLocked && !other) throw new Exception("请先锁定允许的公网 IPv4。");
                        if(PackagePolicy.Find(target.path)!=null) {
                            if(!request.ContainsKey("package") || !(bool)request["package"]) throw new Exception("请通过 Desktop 原快捷方式或 IP Guard 的启动按钮打开安装包。");
                            Win32.ProcessInfo existing=PackagePolicy.OpenTarget(target,Convert.ToUInt32(request["pid"]),Convert.ToUInt32(request["tid"]));
                            Win32.CloseHandle(existing.thread); Win32.CloseHandle(existing.process);
                        }
                        bool disconnected=false;
                        Action<ProbeProgress> progress = item => {
                            if(disconnected) return;
                            try { writer.WriteLine(Data.Json().Serialize(new { type="progress", data=item })); }
                            catch(IOException) { disconnected=true; }
                        };
                        if(!other) {
                            progress(new ProbeProgress("security","系统防护","running","检查防火墙与 IP 锁定"));
                            if((config.egress!=null || target.enhanced) && ClaudeCodeScope.LocalGateway(evidence)) throw new Exception("此会话使用本地或内网 API 中转；请为中转进程配置同一上游出口，或关闭该入口增强后使用基础防护。");
                            SystemPolicy.FirewallHealthy();
                            progress(new ProbeProgress("security",ClaudeCodeScope.IsCli(target) ? "API 与系统防护" : "系统防护","ok",ClaudeCodeScope.IsCli(target) ? decision.reason : "锁定与防火墙已就绪"));
                            if(inherited) {
                                if(!CanInherit(pipe,target.id)) throw new Exception("原启动许可已失效，子进程启动已阻断。");
                            } else if(!Check(progress)) throw new Exception(reason);
                        }
                        if(disconnected) throw new IOException("启动校验窗口已关闭。");
                        string name = (target.enhanced && !other ? "Global\\IPGuard-"+SystemPolicy.Sid+"-" : "Local\\IPGuard-") + Guid.NewGuid().ToString("D");
                        lock(state) {
                            if(!healthy && !inherited && !other) throw new Exception(reason);
                            session = new Session { appId=target.id, name=name, job=Win32.NewJob(name), epoch=epoch,otherModel=other,enhanced=target.enhanced };
                            if(session.enhanced && !other) commandGuard.Register(name,session.job);
                            sessions.Add(session);
                        }
                        writer.WriteLine(Data.Json().Serialize(new { allow=true, job=name, commandProtection=target.enhanced && !other,enhancementPolicy=target.enhanced ? EnhancementRoute : null,otherModel=other,scopeReason=decision.reason,currentIp=currentIp, expectedIps=config.settings.expectedIps }));
                    }
                    Task<string> started = Task.Run(() => reader.ReadLine());
                    if(!started.Wait(other ? 30000 : 8000) || started.Result != "started") throw new Exception("目标进程未完成启动准备。");
                    lock(actions) {
                        lock(state) {
                            if(session.stopped || (!other && (session.epoch!=epoch || (!healthy && !inherited)))) throw new Exception("启动许可已撤销。");
                            if(!other) SystemPolicy.Block(target,!healthy);writer.WriteLine("run");
                        }
                        if(other) Log("info",target.name+" · 已启动，使用原网络，未加入 IPv4 防护");
                    }
                    if(!inherited && !session.otherModel) Log("info", target.name + " · 校验通过，已启动"); Publish();
                    Task<string> alive = Task.Run(() => reader.ReadLine());
                    while(!quit && !session.stopped && !alive.IsCompleted) {
                        if(!session.otherModel && session.epoch!=Volatile.Read(ref epoch)) break;
                        try {writer.WriteLine("lease");} catch(IOException) {break;}
                        Thread.Sleep(400);
                    }
                    if(alive.Wait(1000) && alive.Result!=null && alive.Result.Length<4096 && alive.Result.StartsWith("{",StringComparison.Ordinal)) {
                        var blocked=Data.Json().Deserialize<Dictionary<string,object>>(alive.Result);
                        if(blocked.ContainsKey("type") && blocked["type"] as string=="command-blocked") {
                            lock(state) {commandBlockId=Guid.NewGuid().ToString("D");commandBlockAppId=target==null ? "" : target.id;commandBlockReason=blocked["error"] as string ?? "子进程启动被阻断。";}
                            Log("warning",commandBlockReason);Publish();
                        }
                    }
                } catch(Exception e) {
                    Log("warning", (target == null ? "启动拦截" : target.name) + " · " + e.GetBaseException().Message);
                    try { writer.WriteLine(Data.Json().Serialize(new { allow=false, currentIp=currentIp, expectedIps=config.settings.expectedIps, error=e.GetBaseException().Message, code=e.GetBaseException() is FirewallDisabledException ? FirewallDisabledException.Code : "" })); } catch(IOException) { }
                } finally {
                    if(session != null) lock(state) { session.stopped=true; Win32.TerminateJobObject(session.job,1); if(session.enhanced && !session.otherModel) {try {commandGuard.Unregister(session.name);} catch(Exception error) {Log("warning",error.Message);}} Win32.CloseHandle(session.job); sessions.Remove(session); pendingBlock=true; }
                    Publish();
                }
            }
            } catch(IOException e) { Log("info", "启动连接已关闭 · " + e.Message); }
        }
        public void Run() {
            BrowserRetirement.Remove(config);
            try {BrowserHost.Register(true);} catch(Exception error) {Log("error","网页扩展连接注册失败 · "+error.Message);}
            if(config.commandProtection && SystemPolicy.Admin) {
                try {LoadCommandGuard();} catch(Exception error) {reason=error.Message;Log("error",reason);}
            }
            if(config.apps.Any(t => t.enabled) && SystemPolicy.Admin) {
                Trip("守护程序已启动，等待重新校验"); BlockPending();
                Target desktop=config.apps.FirstOrDefault(t=>t.enabled && PackagePolicy.IsClaudeDesktop(t.path));
                EgressPolicy desktopRoute=desktop!=null && desktop.enhanced ? EnhancementRoute : config.egress;
                if(desktopRoute!=null && desktop!=null) {
                    try {DesktopProxyPolicy.Apply(desktopRoute.Url);}
                    catch(Exception error) {egressIssue=error.GetBaseException().Message;Log("error",egressIssue);}
                }
                foreach(Target t in config.apps.Where(t => t.enabled)) {
                    if(PackagePolicy.IsClaudeDesktop(t.path) && !File.Exists(t.path)) { staleDesktopPaths.Add(t.id);Log("warning",t.name+" · 安装目录已更新，请点击“更新路径”重新接管");continue; }
                    try { Data.Validate(t,true);SystemPolicy.Intercept(t); }
                    catch(PackageUnavailableException) {
                        if(!PackagePolicy.IsClaudeDesktop(t.path)) throw;
                        staleDesktopPaths.Add(t.id);
                        Log("warning",t.name+" · 安装包已更新，请点击“更新路径”重新接管");
                    }
                }
            }
            NetworkChange.NetworkAddressChanged += NetworkChanged;
            NetworkChange.NetworkAvailabilityChanged += AvailabilityChanged;
            SystemEvents.PowerModeChanged += PowerChanged;
            if(SystemPolicy.Admin) Background(Listen);
            Background(Dispatch); Background(Loop); Background(WatchNetwork);Background(WatchStartup);Publish();
            try {
                string line;
                while((line=Console.ReadLine()) != null) {
                    string id = "";
                    try {
                        if(line.Length > 32768) throw new Exception("操作请求过长。");
                        var input = Data.Json().Deserialize<Dictionary<string,object>>(line); id = input["id"] as string;
                        if((string)input["action"] == "shutdown") { Emit(new { id=id, ok=true, data=Snapshot() }); break; }
                        string action=input["action"] as string;
                        if(action=="probe-result" || action=="probe-progress") probe.Receive(input);
                        else commands.Add(input);
                    } catch(Exception e) { Emit(new { id=id, ok=false, error=e.Message, code=e.GetBaseException() is FirewallDisabledException ? FirewallDisabledException.Code : "", help=e.GetBaseException() is FirewallDisabledException ? FirewallDisabledException.Help : "" }); }
                }
            } finally {
                quit=true; probe.Stop(); commands.CompleteAdding(); Trip("守护程序已退出，受保护程序已结束");
                lock(state) foreach(Session session in sessions.Where(s=>s.otherModel)) {session.stopped=true;Win32.TerminateJobObject(session.job,1);}
                lock(actions) BlockPending();
                if(config.commandProtection) lock(state) {try {commandGuard.Stop();} catch(Exception error) {Log("error","命令防护退出未完成，自动恢复已准备 · "+error.Message);}}
                NetworkChange.NetworkAddressChanged -= NetworkChanged; NetworkChange.NetworkAvailabilityChanged -= AvailabilityChanged; SystemEvents.PowerModeChanged -= PowerChanged;
                wifi.Dispose();
            }
        }
        void Dispatch() {
            foreach(Dictionary<string,object> input in commands.GetConsumingEnumerable()) {
                if(quit) return;
                string id=input["id"] as string;
                try { object result=Command(input); Emit(new { id=id,ok=true,data=result }); Publish(); }
                catch(Exception e) { Emit(new { id=id,ok=false,error=e.Message,code=e.GetBaseException() is FirewallDisabledException ? FirewallDisabledException.Code : "",help=e.GetBaseException() is FirewallDisabledException ? FirewallDisabledException.Help : "" }); }
            }
        }
        void NetworkChanged(object sender,EventArgs e) { Observe("网卡地址发生变化",true); }
        void AvailabilityChanged(object sender,NetworkAvailabilityEventArgs e) { Observe(e.IsAvailable ? "网络连接已切换" : "网络已断开",true); }
        void PowerChanged(object sender,PowerModeChangedEventArgs e) { Observe("系统电源状态改变",true); }
    }
}
