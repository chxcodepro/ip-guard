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
    }
    public sealed class Guard {
        readonly object state = new object(), actions = new object(), output = new object();
        readonly List<Session> sessions = new List<Session>();
        readonly List<object> logs = new List<object>();
        readonly Config config;
        readonly WifiWatch wifi;
        readonly ClaudeProbe probe;
        readonly BlockingCollection<Dictionary<string,object>> commands=new BlockingCollection<Dictionary<string,object>>();
        AdapterInfo[] adapters=new AdapterInfo[0];
        AdapterInfo watchedAdapter=new AdapterInfo { id="",name="正在检测网卡",exists=false };
        bool healthy, pendingBlock, checking;
        volatile bool quit;
        string currentIp = "", reason = "请先锁定允许的公网 IPv4", checkedAt = "", topology = "";
        int epoch;
        int checkRequested;
        string detection = "";
        long lastVerified;
        DateTime nextCheck = DateTime.MinValue;
        public Guard() { config = Data.Load(); wifi = new WifiWatch(why => Observe(why, true)); probe=new ClaudeProbe(Emit); RefreshAdapters(); }
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
                online = true,
                admin = SystemPolicy.Admin, ready = healthy, currentIp = currentIp, adapter = NetworkProbe.Adapter,
                checking=checking, nativeVersion=BuildInfo.Version, ipSource=BuildInfo.Endpoint,
                networkAdapters=adapters, watchedAdapter=watchedAdapter, networkAdapterId=config.networkAdapterId,
                lastChecked = checkedAt, reason = reason, running = sessions.Where(s => !s.stopped).Select(s => s.appId).Distinct().ToArray(),
                detection = detection,
                autostart = config.autostart, rulesLocked = config.rulesLocked, settings = config.settings, apps = config.apps.ToArray(), logs = logs.ToArray()
            };
        }
        void Publish() { Emit(new { type = "snapshot", data = Snapshot() }); }
        void Observe(string message, bool networkChanged = false) {
            bool changed;
            lock(state) {
                changed = detection != message; detection = message;
                if(networkChanged) Interlocked.Exchange(ref checkRequested,1);
            }
            if(changed) { Log("info",message); Publish(); }
        }
        public void Trip(string why, bool preserveIp = false) {
            bool changed;
            lock(state) {
                changed = healthy || reason != why || sessions.Any(s => !s.stopped);
                healthy = false; reason = why; epoch++; pendingBlock = pendingBlock || changed;
                if(!preserveIp) currentIp = "";
                foreach(Session s in sessions) { s.stopped = true; Win32.TerminateJobObject(s.job, 1); }
            }
            if(changed) { Log("warning", why); Publish(); }
        }
        void BlockPending() {
            bool block; lock(state) { block = pendingBlock; pendingBlock = false; }
            if(!block || !SystemPolicy.Admin) return;
            Target[] targets;
            lock(state) targets = config.apps.Where(t => t.enabled && (!healthy || !sessions.Any(s => s.appId == t.id && !s.stopped))).ToArray();
            foreach(Target t in targets) {
                try { SystemPolicy.Block(t, true); }
                catch(Exception e) { lock(state) pendingBlock = true; Log("error", "封锁失败 · " + t.name + " · " + e.Message); }
            }
        }
        bool Check(Action<ProbeProgress> progress = null) {
            DateTime started=DateTime.UtcNow;
            Interlocked.Exchange(ref checkRequested,0);
            int startEpoch; lock(state) startEpoch = epoch;
            lock(state) checking=true; Publish();
            try {
                ClaudeProbeResult result=probe.Read(progress); string ip=result.ip;
                lock(state) { currentIp=ip; checkedAt=result.checkedAt; NetworkProbe.Adapter=result.adapter ?? ""; }
                if(!config.rulesLocked) { lock(state) { healthy=false; reason="IP 未锁定，请先锁定允许的公网 IPv4"; } return false; }
                if(progress!=null) {
                    try {
                        TimeZoneInfo zone=TimeZoneInfo.Local;
                        TimeSpan offset=zone.GetUtcOffset(DateTime.Now);
                        progress(new ProbeProgress("timezone","本机时区",zone.Id=="China Standard Time" ? "warning" : "info","UTC"+(offset<TimeSpan.Zero ? "-" : "+")+offset.Duration().ToString(@"hh\:mm")+" · "+(zone.IsDaylightSavingTime(DateTime.Now) ? zone.DaylightName : zone.StandardName)));
                    } catch(Exception) { progress(new ProbeProgress("timezone","本机时区","unknown","未取得时区信息")); }
                    progress(new ProbeProgress("match","锁定地址",ip==config.settings.expectedIp ? "ok" : "error",ip==config.settings.expectedIp ? "IPv4 完全匹配" : "IPv4 与锁定地址不同"));
                }
                if(ip != config.settings.expectedIp) { Trip("公网 IPv4 与允许地址不匹配，已阻断",true); BlockPending(); return false; }
                lock(state) {
                    if(startEpoch != epoch) return false;
                    healthy = true; reason = ""; lastVerified = Stopwatch.GetTimestamp();
                }
                return true;
            } catch(Exception e) {
                lock(state) { checkedAt = DateTimeOffset.Now.ToString("o"); }
                Trip("公网 IPv4 校验失败 · " + e.GetBaseException().Message); BlockPending(); return false;
            } finally { lock(state) checking=false; nextCheck = Interlocked.Exchange(ref checkRequested,0)==1 ? DateTime.MinValue : started.AddSeconds(config.settings.intervalSeconds); Publish(); }
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
        void Protect(Target t, bool enabled) {
            if(enabled && !config.rulesLocked) throw new Exception("请先锁定允许的公网 IPv4，再启用程序防护。");
            SystemPolicy.RequireAdmin(); StopTarget(t.id);
            if(enabled) {
                Data.Validate(config.settings); Data.Validate(t, true); RequireClosed(t); SystemPolicy.FirewallHealthy();
                SystemPolicy.Block(t, true);
                try { SystemPolicy.Intercept(t); t.enabled = true; Data.Save(config); }
                catch { SystemPolicy.Unintercept(t); SystemPolicy.RemoveFirewall(t); t.enabled = false; throw; }
            } else {
                SystemPolicy.Unintercept(t); SystemPolicy.RemoveFirewall(t); t.enabled = false; Data.Save(config);
            }
            Log("info", t.name + (enabled ? " · 已接管启动" : " · 已解除防护"));
        }
        object Command(Dictionary<string,object> input) {
            string action = input["action"] as string;
            lock(actions) {
                if(action == "status") return Snapshot();
                if(action == "check") { Check(); return Snapshot(); }
                SystemPolicy.RequireAdmin();
                if(action == "lock") {
                    if(config.rulesLocked) throw new Exception("IP 已锁定，请先取消锁定再修改。");
                    Settings s = Data.Json().Deserialize<Settings>(Data.Json().Serialize(input["settings"])); Data.Validate(s);
                    Data.Save(new Config { settings=s, apps=config.apps, autostart=config.autostart, rulesLocked=true, networkAdapterId=config.networkAdapterId, networkAdapterName=config.networkAdapterName });
                    lock(state) { config.settings = s; config.rulesLocked = true; healthy = false; currentIp = ""; reason = "正在校验锁定的公网 IPv4"; }
                    Log("info", "允许的公网 IPv4 已锁定"); Check();
                } else if(action == "unlock") {
                    if(!config.rulesLocked) return Snapshot();
                    Data.Save(new Config { settings=config.settings, apps=config.apps, autostart=config.autostart, rulesLocked=false, networkAdapterId=config.networkAdapterId, networkAdapterName=config.networkAdapterName });
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
                    bool enabled = (bool)input["enabled"]; SystemPolicy.Autostart(enabled, input["executable"] as string);
                    lock(state) config.autostart = enabled; Data.Save(config); Log("info", enabled ? "已开启登录后启动" : "已关闭登录后启动");
                } else {
                    Target t = Find(input["targetId"] as string);
                    if(action == "protect") Protect(t, (bool)input["enabled"]);
                    else if(action == "edit") {
                        Target changed=new Target { id=t.id,path=t.path,enabled=t.enabled,name=input["name"] as string,arguments=input["arguments"] as string };
                        Data.Validate(changed,false);
                        List<Target> next=config.apps.Select(a=>a.id==t.id ? changed : a).ToList();
                        Data.Save(new Config { settings=config.settings,apps=next,autostart=config.autostart,rulesLocked=config.rulesLocked,networkAdapterId=config.networkAdapterId,networkAdapterName=config.networkAdapterName });
                        lock(state) config.apps=next;
                        Log("info",changed.name+" · 启动配置已更新");
                    }
                    else if(action == "remove") { if(t.enabled) Protect(t, false); lock(state) config.apps.Remove(t); Data.Save(config); }
                    else if(action == "stop") { StopTarget(t.id); SystemPolicy.Block(t,true); Log("info", t.name + " · 已停止并封锁"); }
                    else if(action == "start") {
                        if(!config.rulesLocked) throw new Exception("请先锁定允许的公网 IPv4。");
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
                    lock(actions) {
                        target = Find(request["id"] as string);
                        if(!target.enabled || !String.Equals(target.path,request["path"] as string,StringComparison.OrdinalIgnoreCase)) throw new Exception("该程序未启用启动防护。");
                        writer.WriteLine(Data.Json().Serialize(new { type="context", name=target.name, expectedIp=config.settings.expectedIp }));
                        if(!config.rulesLocked) throw new Exception("请先锁定允许的公网 IPv4。");
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
                        progress(new ProbeProgress("security","系统防护","running","检查防火墙与 IP 锁定"));
                        SystemPolicy.FirewallHealthy();
                        progress(new ProbeProgress("security","系统防护","ok","锁定与防火墙已就绪"));
                        if(!Check(progress)) throw new Exception(reason);
                        if(disconnected) throw new IOException("启动校验窗口已关闭。");
                        string name = "Local\\IPGuard-" + Guid.NewGuid().ToString("D");
                        lock(state) {
                            if(!healthy) throw new Exception(reason);
                            session = new Session { appId=target.id, name=name, job=Win32.NewJob(name), epoch=epoch };
                            sessions.Add(session);
                        }
                        writer.WriteLine(Data.Json().Serialize(new { allow=true, job=name, currentIp=currentIp, expectedIp=config.settings.expectedIp }));
                        Task<string> started = Task.Run(() => reader.ReadLine());
                        if(!started.Wait(8000) || started.Result != "started") throw new Exception("目标进程未完成启动准备。");
                        SystemPolicy.Block(target,false);
                        lock(state) { if(session.stopped || session.epoch != epoch || !healthy) throw new Exception("启动许可已撤销。"); writer.WriteLine("run"); }
                    }
                    Log("info", target.name + " · 校验通过，已启动"); Publish();
                    Task<string> alive = Task.Run(() => reader.ReadLine());
                    while(!quit && !session.stopped && !alive.IsCompleted) {
                        bool stale;
                        lock(state) {
                            if(session.epoch != epoch || !healthy) break;
                            stale = Stopwatch.GetTimestamp()-lastVerified > Stopwatch.Frequency*(config.settings.intervalSeconds+8);
                            if(!stale) writer.WriteLine("lease");
                        }
                        if(stale) { Trip("公网检测结果已过期，已结束受保护程序"); break; }
                        Thread.Sleep(400);
                    }
                } catch(Exception e) {
                    Log("warning", (target == null ? "启动拦截" : target.name) + " · " + e.GetBaseException().Message);
                    try { writer.WriteLine(Data.Json().Serialize(new { allow=false, currentIp=currentIp, expectedIp=config.settings.expectedIp, error=e.GetBaseException().Message, code=e.GetBaseException() is FirewallDisabledException ? FirewallDisabledException.Code : "" })); } catch(IOException) { }
                } finally {
                    if(session != null) lock(state) { session.stopped=true; Win32.TerminateJobObject(session.job,1); Win32.CloseHandle(session.job); sessions.Remove(session); pendingBlock=true; }
                    Publish();
                }
            }
            } catch(IOException e) { Log("info", "启动连接已关闭 · " + e.Message); }
        }
        public void Run() {
            try { BrowserHost.Register(true); } catch(Exception error) { Log("error","浏览器连接注册失败 · "+error.Message); }
            if(config.apps.Any(t => t.enabled) && SystemPolicy.Admin) {
                Trip("守护程序已启动，等待重新校验"); BlockPending();
                foreach(Target t in config.apps.Where(t => t.enabled)) { Data.Validate(t,true); SystemPolicy.Intercept(t); }
            }
            NetworkChange.NetworkAddressChanged += NetworkChanged;
            NetworkChange.NetworkAvailabilityChanged += AvailabilityChanged;
            SystemEvents.PowerModeChanged += PowerChanged;
            if(SystemPolicy.Admin) Background(Listen);
            Background(Dispatch); Background(Loop); Background(WatchNetwork); Publish();
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
                    } catch(Exception e) { Emit(new { id=id, ok=false, error=e.GetBaseException().Message, code=e.GetBaseException() is FirewallDisabledException ? FirewallDisabledException.Code : "", help=e.GetBaseException() is FirewallDisabledException ? FirewallDisabledException.Help : "" }); }
                }
            } finally {
                quit=true; probe.Stop(); commands.CompleteAdding(); Trip("守护程序已退出，受保护程序已结束");
                lock(actions) BlockPending();
                NetworkChange.NetworkAddressChanged -= NetworkChanged; NetworkChange.NetworkAvailabilityChanged -= AvailabilityChanged; SystemEvents.PowerModeChanged -= PowerChanged;
                wifi.Dispose();
            }
        }
        void Dispatch() {
            foreach(Dictionary<string,object> input in commands.GetConsumingEnumerable()) {
                if(quit) return;
                string id=input["id"] as string;
                try { object result=Command(input); Emit(new { id=id,ok=true,data=result }); Publish(); }
                catch(Exception e) { Emit(new { id=id,ok=false,error=e.GetBaseException().Message,code=e.GetBaseException() is FirewallDisabledException ? FirewallDisabledException.Code : "",help=e.GetBaseException() is FirewallDisabledException ? FirewallDisabledException.Help : "" }); }
            }
        }
        void NetworkChanged(object sender,EventArgs e) { Observe("网卡地址发生变化",true); }
        void AvailabilityChanged(object sender,NetworkAvailabilityEventArgs e) { Observe(e.IsAvailable ? "网络连接已切换" : "网络已断开",true); }
        void PowerChanged(object sender,PowerModeChangedEventArgs e) { Observe("系统电源状态改变",true); }
    }
}
