using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace IpGuard.ProcessNetwork {
    internal static class OfflineReview {
        // Only the external Windows driver and Job query are replaced; all encoding and controller logic is real.
        sealed class Device : IFortDevice {
            public FortEnvironment environment=new FortEnvironment(true,false,false,true,true,true);
            public readonly List<FortRequest> requests=new List<FortRequest>();
            public int failAt;
            public FortEnvironment Environment {get {return environment;}}
            public void Send(FortRequest request) {if(requests.Count+1==failAt) throw new IOException("driver rejected request");requests.Add(request);}
        }
        sealed class Jobs : IProtectedJobs {
            public bool active,sealedRegistry;
            public void Seal() {sealedRegistry=true;}
            public bool HasActiveProcesses {get {return active;}}
        }
        static int assertions;
        static void Check(bool ok,string name) {assertions++;if(!ok) throw new Exception("FAIL: "+name);}
        static void Throws<T>(Action action,string name) where T:Exception {try {action();} catch(T) {assertions++;return;}throw new Exception("FAIL: "+name);}
        static EgressPolicy Egress() {return new EgressPolicy {id="ad31925c-d91b-4d91-953d-127bdce75d69",label="offline",port=23456};}
        static FortPolicy Policy(params string[] paths) {return new FortPolicy(Egress(),paths.Length==0 ? new[] {@"C:\apps\claude.exe"} : paths);}
        static string Hex(byte[] bytes) {return BitConverter.ToString(bytes).Replace("-","").ToLowerInvariant();}
        static void ProtocolCases() {
            Check(FortPolicy.Validation().Code==0xd000b400 && Hex(FortPolicy.Validation().CopyPayload())=="4100","Fort ABI 65 validation request");
            FortRequest request=Policy().Configuration();byte[] data=request.CopyPayload();
            Check(request.Code==0xd000b408 && data.Length==208,"SETCONF code and SDK structure lengths");
            Check(BitConverter.ToUInt32(data,8)==0x4039,"boot, filtering, loopback, LAN and outside-allow flags");
            Check(BitConverter.ToUInt16(data,18)==1 && BitConverter.ToUInt32(data,32)==40,"exact app count and data-relative offset");
            Check(BitConverter.ToUInt32(data,76)==0x4002,"kernel recursive parent-rule inheritance");
            Check(BitConverter.ToUInt32(data,100)==64 && BitConverter.ToUInt16(data,104)==36,"app rule and UTF-16 length");
            const string rule="61200000 781e0000 28040000 01000000 30040000 02000000 20040000 01000600 000c0000 01000000 00000000 0100007f 00000000 00000000 08040000 0100a05b";
            Check(Hex(data.Skip(144).ToArray())==rule.Replace(" ",""),"documented IPv4/outbound/TCP/loopback/port AND predicate with terminal deny");
            data[8]=0;Check(BitConverter.ToUInt32(request.CopyPayload(),8)==0x4039,"caller cannot mutate stored commands");
            Check(Policy(@"C:\APPS\CLAUDE.EXE",@"c:\apps\claude.exe").Configuration().CopyPayload().Length==208,"canonical paths deduplicate");
            byte[] unicode=Policy(@"C:\工具\claude.exe").Configuration().CopyPayload();
            Check(BitConverter.ToUInt16(unicode,104)==32,"Unicode path length is bytes");
            foreach(string path in new[] {@"\\server\claude.exe",@"relative\claude.exe",@"C:\apps\*.exe",@"C:\apps\claude.cmd",@"C:\apps\claude.exe:payload"})
                Throws<ArgumentException>(()=>Policy(path),"invalid root rejected");
            Throws<ArgumentException>(()=>new FortPolicy(Egress(),new string[0]),"empty root list rejected");
            EgressPolicy invalid=Egress();invalid.port=0;
            Throws<Exception>(()=>new FortPolicy(invalid,new[] {@"C:\apps\claude.exe"}),"missing fixed proxy rejected");
        }
        static void StateCases() {
            var device=new Device();var jobs=new Jobs();var gate=new List<bool>();
            var controller=new ProcessNetworkController(device,Policy(),jobs,v=>gate.Add(v));
            Check(device.requests.Count==2 && !gate.Last() && controller.Phase==ControllerPhase.Paused,"gate closed before one-time kernel configuration");
            for(int i=0;i<20;i++) {controller.SetReady(true);controller.SetReady(false);}
            Check(device.requests.Count==2 && !gate.Last(),"network retries change the gate, not kernel policy or processes");
            jobs.active=true;controller.BeginDrain();
            Check(jobs.sealedRegistry && !controller.CompleteDrain(),"active jobs retain enforcement");
            jobs.active=false;Check(controller.CompleteDrain() && controller.Phase==ControllerPhase.Stopped,"empty sealed jobs release controller");
            controller.VerifyDrained(device);
            Throws<InvalidOperationException>(()=>controller.VerifyDrained(new Device()),"different device cannot borrow a drain proof");
            jobs.active=true;Throws<InvalidOperationException>(()=>controller.VerifyDrained(device),"late active job retains enforcement");jobs.active=false;
            Throws<InvalidOperationException>(()=>controller.SetReady(true),"stopped controller never resumes");
            foreach(var environment in new[] {
                new FortEnvironment(false,false,false,true,true,true),new FortEnvironment(true,true,false,true,true,true),
                new FortEnvironment(true,false,true,true,true,true),new FortEnvironment(true,false,false,false,true,true),
                new FortEnvironment(true,false,false,true,false,true),new FortEnvironment(true,false,false,true,true,false)
            }) {
                var unsupported=new Device {environment=environment};var closed=new List<bool>();
                Throws<InvalidOperationException>(()=>new ProcessNetworkController(unsupported,Policy(),new Jobs(),v=>closed.Add(v)),"unsafe platform or incomplete bootstrap rejected");
                Check(unsupported.requests.Count==0 && !closed.Last(),"preflight refusal writes no driver configuration");
            }
            var busy=new Device();
            Throws<InvalidOperationException>(()=>new ProcessNetworkController(busy,Policy(),new Jobs {active=true},v=>{}),"live apps prevent initial reconfiguration");
            Check(busy.requests.Count==0,"no policy overwrite for live jobs");
            var failure=new Device {failAt=2};var events=new List<bool>();
            Throws<IOException>(()=>new ProcessNetworkController(failure,Policy(),new Jobs(),v=>events.Add(v)),"kernel configuration refusal propagates");
            Check(!events.Last(),"configuration refusal keeps gate closed");
            var faultGate=new List<bool>();var fault=new ProcessNetworkController(new Device(),Policy(),new Jobs(),v=>faultGate.Add(v));
            fault.SetReady(true);fault.DriverFault(new IOException("offline"));
            Check(!faultGate.Last() && fault.Phase==ControllerPhase.Faulted,"driver fault closes existing forwarding");
            Throws<InvalidOperationException>(()=>fault.SetReady(true),"fault requires explicit recovery");
        }
        static void RecoveryCases() {
            // Expected identities come from Fort v3.20.9 fortguid.h/fortprov.c and the Windows FWPM_FILTER0 ABI.
            Check(Marshal.SizeOf(typeof(FortProvider.Filter))==200 && Marshal.OffsetOf(typeof(FortProvider.Filter),"layer").ToInt32()==64 && Marshal.OffsetOf(typeof(FortProvider.Filter),"action").ToInt32()==128,"x64 FWPM_FILTER0 read/write layout");
            string[] boot={"72af05f1-4b4d-4485-b852-85407c0be405","20406f5a-0819-471d-8499-bca022c284f0","87135302-8994-41d0-9dd0-06b28e8409ee","e789730b-7973-4a62-949f-b2fdef6d8578"};
            string[] persist={"1811ad5c-dfbd-485a-a1ff-1018c56ec772","e6c87910-11d8-481e-9d1c-0ff0cbf2aee7","46b0ff23-137e-47af-9689-ee589fe1615d","22006cb4-3723-4c13-9a93-719ce21557f7"};
            string[] layers={"c38d57d1-05a7-4c33-904f-7fbceee60e82","4a72393b-319f-44bc-84c3-ba54dcb3b6b4","e1cd9fe7-f4b5-4273-96c0-592e487b8650","a3b42c97-9f04-4672-b87e-cee9c483257f"};
            string[] directions={"Connect4","Connect6","Accept4","Accept6"};
            Guid sublayer=new Guid("afa06cd5-4942-4fdf-8a4a-2edeb25bbece"),universal=new Guid("eebecc03-ced4-4380-819a-2734397b2b74");
            IntPtr provider=Marshal.AllocHGlobal(16);
            try {
                for(int kind=0;kind<2;kind++) for(int i=0;i<4;i++) {
                    bool isBoot=kind==0;IntPtr name=Marshal.StringToHGlobalUni((isBoot ? "FortBootFilter" : "FortPersistFilter")+directions[i]);
                    try {
                        var filter=new FortProvider.Filter {key=new Guid(isBoot ? boot[i] : persist[i]),display=new FortProvider.Display {name=name},flags=isBoot ? 10U : 9U,layer=new Guid(layers[i]),sublayer=isBoot ? universal : sublayer,action=new FortProvider.NativeAction {type=0x1001}};
                        Check(FortProvider.MatchesBlock(filter,i,isBoot),"native filter with no provider key is recognized independently of provider existence");
                        filter.flags|=0x20;Check(FortProvider.MatchesBlock(filter,i,isBoot),"disabled owned filter remains removable");filter.flags&=~0x20U;
                        filter.conditionCount=1;Check(!FortProvider.MatchesBlock(filter,i,isBoot),"conditional same-key filter is preserved");filter.conditionCount=0;
                        Marshal.StructureToPtr(Guid.NewGuid(),provider,false);filter.provider=provider;
                        Check(!FortProvider.MatchesBlock(filter,i,isBoot),"explicit foreign provider is preserved");
                        Marshal.StructureToPtr(FortProvider.Provider,provider,false);
                        Check(FortProvider.MatchesBlock(filter,i,isBoot),"owned bootstrap provider is accepted");
                        filter.layer=Guid.Empty;Check(!FortProvider.MatchesBlock(filter,i,isBoot),"same key on a different layer is preserved");
                    } finally {Marshal.FreeHGlobal(name);}
                }
                string[] keys={"91cf8b80-7bb2-42ba-8a26-8242e14532fc","c2d858f8-2951-4eed-8da1-a4930f8e5204"};
                string[] names={"FortFilterConnect4","FortFilterReauthIn4"};
                for(int i=0;i<2;i++) {
                    IntPtr name=Marshal.StringToHGlobalUni(names[i]);
                    try {
                        var filter=new FortProvider.Filter {key=new Guid(keys[i]),display=new FortProvider.Display {name=name},sublayer=sublayer,action=new FortProvider.NativeAction {type=i==0 ? 0x4005U : 0x2006U}};
                        Check(FortProvider.MatchesRuntime(filter),"providerless runtime filter is removable");
                        filter.sublayer=Guid.Empty;Check(!FortProvider.MatchesRuntime(filter),"foreign sublayer is preserved");
                    } finally {Marshal.FreeHGlobal(name);}
                }
            } finally {Marshal.FreeHGlobal(provider);}
            Check(OwnedDriverRegistration.ServicePath(@"\??\C:\ProgramData\IPGuard\CommandProtection\driver\fortfw.sys")==@"C:\ProgramData\IPGuard\CommandProtection\driver\fortfw.sys","NT driver path normalizes without executable quoting");
        }
        static void BrowserRetirementCases() {
            foreach(string image in new[] {"chrome.exe","msedge.exe","CHROME.EXE","firefox.exe","brave.exe"})
                Check(BrowserRetirement.IsBrowser(Path.Combine(@"C:\fixture",image)),"browser targets are retired regardless of installation directory or case");
            foreach(string image in new[] {"claude.exe","Claude.exe","node.exe"})
                Check(!BrowserRetirement.IsBrowser(Path.Combine(@"C:\fixture",image)),"CLI and Desktop target names remain eligible");
            var browser=new Target {path=@"C:\fixture\chrome.exe",enabled=true,enhanced=true};
            var cli=new Target {path=@"C:\fixture\claude.exe",enabled=true,enhanced=true};
            var desktop=new Target {path=@"C:\fixture\Claude.exe",enabled=false,enhanced=false};
            var config=new Config {apps=new List<Target> {browser,cli,desktop},commandProtection=true,rulesLocked=true};
            var released=new List<Target>();
            Check(BrowserRetirement.Detach(config,target=>released.Add(target)),"browser migration runs for deployed entries");
            Check(released.SequenceEqual(new[] {browser}) && config.apps.SequenceEqual(new[] {cli,desktop}),"migration releases only browser policies and retains native entries");
            Check(config.commandProtection && config.rulesLocked && cli.enhanced && !desktop.enabled,"migration retains program selections and lock state");
            Check(!BrowserRetirement.Detach(config,target=>{throw new Exception("repeat release");}),"a second startup does not repeat the migration");
            config.apps=new List<Target> {browser};
            Throws<IOException>(()=>BrowserRetirement.Detach(config,target=>{throw new IOException("release failure");}),"failed OS cleanup retains the browser record for retry");
            Check(config.apps.Single()==browser,"failed cleanup keeps recovery ownership");
            BrowserRetirement.Detach(config,target=>{});
            Check(config.apps.Count==0 && !config.commandProtection,"removing the last enhanced browser never starts a driver");
        }
        static void ModelCases() {
            Check(ClaudeCodeScope.Options(new[] {"claude.exe","--","--model","deepseek-chat"}).Count==0,"model-like prompt text after end-of-options is not a model override");
            Check(!ClaudeCodeScope.Options(new[] {"claude.exe","--system-prompt","--model","deepseek-chat"}).ContainsKey("--model"),"a model-like system prompt value is not mistaken for a model flag");
            Check(ClaudeCodeScope.Options(new[] {"claude.exe","--system-prompt","--model","--model=claude-sonnet"})["--model"]=="claude-sonnet","real model flag follows unrelated option values");
            Throws<InvalidDataException>(()=>ClaudeCodeScope.Options(new[] {"claude.exe","--unknown-option","--model","deepseek-chat"}),"unsupported argument grammar stays unknown rather than loosening protection");
            Check(ClaudeCodeScope.Classify("auto",false,new ModelEvidence {apiBase="https://api.anthropic.com",model="claude-sonnet-4-5"}).kind=="claude","official Claude API is protected");
            Check(ClaudeCodeScope.Classify("auto",false,new ModelEvidence {apiBase="https://api.deepseek.com/anthropic",model="deepseek-flash[1M]"}).Other,"DeepSeek Anthropic-compatible API remains a non-Claude session");
            Check(ClaudeCodeScope.Classify("auto",false,new ModelEvidence {apiBase="http://127.0.0.1:3456",model="claude-opus-4-5"}).kind=="claude","Claude model behind an arbitrary loopback gateway is protected");
            Check(ClaudeCodeScope.Classify("auto",false,new ModelEvidence {apiBase="http://127.0.0.1:3456",model="deepseek-chat"}).Other,"DeepSeek model behind the same gateway keeps original networking");
            Check(ClaudeCodeScope.Classify("auto",false,new ModelEvidence {apiBase="http://localhost:3456",model="custom-route"}).kind=="unknown","hidden model alias is not guessed");
            Check(ClaudeCodeScope.Classify("other",false,new ModelEvidence {unknown=true}).Other,"explicit non-Claude route marking applies to new sessions");
            Check(ClaudeCodeScope.Classify("other",true,new ModelEvidence {apiBase="https://api.deepseek.com"}).kind=="claude","strict command filtering protects every managed root");
            Check(ClaudeCodeScope.Classify("claude",false,new ModelEvidence {apiBase="https://api.deepseek.com"}).kind=="claude","explicit Claude marking overrides host detection");
            Check(ClaudeCodeScope.Classify("auto",false,new ModelEvidence {model="deepseek-chat"}).kind=="claude","a model name alone never changes the default official API");
            Check(ClaudeCodeScope.Classify("auto",false,new ModelEvidence {apiBase="https://api.deepseek.com.evil",model=""}).kind=="unknown","lookalike provider hosts are not trusted");
            Check(ClaudeCodeScope.Classify("auto",false,new ModelEvidence {apiBase="https://api.deepseek.com",cloud=true}).kind=="claude","cloud Claude selection takes precedence over a stale base URL");
            Check(ClaudeCodeScope.Classify("auto",false,new ModelEvidence {apiBase="http://127.0.0.1:1234",model=null}).kind=="unknown","malformed model metadata stays protected");
            Check(ClaudeCodeScope.LocalGateway(new ModelEvidence {apiBase="http://127.0.0.1:3456"}),"loopback API gateway is identified before applying a remote fixed proxy");
            Check(ClaudeCodeScope.LocalGateway(new ModelEvidence {apiBase="http://[::1]:3456"}),"IPv6 loopback API remains local");
            Check(ClaudeCodeScope.LocalGateway(new ModelEvidence {apiBase="http://[fd00::1]:3456"}),"IPv6 unique-local API cannot be forwarded as a remote gateway");
            Check(ClaudeCodeScope.LocalGateway(new ModelEvidence {apiBase="http://[fe80::1]:3456"}),"IPv6 link-local API cannot be forwarded as a remote gateway");
            Check(ClaudeCodeScope.LocalGateway(new ModelEvidence {apiBase="http://[::ffff:192.168.1.2]:3456"}),"mapped IPv4 LAN API remains local");
            Check(!ClaudeCodeScope.LocalGateway(new ModelEvidence {apiBase="https://[2606:4700:4700::1111]"}),"public IPv6 API remains eligible for the fixed channel");
            Check(!ClaudeCodeScope.LocalGateway(new ModelEvidence {apiBase="https://api.anthropic.com"}),"remote official API is eligible for the fixed channel");
        }
        static void RetiredModelTestCases() {
            var config=new Config {apps=new List<Target> {new Target {apiScope="other",enabled=true},new Target {apiScope="auto",enabled=false}}};
            Check(Data.MigrateModelTest(config,new Dictionary<string,object> {{"protectAllModels",true}}),"retired test field triggers one explicit migration");
            Check(config.apps.All(target=>target.apiScope=="claude") && config.apps[0].enabled && !config.apps[1].enabled && !config.commandProtection,"migration retains effective scope without enabling programs or a driver");
            var unchanged=new Config {apps=new List<Target> {new Target {apiScope="other"}}};
            Check(Data.MigrateModelTest(unchanged,new Dictionary<string,object> {{"protectAllModels",false}}) && unchanged.apps[0].apiScope=="other","disabled legacy test preserves entry choices");
            Check(!Data.MigrateModelTest(unchanged,new Dictionary<string,object>()),"current configuration has no repeat migration");
            Throws<Exception>(()=>Data.MigrateModelTest(unchanged,new Dictionary<string,object> {{"protectAllModels","true"}}),"invalid retired field is not silently ignored");
        }
        public static int Main(string[] args) {
            if(args.Length!=1 || args[0]!="--self-check") {Console.WriteLine("Offline Fort adapter. --self-check uses memory only; no driver or service access.");return 2;}
            try {
                ProtocolCases();StateCases();RecoveryCases();BrowserRetirementCases();ModelCases();RetiredModelTestCases();EnhancementCases();ProxySettingsCases();
                Check(StartupPolicy.MissingTask(new FileNotFoundException()),"missing task mapped to a .NET file exception remains a missing-task result");
                Check(StartupPolicy.MissingTask(new COMException("missing",unchecked((int)0x80070002))),"raw COM missing-task HRESULT remains supported");
                Check(!StartupPolicy.MissingTask(new UnauthorizedAccessException()),"scheduler access denial stays a visible failure");
                Check(!StartupPolicy.MissingTask(new DirectoryNotFoundException()),"a missing scheduler directory stays a visible failure");
                Check(!StartupPolicy.MissingTask(new COMException("missing",unchecked((int)0x80070005))),"error classification uses HRESULT instead of message text");
                Check(StartupPolicy.Assess(true,false,false,false,0,false).state=="error","requested but missing startup task is not reported enabled");
                Check(StartupPolicy.Assess(false,false,false,false,0,false).state=="off","disabled startup remains off");
                Check(!StartupPolicy.Assess(true,true,false,true,0,false).enabled,"disabled registered task is ineffective");
                Check(!StartupPolicy.Assess(true,true,true,false,0,false).enabled,"wrong startup action is ineffective");
                Check(StartupPolicy.Assess(true,true,true,true,0x41303,false).state=="waiting","Windows task not-yet-run status waits for next logon");
                Check(StartupPolicy.Assess(true,true,true,true,0,false).state=="ready","successful task stays enabled");
                Check(StartupPolicy.Assess(true,true,true,true,2,false).state=="error","failed task is shown with a repair action");
                Check(StartupPolicy.Assess(true,true,true,true,0x41301,true).state=="running","running task is not misclassified as an error");
                Console.WriteLine("PASS: "+assertions+" offline assertions. No driver loaded or opened.");return 0;
            }
            catch(Exception error) {Console.Error.WriteLine(error);return 1;}
        }
        static void EnhancementCases() {
            var legacy=new Config {commandProtection=true,apps=new List<Target> {new Target {enabled=true},new Target {enabled=false}}};
            var absent=new System.Collections.ArrayList {new Dictionary<string,object>(),new Dictionary<string,object>()};
            Check(Data.MigrateEnhancement(legacy,absent) && legacy.apps[0].enhanced && !legacy.apps[1].enhanced,"legacy active filtering retains only its existing enabled roots");
            var normal=new Config {apps=new List<Target> {new Target {enabled=true},new Target {enabled=true}}};
            Check(Data.MigrateEnhancement(normal,absent) && normal.apps.All(t=>!t.enhanced) && !normal.commandProtection,"normal programs stay default-off");
            var explicitChoices=new System.Collections.ArrayList {new Dictionary<string,object> {{"enhanced",true}},new Dictionary<string,object> {{"enhanced",false}}};
            Check(Data.MigrateEnhancement(normal,explicitChoices) && normal.commandProtection && normal.apps[0].enhanced && !normal.apps[1].enhanced,"each entry selects its own filtering independent of its neighbour");
            Throws<Exception>(()=>Data.MigrateEnhancement(normal,new System.Collections.ArrayList {new Dictionary<string,object> {{"enhanced","true"}},new Dictionary<string,object>()}),"invalid enhancement fields are rejected");
        }
        static void ProxySettingsCases() {
            var proxy=EgressEnvironment.ProxyVariables(Egress());
            Check(new[] {"HTTP_PROXY","http_proxy","HTTPS_PROXY","https_proxy","ALL_PROXY","all_proxy"}.All(key=>proxy[key]=="http://127.0.0.1:23456"),"every proxy alias uses the guarded port");
            Check(proxy["NO_PROXY"]=="" && proxy["no_proxy"]=="" && proxy["CLAUDE_CODE_PROXY_RESOLVES_HOSTS"]=="1","bypass lists clear and proxy handles DNS");
            string original="{\"model\":\"deepseek-flash[1M]\",\"permissions\":{\"allow\":[\"Read\"]},\"env\":{\"ANTHROPIC_BASE_URL\":\"https://api.deepseek.com/anthropic\",\"ANTHROPIC_AUTH_TOKEN\":\"fixture-token\",\"HTTPS_PROXY\":\"http://127.0.0.1:21126\",\"https_proxy\":\"http://127.0.0.1:21126\",\"NO_PROXY\":\"*\",\"CUSTOM\":\"keep\"}}";
            var merged=Data.Json().Deserialize<Dictionary<string,object>>(ClaudeProxySettings.Merge(original,Egress()));
            var env=(Dictionary<string,object>)merged["env"];
            Check(env["HTTPS_PROXY"] as string==Egress().Url && env["https_proxy"] as string==Egress().Url && env["NO_PROXY"] as string=="","session settings override the old user proxy and bypass");
            Check(env["ANTHROPIC_BASE_URL"] as string=="https://api.deepseek.com/anthropic" && env["ANTHROPIC_AUTH_TOKEN"] as string=="fixture-token" && env["CUSTOM"] as string=="keep" && merged["model"] as string=="deepseek-flash[1M]" && merged.ContainsKey("permissions"),"DeepSeek endpoint, model, credentials and unrelated settings remain intact");
            var overlay=Data.Json().Deserialize<Dictionary<string,object>>(ClaudeProxySettings.Merge(null,Egress()));
            Check(overlay.Count==1 && ((Dictionary<string,object>)overlay["env"]).Count==9,"default session overlay leaves provider settings to existing files");
            string[] prompt={"claude.exe","--system-prompt","--settings","--","--settings","message"};
            Check(ClaudeProxySettings.SettingsIndex(prompt)==-1,"settings-looking values and prompt text are never removed");
            string[] command={"claude.exe","--resume","--settings=custom.json","--model","deepseek-chat","--","message"};
            int selected=ClaudeProxySettings.SettingsIndex(command);
            Check(selected==2 && ClaudeProxySettings.Replace(command,selected,@"C:\session.json").SequenceEqual(new[] {"claude.exe","--settings",@"C:\session.json","--resume","--model","deepseek-chat","--","message"}),"existing settings replacement retains resume, model and prompt tokens");
            string[] spaced={"claude.exe","--settings","original.json","-p","message"};
            Check(ClaudeProxySettings.Replace(spaced,ClaudeProxySettings.SettingsIndex(spaced),"session.json").SequenceEqual(new[] {"claude.exe","--settings","session.json","-p","message"}),"separate settings file syntax is replaced once");
            Check(ClaudeProxySettings.Replace(prompt,-1,"session.json").Skip(3).SequenceEqual(prompt.Skip(1)),"adding an overlay retains every original argument");
            Throws<InvalidDataException>(()=>ClaudeProxySettings.SettingsIndex(new[] {"claude.exe","--settings","a.json","--settings=b.json"}),"duplicate settings are rejected before launching");
            Throws<InvalidDataException>(()=>ClaudeProxySettings.SettingsIndex(new[] {"claude.exe","--settings"}),"missing settings value is rejected");
            Throws<InvalidDataException>(()=>ClaudeProxySettings.SettingsIndex(new[] {"claude.exe","--unknown-value","--settings","a.json"}),"ambiguous option values are not rewritten");
            Throws<InvalidDataException>(()=>ClaudeProxySettings.Merge("{\"env\":true}",Egress()),"invalid environment object is rejected");
            Throws<InvalidDataException>(()=>ClaudeProxySettings.Merge("{\"env\":{\"CUSTOM\":true}}",Egress()),"invalid environment value is rejected");
            try {ClaudeProxySettings.Merge("{private-fixture",Egress());throw new Exception("expected malformed JSON rejection");}
            catch(InvalidDataException error) {Check(!error.Message.Contains("private-fixture"),"invalid settings errors do not include source contents");}
        }
    }
}
