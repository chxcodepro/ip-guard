using System;
using System.Collections.Generic;
using System.Threading;

namespace IpGuard {
    public sealed class ClaudeProbeResult {
        public string ip,error,checkedAt,adapter;
    }
    public sealed class ClaudeProbe {
        sealed class Pending {
            public readonly ManualResetEventSlim signal=new ManualResetEventSlim(false);
            public Action<ProbeProgress> progress;
            public ClaudeProbeResult result;
        }
        readonly object sync=new object();
        readonly Dictionary<string,Pending> pending=new Dictionary<string,Pending>();
        readonly Action<object> emit;
        bool stopped;
        public ClaudeProbe(Action<object> emit) { this.emit=emit; }
        public ClaudeProbeResult Read(Action<ProbeProgress> progress) {
            string id=Guid.NewGuid().ToString("D"); Pending request=new Pending { progress=progress };
            lock(sync) { if(stopped) throw new Exception("Claude 出口检测服务正在退出。"); pending.Add(id,request); }
            try {
                emit(new { type="probe",id=id });
                if(!request.signal.Wait(8000)) throw new Exception("Claude AI 出口 IPv4 检测服务未响应。");
                ClaudeProbeResult result=request.result;
                if(result==null) throw new Exception("Claude AI 出口 IPv4 检测已取消。");
                if(!String.IsNullOrEmpty(result.error)) throw new Exception(result.error);
                if(!Data.PublicV4(result.ip)) throw new Exception("Claude AI 出口未返回有效公网 IPv4。");
                DateTimeOffset checkedAt;
                if(!DateTimeOffset.TryParse(result.checkedAt,out checkedAt) || (DateTimeOffset.UtcNow-checkedAt).TotalSeconds>8 || checkedAt>DateTimeOffset.UtcNow.AddSeconds(1)) throw new Exception("Claude AI 出口 IPv4 检测结果已过期。");
                return result;
            } finally {
                lock(sync) pending.Remove(id);
                request.signal.Dispose();
            }
        }
        public void Receive(Dictionary<string,object> input) {
            string id=input.ContainsKey("id") ? input["id"] as string : null;
            lock(sync) {
                Pending request;
                if(id==null || !pending.TryGetValue(id,out request)) return;
                if(input["action"] as string=="probe-progress") {
                    ProbeProgress value=Data.Json().Deserialize<ProbeProgress>(Data.Json().Serialize(input["data"]));
                    if(value!=null && request.progress!=null) request.progress(value);
                } else {
                    request.result=Data.Json().Deserialize<ClaudeProbeResult>(Data.Json().Serialize(input["data"]));
                    request.signal.Set();
                }
            }
        }
        public void Stop() {
            lock(sync) { stopped=true; foreach(Pending request in pending.Values) request.signal.Set(); }
        }
    }
}
