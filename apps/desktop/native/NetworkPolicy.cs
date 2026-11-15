using System;
using System.Linq;

namespace IpGuard {
    public sealed class NetworkPolicyConfig {
        public string revision;
        public int[] localPorts;
        public void Validate(int proxyPort) {
            Guid id;
            if(!Guid.TryParseExact(revision,"D",out id) || localPorts==null || localPorts.Length>64 || localPorts.Any(p=>p<1 || p>65535 || p==proxyPort) || localPorts.Distinct().Count()!=localPorts.Length) throw new Exception("本机端口策略无效，请检查重复项或代理端口冲突。");
            localPorts=localPorts.OrderBy(p=>p).ToArray();
        }
    }
}
