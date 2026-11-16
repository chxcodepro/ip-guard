using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace IpGuard.ProcessNetwork {
    internal sealed class FortRequest {
        public readonly uint Code;
        readonly byte[] payload;
        internal FortRequest(int index,byte[] payload) {
            if(index!=0 && index!=2) throw new ArgumentOutOfRangeException("index");
            Code=(0xd000U<<16)|(2U<<14)|((0xd00U+(uint)index)<<2);this.payload=(byte[])payload.Clone();
        }
        public byte[] CopyPayload() {return (byte[])payload.Clone();}
    }

    internal sealed class FortPolicy {
        public const ushort ApiVersion=65;
        public const uint Flags=(1U<<0)|(1U<<3)|(1U<<4)|(1U<<5)|(1U<<14);
        readonly string[] paths;
        readonly ushort port;
        readonly bool loopbackDirect;
        readonly ushort[] localPorts;
        public int[] LocalPorts {get {return localPorts.Select(p=>(int)p).ToArray();}}
        static readonly Encoding Utf16=new UnicodeEncoding(false,false,true);

        public FortPolicy(EgressPolicy egress,IEnumerable<string> roots,bool loopbackDirect,IEnumerable<int> localPorts) {
            if(egress==null || roots==null || localPorts==null) throw new ArgumentNullException();
            egress.Validate();port=(ushort)egress.port;
            this.loopbackDirect=loopbackDirect;
            int[] ports=localPorts.Distinct().OrderBy(p=>p).ToArray();
            if(ports.Length>64 || ports.Any(p=>p<1 || p>65535 || p==port)) throw new ArgumentException("本机开发端口无效或与代理端口冲突。");
            this.localPorts=ports.Select(p=>(ushort)p).ToArray();
            paths=roots.Select(NormalizePath).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(p=>p,StringComparer.Ordinal).ToArray();
            if(paths.Length==0 || paths.Length>UInt16.MaxValue) throw new ArgumentException("请提供受控程序的完整 EXE 路径。");
        }
        static string NormalizePath(string path) {
            try {path=OwnedDriverRegistration.LocalPath(path);}
            catch(InvalidDataException error) {throw new ArgumentException("受控根路径须为本机绝对路径。","path",error);}
            if(path.IndexOfAny(new[] {'*','?'})>=0 || !path.EndsWith(".exe",StringComparison.OrdinalIgnoreCase) || path.Length>2048) throw new ArgumentException("受控根路径须为精确的本机 EXE 路径。");
            try {Utf16.GetByteCount(path);} catch(EncoderFallbackException error) {throw new ArgumentException("受控路径的 Unicode 无效。","path",error);}
            path=path.ToLowerInvariant();return Char.ToUpperInvariant(path[0])+path.Substring(1);
        }
        public static FortRequest Validation() {return new FortRequest(0,new[] {(byte)ApiVersion,(byte)(ApiVersion>>8)});}
        static byte[] Bytes(Action<BinaryWriter> write) {
            using(var stream=new MemoryStream()) {using(var writer=new BinaryWriter(stream,Encoding.UTF8,true)) write(writer);return stream.ToArray();}
        }
        static byte[] Filter(int type,byte[] body,bool isNot=false) {
            int size=(4+body.Length+3)&~3;
            return Bytes(w=>{w.Write(((uint)size<<7)|((uint)type<<3)|(isNot ? 1U : 0U));w.Write(body);w.Write(new byte[size-4-body.Length]);});
        }
        byte[] ProxyRule() {
            byte[][] conditions={
                Filter(5,Bytes(w=>w.Write((ushort)1))),
                Filter(6,Bytes(w=>w.Write((ushort)2))),
                Filter(4,new byte[] {1,0,6}),
                Filter(0,Bytes(w=>{w.Write(1U);w.Write(0U);w.Write(0x7f000001U);w.Write(0U);w.Write(0U);})),
                Filter(1,Bytes(w=>{w.Write((byte)1);w.Write((byte)0);w.Write(port);}))
            };
            var alternatives=new List<byte[]> {Filter(15,conditions.SelectMany(c=>c).ToArray())};
            if(loopbackDirect && localPorts.Length==0) alternatives.Add(Filter(8,Bytes(w=>w.Write((ushort)1))));
            else if(localPorts.Length>0) {
                foreach(bool inbound in new[] {false,true}) {
                    var local=new List<byte[]> {
                        Filter(8,Bytes(w=>w.Write((ushort)1))),
                        Filter(6,Bytes(w=>w.Write((ushort)(inbound ? 1 : 2)))),
                    };
                    if(!loopbackDirect) local.Add(Filter(4,new byte[] {1,0,6}));
                    local.Add(Filter(inbound ? 3 : 1,Bytes(w=>{w.Write((byte)localPorts.Length);w.Write((byte)0);foreach(ushort p in localPorts) w.Write(p);}),loopbackDirect));
                    alternatives.Add(Filter(15,local.SelectMany(c=>c).ToArray()));
                }
            }
            byte[] predicate=alternatives.Count==1 ? alternatives[0] : Filter(14,alternatives.SelectMany(c=>c).ToArray());
            // A non-match terminates as blocked; a matching IPv4 TCP proxy request remains allowed.
            return Bytes(w=>{w.Write((ushort)((1<<0)|(1<<5)|(1<<6)|(1<<13)));w.Write((byte)0);w.Write((byte)0);w.Write(predicate);});
        }
        public FortRequest Configuration() {
            byte[] rule=ProxyRule();
            byte[] data=Bytes(w=>{
                w.Write(0UL);
                w.Write(Flags);w.Write((byte)0);w.Write((byte)0);
                w.Write((ushort)0);w.Write((ushort)0);w.Write((ushort)paths.Length);
                w.Write(0U);w.Write(40U);w.Write(40U);w.Write(40U);
                w.Write(8U);w.Write(24U);
                for(int i=0;i<2;i++) {w.Write(13U);w.Write(0U);w.Write(0U);w.Write(0U);}
                for(int i=0;i<paths.Length;i++) {
                    byte[] path=Utf16.GetBytes(paths[i]);
                    w.Write((1U<<1)|(1U<<14));
                    w.Write(0UL);w.Write((ushort)0);w.Write((ushort)0);w.Write(0U);w.Write((uint)(i+1));
                    w.Write((uint)rule.Length);w.Write((ushort)path.Length);w.Write(path);w.Write((ushort)0);w.Write(rule);
                    if(w.BaseStream.Length>64*1024*1024) throw new ArgumentException("受控程序配置超过驱动容量。");
                }
            });
            return new FortRequest(2,data);
        }
    }
}
