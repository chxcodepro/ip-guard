using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Net;
using System.Net.Sockets;

namespace IpGuard {
    public sealed class AdapterInfo {
        public string id,name,error="";
        public bool exists,up,ipv4;
    }
    public sealed class ProbeProgress {
        public string step,label,status,detail;
        public ProbeProgress() { }
        public ProbeProgress(string step,string label,string status,string detail) { this.step=step; this.label=label; this.status=status; this.detail=detail; }
    }
    public static class NetworkProbe {
        public static string Adapter="";
        public static AdapterInfo[] Adapters() {
            return NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.NetworkInterfaceType!=NetworkInterfaceType.Loopback)
                .Select(n=>{
                    bool ipv4=false;
                    try { ipv4=n.GetIPProperties().UnicastAddresses.Any(a=>a.Address.AddressFamily==AddressFamily.InterNetwork); }
                    catch(NetworkInformationException) { }
                    return new AdapterInfo { id=n.Id,name=n.Name,exists=true,up=n.OperationalStatus==OperationalStatus.Up,ipv4=ipv4 };
                }).OrderBy(n=>n.name).ToArray();
        }
        public static AdapterInfo Watched(AdapterInfo[] adapters,string id,string name) {
            if(id!="") return adapters.FirstOrDefault(n=>n.id==id) ?? new AdapterInfo { id=id,name=name,exists=false };
            uint index;
            if(Win32.GetBestInterface(BitConverter.ToUInt32(IPAddress.Parse("1.1.1.1").GetAddressBytes(),0),out index)==0) {
                foreach(NetworkInterface n in NetworkInterface.GetAllNetworkInterfaces()) {
                    try { var properties=n.GetIPProperties().GetIPv4Properties(); if(properties!=null && properties.Index==index) { var chosen=adapters.FirstOrDefault(a=>a.id==n.Id); if(chosen!=null) return chosen; } }
                    catch(NetworkInformationException) { }
                }
            }
            return adapters.FirstOrDefault(n=>n.up && n.ipv4) ?? adapters.FirstOrDefault() ?? new AdapterInfo { id="",name="未检测到网卡",exists=false };
        }
        public static string Fingerprint() {
            string[] adapters=NetworkInterface.GetAllNetworkInterfaces()
                .Where(n=>n.NetworkInterfaceType!=NetworkInterfaceType.Loopback)
                .Select(n=>n.Id+":"+n.OperationalStatus+":"+String.Join(",",n.GetIPProperties().UnicastAddresses.Select(a=>a.Address.ToString()).OrderBy(a=>a))+":"+String.Join(",",n.GetIPProperties().GatewayAddresses.Select(a=>a.Address.ToString()).OrderBy(a=>a)))
                .OrderBy(s=>s).ToArray();
            uint size=0; uint result=Win32.GetIpForwardTable(IntPtr.Zero,ref size,true);
            if(result!=122 || size==0) throw new Exception("读取系统路由表失败。");
            IntPtr table=Marshal.AllocHGlobal((int)size);
            try {
                if(Win32.GetIpForwardTable(table,ref size,true)!=0) throw new Exception("读取系统路由表失败。");
                int count=Marshal.ReadInt32(table); string[] rows=new string[count];
                for(int i=0;i<count;i++) {
                    IntPtr row=IntPtr.Add(table,4+i*56);
                    rows[i]=String.Join(":",new[] {0,4,12,16,20,24,32}.Select(o=>Marshal.ReadInt32(row,o).ToString()));
                }
                return String.Join("|",adapters)+"#"+String.Join("|",rows.OrderBy(s=>s));
            } finally { Marshal.FreeHGlobal(table); }
        }
    }
}
