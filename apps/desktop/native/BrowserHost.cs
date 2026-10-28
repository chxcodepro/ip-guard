using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace IpGuard {
    public static class BrowserHost {
        const string Host="com.ipguard.browser";
        static string Manifest { get { return Path.Combine(Data.DirectoryPath,"browser",Host+".json"); } }
        static string[] Browsers { get { return new[] { @"Software\Google\Chrome\NativeMessagingHosts\", @"Software\Microsoft\Edge\NativeMessagingHosts\" }; } }
        public static void Register(bool refreshOnly=false) {
            if(refreshOnly && !File.Exists(Manifest)) return;
            foreach(string browser in Browsers) using(RegistryKey existing=Registry.CurrentUser.OpenSubKey(browser+Host))
                if(existing!=null && !String.Equals(existing.GetValue("") as string,Manifest,StringComparison.OrdinalIgnoreCase)) throw new Exception("浏览器连接注册冲突，请检查现有 IP Guard 安装。");
            Directory.CreateDirectory(Path.GetDirectoryName(Manifest));
            File.WriteAllText(Manifest,Data.Json().Serialize(new { name=Host,description="IP Guard browser connection",path=SystemPolicy.Exe,type="stdio",allowed_origins=new[] { "chrome-extension://"+BuildInfo.ExtensionId+"/" } }),new UTF8Encoding(false));
            foreach(string browser in Browsers) using(RegistryKey key=Registry.CurrentUser.CreateSubKey(browser+Host)) key.SetValue("",Manifest);
        }
        public static void Unregister() {
            foreach(string browser in Browsers) {
                bool own; using(RegistryKey key=Registry.CurrentUser.OpenSubKey(browser+Host)) own=key!=null && String.Equals(key.GetValue("") as string,Manifest,StringComparison.OrdinalIgnoreCase);
                if(own) Registry.CurrentUser.DeleteSubKey(browser+Host,false);
            }
            if(File.Exists(Manifest)) File.Delete(Manifest);
        }
        static byte[] Read(Stream input,int size) {
            byte[] bytes=new byte[size]; int offset=0;
            while(offset<size) { int count=input.Read(bytes,offset,size-offset); if(count==0) throw new EndOfStreamException(); offset+=count; }
            return bytes;
        }
        static void Send(Stream output,string json) {
            byte[] bytes=Encoding.UTF8.GetBytes(json);
            if(bytes.Length>16384) throw new IOException("浏览器消息过长");
            byte[] length=BitConverter.GetBytes((uint)bytes.Length); output.Write(length,0,4); output.Write(bytes,0,bytes.Length); output.Flush();
        }
        public static int Run(string origin) {
            if(origin!="chrome-extension://"+BuildInfo.ExtensionId+"/") return 1;
            using(Stream input=Console.OpenStandardInput()) using(Stream output=Console.OpenStandardOutput()) {
                try {
                    uint size=BitConverter.ToUInt32(Read(input,4),0);
                    if(size==0 || size>16384) return 1;
                    var request=Data.Json().Deserialize<Dictionary<string,object>>(Encoding.UTF8.GetString(Read(input,(int)size)));
                    if(request==null || !request.ContainsKey("action") || request["action"] as string!="watch" || !request.ContainsKey("protocol") || Convert.ToInt32(request["protocol"])!=1) return 1;
                    string version=request.ContainsKey("extensionVersion") ? request["extensionVersion"] as string : "";
                    if(version==null || (version!="" && (!Regex.IsMatch(version,@"^\d{1,5}(?:\.\d{1,5}){1,3}$") || version.Split('.').Any(part=>Int32.Parse(part)>65535)))) return 1;
                    using(NamedPipeClientStream pipe=new NamedPipeClientStream(".","IPGuard-Browser-"+SystemPolicy.Sid,PipeDirection.InOut,PipeOptions.Asynchronous)) {
                        pipe.Connect(2000);
                        byte[] metadata=Encoding.UTF8.GetBytes(Data.Json().Serialize(new { extensionVersion=version })+"\n");pipe.Write(metadata,0,metadata.Length);pipe.Flush();
                        Task.Run(()=>{try { while(input.ReadByte()!=-1) { } } catch(IOException) { } finally { pipe.Dispose(); }});
                        using(StreamReader reader=new StreamReader(pipe,new UTF8Encoding(false),false,1024,true)) {
                            while(true) {
                                Task<string> read=Task.Run(()=>reader.ReadLine());
                                if(!read.Wait(2500) || read.Result==null) throw new IOException("守护连接已断开");
                                Send(output,read.Result);
                            }
                        }
                    }
                } catch(Exception) {
                    try { Send(output,Data.Json().Serialize(new { protocol=1,appVersion=BuildInfo.Version,phase="offline",currentIp="",expectedIp="",checkedAt="",reason="请运行新版 IP Guard，并在设置中准备浏览器扩展" })); } catch(IOException) { }
                    return 1;
                }
            }
        }
    }
}
