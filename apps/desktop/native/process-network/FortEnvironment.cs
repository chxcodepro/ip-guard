using System;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace IpGuard.ProcessNetwork {
    internal sealed class FortEnvironment {
        public readonly bool Known,HvciConfigured,HvciRunning;
        public readonly bool BootFilter,FilterLocals,PersistentBlock;
        public FortEnvironment(bool known,bool configured,bool running,bool bootFilter,bool filterLocals,bool persistentBlock) {
            Known=known;HvciConfigured=configured;HvciRunning=running;BootFilter=bootFilter;FilterLocals=filterLocals;PersistentBlock=persistentBlock;
        }
        public void RequireSupported() {
            RequirePlatform();
            if(!BootFilter || !FilterLocals || !PersistentBlock) throw new InvalidOperationException("持久故障封锁或回环过滤尚未准备，拒绝接入驱动。");
        }
        public void RequirePlatform() {
            if(!Known) throw new InvalidOperationException("无法确认内存完整性状态，驱动接入保持关闭。");
            if(HvciConfigured || HvciRunning) throw new InvalidOperationException("内存完整性已启用或等待启用，拒绝接入 Fort 驱动；系统安全设置保持原样。");
        }
        static bool ContainsHvci(object value) {
            var services=value as uint[];
            if(services==null) throw new InvalidDataException("系统安全状态格式无效。");
            foreach(uint service in services) if(service==2) return true;return false;
        }
        public static FortEnvironment ReadPlatform() {
            bool configured=false,running=false,found=false;
            using(var query=new ManagementObjectSearcher(@"root\Microsoft\Windows\DeviceGuard","SELECT SecurityServicesConfigured,SecurityServicesRunning FROM Win32_DeviceGuard"))
            using(var results=query.Get()) foreach(ManagementObject result in results) using(result) {
                if(found) throw new InvalidDataException("系统安全状态重复。");found=true;
                configured=ContainsHvci(result["SecurityServicesConfigured"]);running=ContainsHvci(result["SecurityServicesRunning"]);
            }
            if(!found) return new FortEnvironment(false,false,false,false,false,false);
            using(RegistryKey machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64)) {
                foreach(string keyName in new[] {@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",@"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"})
                using(RegistryKey key=machine.OpenSubKey(keyName)) if(key!=null) {
                    string name=keyName.StartsWith("SYSTEM",StringComparison.Ordinal) ? "Enabled" : "HypervisorEnforcedCodeIntegrity";
                    object value=key.GetValue(name);
                    if(value!=null && !(value is int)) throw new InvalidDataException("内存完整性策略格式无效。");
                    configured|=value is int && (int)value!=0;
                }
            }
            return new FortEnvironment(true,configured,running,false,false,false);
        }
        public static FortEnvironment Read() {
            FortEnvironment platform=ReadPlatform();platform.RequirePlatform();
            var proof=FortProvider.ReadProtection();
            return new FortEnvironment(true,false,false,proof.BootFilter,proof.FilterLocals,proof.PersistentBlock);
        }
    }
    internal static class BootIdentity {
        [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int informationClass,IntPtr information,uint length,out uint returned);
        public static Guid Read() {
            IntPtr buffer=Marshal.AllocHGlobal(32);
            try {
                uint returned;
                if(NtQuerySystemInformation(90,buffer,32,out returned)<0 || returned<16) throw new InvalidOperationException("无法核对本次 Windows 启动标识，保留恢复封锁。");
                var id=(Guid)Marshal.PtrToStructure(buffer,typeof(Guid));
                if(id==Guid.Empty) throw new InvalidDataException("Windows 启动标识无效。");return id;
            } finally {Marshal.FreeHGlobal(buffer);}
        }
    }
}
