using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace IpGuard {
    public sealed class WifiWatch : IDisposable {
        [StructLayout(LayoutKind.Sequential)] struct Notification {
            public uint source, code; public Guid network; public uint size; public IntPtr data;
        }
        delegate void Callback(ref Notification notification, IntPtr context);
        [DllImport("wlanapi.dll")] static extern uint WlanOpenHandle(uint version, IntPtr reserved, out uint negotiated, out IntPtr handle);
        [DllImport("wlanapi.dll")] static extern uint WlanRegisterNotification(IntPtr handle, uint source, bool ignoreDuplicates, Callback callback, IntPtr context, IntPtr reserved, IntPtr previous);
        [DllImport("wlanapi.dll")] static extern uint WlanCloseHandle(IntPtr handle, IntPtr reserved);
        readonly object sync = new object();
        readonly Callback callback;
        IntPtr handle;
        public WifiWatch(Action<string> notify) {
            callback = delegate(ref Notification n, IntPtr context) {
                if(n.source == 8 && new uint[] { 9,10,11,13,14,15,16,18,20,21,27 }.Contains(n.code)) notify("Wi-Fi 连接发生变化");
            };
        }
        public void Ensure() {
            if(!NetworkInterface.GetAllNetworkInterfaces().Any(n => n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 && n.OperationalStatus == OperationalStatus.Up)) return;
            lock(sync) {
                if(handle != IntPtr.Zero) {
                    if(WlanRegisterNotification(handle,8,true,callback,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero) == 0) return;
                    WlanCloseHandle(handle,IntPtr.Zero); handle=IntPtr.Zero;
                }
                uint version; uint result=WlanOpenHandle(2,IntPtr.Zero,out version,out handle);
                if(result != 0) { handle=IntPtr.Zero; throw new Exception("Wi-Fi 切换通知不可用 · " + result); }
                result=WlanRegisterNotification(handle,8,true,callback,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero);
                if(result != 0) { WlanCloseHandle(handle,IntPtr.Zero); handle=IntPtr.Zero; throw new Exception("Wi-Fi 切换通知注册失败 · " + result); }
            }
        }
        public void Dispose() {
            lock(sync) if(handle != IntPtr.Zero) { WlanCloseHandle(handle,IntPtr.Zero); handle=IntPtr.Zero; }
            GC.KeepAlive(callback);
        }
    }
}
