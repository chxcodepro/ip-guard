using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace IpGuard.ProcessNetwork {
    internal static class DriverBinaryTrust {
        [StructLayout(LayoutKind.Sequential)] struct TrustFile {
            public uint size;
            public IntPtr path,handle,subject;
        }
        [StructLayout(LayoutKind.Sequential)] struct TrustData {
            public uint size;
            public IntPtr policy,sip;
            public uint ui,revocation,choice;
            public IntPtr file;
            public uint action;
            public IntPtr state,url;
            public uint flags,context;
            public IntPtr signature;
        }
        [DllImport("wintrust.dll",ExactSpelling=true)] static extern int WinVerifyTrust(IntPtr window,ref Guid action,ref TrustData data);

        public static FileStream VerifyAndPin(string path) {
            var locked=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
            try {
                Guid action=new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
                IntPtr name=IntPtr.Zero,file=IntPtr.Zero;
                var trust=new TrustData {size=(uint)Marshal.SizeOf(typeof(TrustData)),ui=2,choice=1,action=1,flags=0x1000};
                try {
                    name=Marshal.StringToHGlobalUni(path);file=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TrustFile)));trust.file=file;
                    var info=new TrustFile {size=(uint)Marshal.SizeOf(typeof(TrustFile)),path=name,handle=locked.SafeFileHandle.DangerousGetHandle()};
                    Marshal.StructureToPtr(info,file,false);
                    int result=WinVerifyTrust(new IntPtr(-1),ref action,ref trust);
                    if(result!=0) throw new Win32Exception(result,"驱动签名验证失败，保持防护接入关闭。");
                } finally {
                    trust.action=2;
                    try {if(trust.state!=IntPtr.Zero) WinVerifyTrust(new IntPtr(-1),ref action,ref trust);}
                    finally {if(file!=IntPtr.Zero) Marshal.FreeHGlobal(file);if(name!=IntPtr.Zero) Marshal.FreeHGlobal(name);}
                }
                using(var signer=new X509Certificate2(X509Certificate.CreateFromSignedFile(path))) {
                    if(signer.GetNameInfo(X509NameType.SimpleName,false)!="Microsoft Windows Hardware Compatibility Publisher") throw new InvalidDataException("驱动发布者与已评估组件不匹配。");
                }
                FileVersionInfo version=FileVersionInfo.GetVersionInfo(path);
                if(locked.Length!=118832 || !String.Equals(version.OriginalFilename,"fortfw.sys",StringComparison.OrdinalIgnoreCase)
                    || version.ProductMajorPart!=1 || version.ProductMinorPart!=0 || version.ProductBuildPart!=0 || version.ProductPrivatePart!=0)
                    throw new InvalidDataException("驱动文件与已评估的 Fort x64 加载器不匹配。");
                return locked;
            } catch {locked.Dispose();throw;}
        }
    }
}
