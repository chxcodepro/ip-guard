using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace IpGuard {
    public static class ConnectionPolicy {
        [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Display { public string name,description; }
        [StructLayout(LayoutKind.Sequential)] struct Blob { public uint size; public IntPtr data; }
        [StructLayout(LayoutKind.Explicit,Size=16)] struct Value { [FieldOffset(0)] public uint type; [FieldOffset(8)] public IntPtr pointer; }
        [StructLayout(LayoutKind.Sequential)] struct Condition { public Guid field; public uint match; public Value value; }
        [StructLayout(LayoutKind.Sequential)] struct Action { public uint type; public Guid key; }
        [StructLayout(LayoutKind.Explicit,Size=16)] struct Context { [FieldOffset(0)] public ulong raw; [FieldOffset(0)] public Guid key; }
        [StructLayout(LayoutKind.Sequential)] struct Filter {
            public Guid key; public Display display; public uint flags; public IntPtr provider; public Blob providerData;
            public Guid layer,sublayer; public Value weight; public uint conditionCount; public IntPtr conditions;
            public Action action; public Context context; public IntPtr reserved; public ulong id; public Value effectiveWeight;
        }
        static readonly object sync=new object();
        static readonly Guid application=new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971"), universal=new Guid("eebecc03-ced4-4380-819a-2734397b2b74");
        static readonly Guid[] layers={new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82"),new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4"),new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650"),new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f")};
        static readonly string[] kinds={"connect4","connect6","accept4","accept6"};
        const uint Missing=0x80320003;
        [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)] static extern uint FwpmEngineOpen0(string server,uint auth,IntPtr identity,IntPtr session,out IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr engine,uint flags);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionCommit0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr engine);
        [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)] static extern uint FwpmGetAppIdFromFileName0(string path,out IntPtr appId);
        [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr memory);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterAdd0(IntPtr engine,ref Filter filter,IntPtr security,out ulong id);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterGetByKey0(IntPtr engine,ref Guid key,out IntPtr filter);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr engine,ref Guid key);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine,IntPtr template,out IntPtr handle);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterEnum0(IntPtr engine,IntPtr handle,uint requested,out IntPtr entries,out uint count);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine,IntPtr handle);
        static void Check(uint result) { if(result!=0) throw new Win32Exception(unchecked((int)result),"应用连接过滤失败（0x"+result.ToString("X8")+"）"); }
        static IntPtr Open() {
            SystemPolicy.RequireAdmin();
            if(IntPtr.Size!=8 || Marshal.SizeOf(typeof(Filter))!=200 || Marshal.SizeOf(typeof(Condition))!=40) throw new PlatformNotSupportedException("应用连接过滤需要 Windows x64。");
            IntPtr engine;Check(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out engine));return engine;
        }
        static Guid Key(string id,int index) { byte[] bytes=new Guid(id).ToByteArray();bytes[0]^=(byte)(0x91+index);return new Guid(bytes); }
        static string Name(string id,int index) { return SystemPolicy.Owner+"."+id+"."+kinds[index]; }
        public static void Block(Target app,bool blocked) {
            lock(sync) {
                IntPtr engine=Open(),appId=IntPtr.Zero,condition=IntPtr.Zero;
                bool transaction=false;
                try {
                    Check(FwpmTransactionBegin0(engine,0));transaction=true;
                    for(int i=0;i<layers.Length;i++) {
                        Guid key=Key(app.id,i);IntPtr existing;
                        uint result=FwpmFilterGetByKey0(engine,ref key,out existing);
                        if(result==0) {
                            try {
                                Filter found=(Filter)Marshal.PtrToStructure(existing,typeof(Filter));
                                if(found.display.name!=Name(app.id,i) || !String.Equals(found.display.description,app.path,StringComparison.OrdinalIgnoreCase) || found.layer!=layers[i] || found.sublayer!=universal || found.action.type!=0x1001 || found.conditionCount!=1 || found.conditions==IntPtr.Zero) throw new Exception("应用连接过滤项所有者、路径或动作已改变。");
                                Condition stored=(Condition)Marshal.PtrToStructure(found.conditions,typeof(Condition));
                                if(stored.field!=application || stored.match!=0 || stored.value.type!=12) throw new Exception("应用连接过滤条件已改变。");
                            } finally {FwpmFreeMemory0(ref existing);}
                            if(!blocked) Check(FwpmFilterDeleteByKey0(engine,ref key));
                        } else {
                            if(result!=Missing) Check(result);
                            if(!blocked) continue;
                            if(appId==IntPtr.Zero) {
                                Check(FwpmGetAppIdFromFileName0(app.path,out appId));
                                condition=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Condition)));
                                Marshal.StructureToPtr(new Condition {field=application,value=new Value {type=12,pointer=appId}},condition,false);
                            }
                            Filter filter=new Filter {key=key,display=new Display {name=Name(app.id,i),description=app.path},flags=1,layer=layers[i],sublayer=universal,conditionCount=1,conditions=condition,action=new Action {type=0x1001}};
                            ulong filterId;Check(FwpmFilterAdd0(engine,ref filter,IntPtr.Zero,out filterId));
                        }
                    }
                    Check(FwpmTransactionCommit0(engine));transaction=false;
                } finally {
                    if(transaction) FwpmTransactionAbort0(engine);
                    if(condition!=IntPtr.Zero) Marshal.FreeHGlobal(condition);
                    if(appId!=IntPtr.Zero) FwpmFreeMemory0(ref appId);
                    FwpmEngineClose0(engine);
                }
            }
        }
        public static void Recover() {
            lock(sync) {
                IntPtr engine=Open(),enumerator=IntPtr.Zero;
                try {
                    Check(FwpmFilterCreateEnumHandle0(engine,IntPtr.Zero,out enumerator));
                    List<Guid> remove=new List<Guid>();
                    while(true) {
                        IntPtr entries;uint count;Check(FwpmFilterEnum0(engine,enumerator,128,out entries,out count));
                        try {
                            for(int i=0;i<count;i++) {
                                Filter filter=(Filter)Marshal.PtrToStructure(Marshal.ReadIntPtr(entries,i*IntPtr.Size),typeof(Filter));
                                for(int kind=0;kind<kinds.Length;kind++) {
                                    string prefix=SystemPolicy.Owner+".",name=filter.display.name;Guid id;
                                    if(name==null || !name.StartsWith(prefix,StringComparison.Ordinal) || name.Length!=prefix.Length+36+1+kinds[kind].Length) continue;
                                    if(Guid.TryParseExact(name.Substring(prefix.Length,36),"D",out id) && name==Name(id.ToString("D"),kind) && filter.key==Key(id.ToString("D"),kind) && filter.layer==layers[kind]) remove.Add(filter.key);
                                }
                            }
                        } finally {if(entries!=IntPtr.Zero) FwpmFreeMemory0(ref entries);}
                        if(count==0) break;
                    }
                    foreach(Guid value in remove) {Guid key=value;Check(FwpmFilterDeleteByKey0(engine,ref key));}
                } finally {if(enumerator!=IntPtr.Zero) FwpmFilterDestroyEnumHandle0(engine,enumerator);FwpmEngineClose0(engine);}
            }
        }
    }
}
