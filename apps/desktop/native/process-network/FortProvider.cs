using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

namespace IpGuard.ProcessNetwork {
    internal static class FortProvider {
        internal static readonly Guid Provider=new Guid("012b3999-b791-463e-918c-c32b53e9350e");
        static readonly Guid Sublayer=new Guid("afa06cd5-4942-4fdf-8a4a-2edeb25bbece");
        static readonly Guid[] PersistFilters={new Guid("1811ad5c-dfbd-485a-a1ff-1018c56ec772"),new Guid("e6c87910-11d8-481e-9d1c-0ff0cbf2aee7"),new Guid("46b0ff23-137e-47af-9689-ee589fe1615d"),new Guid("22006cb4-3723-4c13-9a93-719ce21557f7")};
        static readonly Guid[] BootFilters={new Guid("72af05f1-4b4d-4485-b852-85407c0be405"),new Guid("20406f5a-0819-471d-8499-bca022c284f0"),new Guid("87135302-8994-41d0-9dd0-06b28e8409ee"),new Guid("e789730b-7973-4a62-949f-b2fdef6d8578")};
        static readonly Guid[] Layers={new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82"),new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4"),new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650"),new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f")};
        static readonly Guid Universal=new Guid("eebecc03-ced4-4380-819a-2734397b2b74");
        const string BootstrapName="IP Guard Command Protection";
        static readonly string[] Directions={"Connect4","Connect6","Accept4","Accept6"};
        // Fort 3.20.9 sets no providerKey on filters; the fixed keys and owned sublayer identify them.
        static readonly Dictionary<Guid,string> RuntimeFilters=new Dictionary<Guid,string> {
            {new Guid("91cf8b80-7bb2-42ba-8a26-8242e14532fc"),"FortFilterConnect4"},
            {new Guid("86510e3e-84c0-4e38-bdf5-3395917251c3"),"FortFilterConnect6"},
            {new Guid("544a3e25-7beb-4970-88ef-b4bca2ce2482"),"FortFilterAccept4"},
            {new Guid("f2985354-c225-4289-8d01-80a87cf6d7b4"),"FortFilterAccept6"},
            {new Guid("f515d62b-26a3-413e-874c-d65ce70c9aef"),"FortFilterInTransport4"},
            {new Guid("fdbb79a9-773d-4028-b4b4-ad99cafcaefc"),"FortFilterInTransport6"},
            {new Guid("d284afe8-4caf-4432-a753-b6f311bda2ba"),"FortFilterOutTransport4"},
            {new Guid("a14e1fae-e1d7-42e0-851c-6f3a1b89bead"),"FortFilterOutTransport6"},
            {new Guid("aaa99e30-54bb-4bc4-981b-e86ef3cfe816"),"FortFilterInTransportDiscard4"},
            {new Guid("8f1e581d-6b09-425d-9af6-ed5aa162db31"),"FortFilterInTransportDiscard6"},
            {new Guid("26cf28b2-f503-4e02-a0ec-f70013c4677d"),"FortFilterInIpPacketDiscard4"},
            {new Guid("bc6efefd-2030-4adf-a612-e8d319699459"),"FortFilterInIpPacketDiscard6"},
            {new Guid("c2d858f8-2951-4eed-8da1-a4930f8e5204"),"FortFilterReauthIn4"},
            {new Guid("635f7606-e920-4d6d-8222-6c3a514c703e"),"FortFilterReauthIn6"},
            {new Guid("749709ce-9686-4056-b89a-7a5852dfc898"),"FortFilterReauthOut4"},
            {new Guid("b3db1623-c317-4e04-a9d1-5482960eb70c"),"FortFilterReauthOut6"}
        };
        [StructLayout(LayoutKind.Sequential)] internal struct Display {public IntPtr name,description;}
        [StructLayout(LayoutKind.Sequential)] internal struct Blob {public uint size;public IntPtr data;}
        [StructLayout(LayoutKind.Sequential)] struct ProviderInfo {public Guid key;public Display display;public uint flags;public Blob data;public IntPtr service;}
        [StructLayout(LayoutKind.Sequential)] struct ObjectPrefix {public Guid key;public Display display;public uint flags;public IntPtr provider;}
        [StructLayout(LayoutKind.Explicit,Size=16)] internal struct Value {[FieldOffset(0)]public uint type;[FieldOffset(8)]public IntPtr pointer;}
        [StructLayout(LayoutKind.Sequential)] internal struct NativeAction {public uint type;public Guid key;}
        [StructLayout(LayoutKind.Explicit,Size=16)] internal struct Context {[FieldOffset(0)]public ulong value;[FieldOffset(0)]public Guid key;}
        [StructLayout(LayoutKind.Sequential)] internal struct Filter {
            public Guid key;public Display display;public uint flags;public IntPtr provider;public Blob data;
            public Guid layer,sublayer;public Value weight;public uint conditionCount;public IntPtr conditions;
            public NativeAction action;public Context context;public IntPtr reserved;public ulong id;public Value effectiveWeight;
        }
        [StructLayout(LayoutKind.Sequential)] struct AddSublayer {public Guid key;public Display display;public uint flags;public IntPtr provider;public Blob data;public ushort weight;}
        [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)] static extern uint FwpmEngineOpen0(string server,uint auth,IntPtr identity,IntPtr session,out IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr data);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmProviderGetByKey0(IntPtr engine,ref Guid key,out IntPtr info);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerGetByKey0(IntPtr engine,ref Guid key,out IntPtr info);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterGetByKey0(IntPtr engine,ref Guid key,out IntPtr info);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmCalloutCreateEnumHandle0(IntPtr engine,IntPtr template,out IntPtr enumeration);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmCalloutEnum0(IntPtr engine,IntPtr enumeration,uint count,out IntPtr entries,out uint returned);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmCalloutDestroyEnumHandle0(IntPtr engine,IntPtr enumeration);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr engine,ref Guid key);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmCalloutDeleteByKey0(IntPtr engine,ref Guid key);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine,ref Guid key);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmProviderDeleteByKey0(IntPtr engine,ref Guid key);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr engine,uint flags);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionCommit0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmProviderAdd0(IntPtr engine,ref ProviderInfo provider,IntPtr security);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerAdd0(IntPtr engine,ref AddSublayer sublayer,IntPtr security);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterAdd0(IntPtr engine,ref Filter filter,IntPtr security,out ulong id);
        delegate uint CreateEnum(IntPtr engine,IntPtr template,out IntPtr enumeration);
        delegate uint Enumerate(IntPtr engine,IntPtr enumeration,uint count,out IntPtr entries,out uint returned);
        delegate uint DestroyEnum(IntPtr engine,IntPtr enumeration);
        static void Check(uint error) {if(error!=0) throw new Win32Exception(unchecked((int)error),"Fort WFP 操作失败：0x"+error.ToString("X8"));}
        static bool Owned(IntPtr provider) {return provider!=IntPtr.Zero && (Guid)Marshal.PtrToStructure(provider,typeof(Guid))==Provider;}

        internal static bool MatchesBlock(Filter filter,int index,bool boot) {
            string nativeName=(boot ? "FortBootFilter" : "FortPersistFilter")+Directions[index];
            string name=Marshal.PtrToStringUni(filter.display.name);
            return filter.key==(boot ? BootFilters[index] : PersistFilters[index]) &&
                (filter.provider==IntPtr.Zero ? name==nativeName : Owned(filter.provider) && (name==nativeName || name==BootstrapName)) &&
                filter.layer==Layers[index] && filter.sublayer==(boot ? Universal : Sublayer) &&
                (filter.flags&~0x20U)==(boot ? 10U : 9U) && filter.action.type==0x1001 && filter.conditionCount==0;
        }
        internal static bool MatchesRuntime(Filter filter) {
            string name;
            return RuntimeFilters.TryGetValue(filter.key,out name) && Marshal.PtrToStringUni(filter.display.name)==name &&
                (filter.provider==IntPtr.Zero || Owned(filter.provider)) && filter.sublayer==Sublayer && filter.conditionCount==0 &&
                (name.StartsWith("FortFilterReauth",StringComparison.Ordinal) ? filter.action.type==0x2006 : filter.action.type==0x4005);
        }
        static bool MatchesFilter(Filter filter) {
            for(int i=0;i<4;i++) if(filter.key==BootFilters[i] || filter.key==PersistFilters[i]) {
                if(!MatchesBlock(filter,i,filter.key==BootFilters[i])) throw new InvalidDataException("Fort 封锁项身份变化，保留该事务："+filter.key);
                return true;
            }
            return MatchesRuntime(filter);
        }
        static void ValidateSublayer(IntPtr engine) {
            Guid key=Sublayer;IntPtr pointer;uint status=FwpmSubLayerGetByKey0(engine,ref key,out pointer);
            if(status==0x80320007) return;Check(status);
            try {
                var sub=(AddSublayer)Marshal.PtrToStructure(pointer,typeof(AddSublayer));string name=Marshal.PtrToStringUni(sub.display.name);
                if(!Owned(sub.provider) || (name!="FortSublayer" && name!=BootstrapName)) throw new InvalidDataException("Fort 子层归属不匹配，保留现有规则。");
            } finally {FwpmFreeMemory0(ref pointer);}
        }

        static bool ProviderData(IntPtr engine,out uint flags,out bool enabled) {
            flags=0;enabled=false;IntPtr pointer;Guid key=Provider;
            uint status=FwpmProviderGetByKey0(engine,ref key,out pointer);
            if(status==0x80320005) return false;Check(status);
            try {
                var info=(ProviderInfo)Marshal.PtrToStructure(pointer,typeof(ProviderInfo));
                if(info.key!=Provider || Marshal.PtrToStringUni(info.service)!="fortfw" || info.data.size!=4 || info.data.data==IntPtr.Zero || (info.flags&1)==0) throw new InvalidDataException("Fort 持久提供者与预期不匹配。");
                flags=unchecked((uint)Marshal.ReadInt32(info.data.data));enabled=(info.flags&0x10)==0;return true;
            } finally {FwpmFreeMemory0(ref pointer);}
        }
        public static FortEnvironment ReadProtection() {
            IntPtr engine;Check(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out engine));
            try {
                uint flags;bool enabled;if(!ProviderData(engine,out flags,out enabled)) return new FortEnvironment(true,false,false,false,false,false);
                bool complete=enabled && flags==3;
                for(int i=0;i<8;i++) {
                    bool boot=i>=4;int index=i%4;Guid key=boot ? BootFilters[index] : PersistFilters[index];IntPtr pointer;
                    uint status=FwpmFilterGetByKey0(engine,ref key,out pointer);
                    if(status==0x80320003) {complete=false;continue;}Check(status);
                    try {
                        var filter=(Filter)Marshal.PtrToStructure(pointer,typeof(Filter));
                        complete&=MatchesBlock(filter,index,boot) && (filter.flags&0x20)==0;
                    } finally {FwpmFreeMemory0(ref pointer);}
                }
                return new FortEnvironment(true,false,false,(flags&1)!=0,(flags&2)!=0,complete);
            } finally {FwpmEngineClose0(engine);}
        }
        static List<Guid> Keys(IntPtr engine,CreateEnum create,Enumerate enumerate,DestroyEnum destroy) {
            IntPtr enumeration;Check(create(engine,IntPtr.Zero,out enumeration));var keys=new List<Guid>();
            try {
                while(true) {
                    IntPtr entries;uint count;Check(enumerate(engine,enumeration,256,out entries,out count));
                    try {
                        if(count>256 || (count!=0 && entries==IntPtr.Zero)) throw new InvalidDataException("WFP 枚举结果无效，保留现有规则。");
                        for(int i=0;i<count;i++) {
                            IntPtr pointer=Marshal.ReadIntPtr(entries,i*IntPtr.Size);
                            var item=(ObjectPrefix)Marshal.PtrToStructure(pointer,typeof(ObjectPrefix));if(Owned(item.provider)) keys.Add(item.key);
                        }
                    } finally {if(entries!=IntPtr.Zero) FwpmFreeMemory0(ref entries);}
                    if(count<256) break;
                }
            } finally {destroy(engine,enumeration);}
            return keys;
        }
        internal static void RemoveOwnedObjects(OwnedDriverRegistration record) {
            if(record==null) throw new ArgumentNullException("record");
            var current=OwnedDriverRegistration.Read();
            if(current==null || current.OwnerSid!=record.OwnerSid || current.DriverPath!=record.DriverPath) throw new InvalidOperationException("驱动所有权已变化，保留现有规则。");
            if(OwnedDriverRegistration.FindFortConflict()!=null) throw new InvalidOperationException("其他 Fort 服务仍存在，保留其规则。");
            record.ValidateStopped();
            IntPtr engine;Check(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out engine));bool transaction=false,filtersRemoved=false;
            try {
                Check(FwpmTransactionBegin0(engine,0));transaction=true;
                uint flags;bool enabled;bool providerPresent=ProviderData(engine,out flags,out enabled);ValidateSublayer(engine);
                var filters=new List<Guid>();var known=new List<Guid>(PersistFilters);known.AddRange(BootFilters);known.AddRange(RuntimeFilters.Keys);
                // Default enumeration omits boot-time and disabled filters, so query every pinned key.
                foreach(Guid value in known) {
                    Guid key=value;IntPtr pointer;
                    uint status=FwpmFilterGetByKey0(engine,ref key,out pointer);if(status==0x80320003) continue;Check(status);
                    try {
                        if(!MatchesFilter((Filter)Marshal.PtrToStructure(pointer,typeof(Filter)))) throw new InvalidDataException("Fort 过滤项身份变化，保留该事务："+key);
                        filters.Add(key);
                    } finally {FwpmFreeMemory0(ref pointer);}
                }
                foreach(Guid value in filters) {Guid key=value;Check(FwpmFilterDeleteByKey0(engine,ref key));}
                Check(FwpmTransactionCommit0(engine));transaction=false;filtersRemoved=true;
                // Metadata cleanup must never roll the removed BLOCK filters back into service.
                Check(FwpmTransactionBegin0(engine,0));transaction=true;
                foreach(Guid value in Keys(engine,FwpmCalloutCreateEnumHandle0,FwpmCalloutEnum0,FwpmCalloutDestroyEnumHandle0)) {Guid key=value;Check(FwpmCalloutDeleteByKey0(engine,ref key));}
                Guid sublayer=Sublayer;uint subStatus=FwpmSubLayerDeleteByKey0(engine,ref sublayer);if(subStatus!=0x80320007) Check(subStatus);
                if(providerPresent) {Guid provider=Provider;Check(FwpmProviderDeleteByKey0(engine,ref provider));}
                Check(FwpmTransactionCommit0(engine));transaction=false;
            } catch(Exception error) {
                if(filtersRemoved) throw new InvalidOperationException("已撤销确认归属的过滤项，WFP 容器清理尚未完成："+error.Message,error);
                throw;
            } finally {if(transaction) FwpmTransactionAbort0(engine);FwpmEngineClose0(engine);}
        }
        internal static void ArmOwned(OwnedDriverRegistration record) {
            RemoveOwnedObjects(record);
            IntPtr engine;Check(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out engine));bool transaction=false;
            IntPtr provider=Marshal.AllocHGlobal(16),data=Marshal.AllocHGlobal(4),name=Marshal.StringToHGlobalUni("IP Guard Command Protection"),service=Marshal.StringToHGlobalUni("fortfw");
            try {
                Marshal.StructureToPtr(Provider,provider,false);Marshal.WriteInt32(data,3);
                Check(FwpmTransactionBegin0(engine,0));transaction=true;
                var info=new ProviderInfo {key=Provider,display=new Display {name=name},flags=1,data=new Blob {size=4,data=data},service=service};
                Check(FwpmProviderAdd0(engine,ref info,IntPtr.Zero));
                var sub=new AddSublayer {key=Sublayer,display=new Display {name=name},flags=1,provider=provider,weight=UInt16.MaxValue};
                Check(FwpmSubLayerAdd0(engine,ref sub,IntPtr.Zero));
                for(int i=0;i<4;i++) {
                    var persist=new Filter {key=PersistFilters[i],display=new Display {name=name},flags=9,provider=provider,layer=Layers[i],sublayer=Sublayer,action=new NativeAction {type=0x1001}};
                    ulong id;Check(FwpmFilterAdd0(engine,ref persist,IntPtr.Zero,out id));
                    var boot=new Filter {key=BootFilters[i],display=new Display {name=name},flags=10,provider=provider,layer=Layers[i],sublayer=Universal,action=new NativeAction {type=0x1001}};
                    Check(FwpmFilterAdd0(engine,ref boot,IntPtr.Zero,out id));
                }
                Check(FwpmTransactionCommit0(engine));transaction=false;
            } finally {
                if(transaction) FwpmTransactionAbort0(engine);FwpmEngineClose0(engine);
                Marshal.FreeHGlobal(provider);Marshal.FreeHGlobal(data);Marshal.FreeHGlobal(name);Marshal.FreeHGlobal(service);
            }
        }
    }
}
