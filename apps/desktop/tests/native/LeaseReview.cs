using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;
using IpGuard;

public static class LeaseReview {
    static void Check(bool condition,string message) {if(!condition) throw new Exception(message);Console.WriteLine("PASS "+message);}
    static void Wait(Func<bool> condition,int timeout,string message) {
        Stopwatch clock=Stopwatch.StartNew();
        while(!condition() && clock.ElapsedMilliseconds<timeout) Thread.Sleep(10);
        Check(condition(),message);
    }
    static void WithLease(Action<LaunchGate.Lease,StreamWriter,NamedPipeServerStream> review) {
        string name="IPGuard-LeaseReview-"+Guid.NewGuid().ToString("N");
        using(var server=new NamedPipeServerStream(name,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous))
        using(var client=new NamedPipeClientStream(".",name,PipeDirection.InOut,PipeOptions.Asynchronous)) {
            Task connected=Task.Factory.StartNew(()=>server.WaitForConnection(),CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
            client.Connect(5000);if(!connected.Wait(5000)) throw new TimeoutException("review pipe connection");
            using(var reader=new StreamReader(client))
            using(var writer=new PipeWriter(server))
            using(var lease=new LaunchGate.Lease(IntPtr.Zero)) {
                lease.Begin(reader);
                review(lease,writer,server);
                server.Dispose();client.Dispose();
            }
        }
    }
    static void SaturatedPool() {
        int workers,io,minWorkers,minIo;
        ThreadPool.GetMaxThreads(out workers,out io);ThreadPool.GetMinThreads(out minWorkers,out minIo);
        int workerLimit=Environment.ProcessorCount;
        using(var occupied=new CountdownEvent(workerLimit))
        using(var release=new ManualResetEvent(false)) {
            var blockers=new List<Task>();
            try {
                Check(ThreadPool.SetMinThreads(workerLimit,minIo) && ThreadPool.SetMaxThreads(workerLimit,io),"review reserves the worker pool");
                for(int i=0;i<workerLimit;i++) blockers.Add(Task.Run(()=>{occupied.Signal();release.WaitOne();}));
                Check(occupied.Wait(5000),"worker pool is occupied by blocking operations");
                WithLease((lease,writer,server)=>{
                    for(int i=0;i<25;i++) {writer.WriteLine("lease");Thread.Sleep(100);}
                    Check(lease.Alive() && lease.HeartbeatAgeMilliseconds<1000,"heartbeats continue while the worker pool is unavailable");
                    server.Dispose();
                    Wait(()=>lease.stopped,2000,"pipe closure revokes the lease without waiting for the heartbeat timeout");
                    bool closed=false;
                    try {lease.RequireAlive();} catch(IOException) {closed=true;}
                    Check(closed,"pipe closure is reported separately from a heartbeat timeout");
                });
            } finally {
                release.Set();
                ThreadPool.SetMaxThreads(workers,io);ThreadPool.SetMinThreads(minWorkers,minIo);
                if(!Task.WaitAll(blockers.ToArray(),5000)) throw new TimeoutException("review worker cleanup");
            }
        }
    }
    static void DelayedHeartbeat() {
        WithLease((lease,writer,server)=>{
            Check(LaunchGate.Lease.TimeoutMilliseconds==10000,"heartbeat loss has a bounded ten-second deadline");
            Thread.Sleep(2500);
            lease.RequireAlive();
            Check(lease.Alive(),"a short scheduling pause retains the protected session");
            writer.WriteLine("lease");
            Wait(()=>lease.HeartbeatAgeMilliseconds<1000,2000,"a fresh heartbeat renews the deadline after a scheduling pause");
            Wait(()=>!lease.Alive(),12000,"a connected but silent guardian eventually loses its lease");
            bool expired=false;
            try {lease.RequireAlive();}
            catch(TimeoutException error) {expired=error.Message.Contains("PID") && error.Message.Contains("10000");}
            Check(expired,"timeout diagnostics identify the gate and heartbeat deadline");
        });
    }
    public static int Main() {
        try {SaturatedPool();DelayedHeartbeat();return 0;}
        catch(Exception error) {Console.Error.WriteLine(error);return 1;}
    }
}
