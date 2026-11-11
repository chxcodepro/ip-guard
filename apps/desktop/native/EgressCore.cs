using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace IpGuard {
    public static class EgressCore {
        public static int Run(string[] args) {
            Console.SetIn(new StreamReader(Console.OpenStandardInput(),new UTF8Encoding(false)));
            Guid id;
            if(args.Length!=3 || !Guid.TryParseExact(args[1],"D",out id) || (args[2]!="xray" && args[2]!="sing-box")) return 1;
            string exe=Path.Combine(Data.DirectoryPath,"egress",id.ToString("D"),args[2]+".exe");
            if(!File.Exists(exe)) return 1;
            string config=Console.ReadLine();
            if(config==null || config.Length>1048576) return 1;
            IntPtr job=Win32.NewJob(null);
            try {
                var start=new ProcessStartInfo(exe,args[2]=="xray" ? "run -config stdin:" : "run -c stdin") {UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
                using(Process process=Process.Start(start)) {
                    if(process==null) return 1;
                    try { Win32.Check(Win32.AssignProcessToJobObject(job,process.Handle)); }
                    catch {try {process.Kill();} catch(InvalidOperationException) {} throw;}
                    process.OutputDataReceived+=(s,e)=>{};process.ErrorDataReceived+=(s,e)=>{};
                    process.BeginOutputReadLine();process.BeginErrorReadLine();
                    using(StreamWriter writer=new StreamWriter(process.StandardInput.BaseStream,new UTF8Encoding(false))) writer.Write(config);
                    Task eof=Task.Run(()=>{while(Console.ReadLine()!=null) {}});
                    while(!process.WaitForExit(100)) if(eof.IsCompleted) return 0;
                    return process.ExitCode;
                }
            } finally {Win32.TerminateJobObject(job,1);Win32.CloseHandle(job);}
        }
    }
}
