using System;
using System.IO;
using System.Text;

namespace IpGuard {
    public sealed class PipeWriter : StreamWriter {
        public PipeWriter(Stream stream) : base(stream,new UTF8Encoding(false),1024,true) { AutoFlush=true; }
        protected override void Dispose(bool disposing) {
            try { base.Dispose(disposing); }
            catch(IOException) { }
            catch(ObjectDisposedException) { }
        }
    }
}
