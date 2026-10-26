using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace IpGuard {
    public sealed class LaunchWindow : Form {
        sealed class Step { public string id,label,status,detail; public double appeared; }
        readonly List<Step> steps=new List<Step>();
        readonly Stopwatch clock=Stopwatch.StartNew();
        readonly System.Windows.Forms.Timer timer=new System.Windows.Forms.Timer { Interval=16 };
        readonly TaskCompletionSource<bool> released=new TaskCompletionSource<bool>();
        readonly Font textFont=new Font("Microsoft YaHei UI",13,FontStyle.Regular,GraphicsUnit.Pixel);
        readonly Font smallFont=new Font("Microsoft YaHei UI",12,FontStyle.Regular,GraphicsUnit.Pixel);
        readonly Font headingFont=new Font("Microsoft YaHei UI",19,FontStyle.Bold,GraphicsUnit.Pixel);
        readonly Font ipFont=new Font("Consolas",24,FontStyle.Regular,GraphicsUnit.Pixel);
        readonly Font brandFont=new Font("Segoe UI",13,FontStyle.Bold,GraphicsUnit.Pixel);
        readonly Font buttonFont;
        readonly Color ink,muted,line,surface,soft,green,greenSoft,red,amber;
        readonly bool motion;
        readonly float scale;
        readonly Button ackButton,firewallButton,closeButton;
        string name, currentIp="", expectedIp="", reason="", phase="running";
        double completed=-1;
        bool finishing;
        volatile bool cancelled;
        public event Action CancelRequested;
        [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
        [DllImport("user32.dll")] static extern bool SystemParametersInfo(uint action,uint parameter,out bool value,uint flags);
        [DllImport("user32.dll")] static extern bool ReleaseCapture();
        [DllImport("user32.dll")] static extern IntPtr SendMessage(IntPtr hwnd,uint message,IntPtr wparam,IntPtr lparam);
        [DllImport("shell32.dll",CharSet=CharSet.Unicode)] static extern int SetCurrentProcessExplicitAppUserModelID(string id);
        public static void ConfigureApplication() { SetProcessDPIAware(); SetCurrentProcessExplicitAppUserModelID("IPGuard.Startup"); Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false); }
        public LaunchWindow(string appName) {
            name=appName;
            bool animate; motion=!SystemParametersInfo(0x1042,0,out animate,0) || animate;
            bool dark=false;
            using(RegistryKey theme=Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")) dark=theme!=null && Convert.ToInt32(theme.GetValue("AppsUseLightTheme",1))==0;
            ink=ColorTranslator.FromHtml(dark ? "#E8F0EC" : "#172D25"); muted=ColorTranslator.FromHtml(dark ? "#8FA49B" : "#62776D");
            surface=ColorTranslator.FromHtml(dark ? "#171F1C" : "#FCFDFB"); soft=ColorTranslator.FromHtml(dark ? "#1D2A24" : "#F1F6F2");
            line=ColorTranslator.FromHtml(dark ? "#2C3B33" : "#E0E9E1"); green=ColorTranslator.FromHtml(dark ? "#78DCAE" : "#137E51");
            greenSoft=ColorTranslator.FromHtml(dark ? "#243C30" : "#E9F5EC"); red=ColorTranslator.FromHtml(dark ? "#F18E91" : "#BE4E57"); amber=ColorTranslator.FromHtml(dark ? "#E7C17D" : "#916617");
            using(Graphics graphics=Graphics.FromHwnd(IntPtr.Zero)) scale=graphics.DpiX/96f;
            buttonFont=new Font(textFont.FontFamily,textFont.Size*scale,FontStyle.Regular,GraphicsUnit.Pixel);
            AutoScaleMode=AutoScaleMode.None; ClientSize=new Size((int)(680*scale),(int)(438*scale));
            FormBorderStyle=FormBorderStyle.None; ShowInTaskbar=false; StartPosition=FormStartPosition.CenterScreen; TopMost=true; KeyPreview=true;
            Text="IP Guard · 启动校验"; BackColor=surface; Opacity=motion ? 0.01 : 1;
            SetStyle(ControlStyles.AllPaintingInWmPaint|ControlStyles.UserPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.ResizeRedraw,true);
            using(GraphicsPath shape=Round(new RectangleF(0,0,ClientSize.Width,ClientSize.Height),18*scale)) Region=new Region(shape);
            ackButton=CreateButton("知道了",Ack,green,surface); ackButton.Visible=false; ackButton.Click+=(sender,args)=>Close();
            firewallButton=CreateButton("打开 Windows 防火墙",Firewall,soft,green); firewallButton.Visible=false;
            firewallButton.Click+=(sender,args)=>{
                TopMost=false; reason="防火墙属性 → 域 / 专用 / 公用 → 状态设为“启用” → 确定后重试";
                try { SystemPolicy.OpenFirewall(); } catch(Exception error) { reason="打开失败 · "+error.GetBaseException().Message+"；Win+R 输入 wf.msc"; } Invalidate();
            };
            closeButton=CreateButton("×",new RectangleF(635,19,26,26),surface,muted); closeButton.AccessibleName="关闭启动校验"; closeButton.Click+=(sender,args)=>Close();
            AcceptButton=ackButton; AccessibleName="IP Guard 启动校验";
            timer.Tick+=(sender,args)=>TickScene(); Shown+=(sender,args)=>{clock.Restart(); timer.Start();};
        }
        Button CreateButton(string label,RectangleF rect,Color background,Color foreground) {
            Button button=new Button { Text=label, AccessibleName=label, FlatStyle=FlatStyle.Flat, BackColor=background, ForeColor=foreground, Font=buttonFont,
                Bounds=new Rectangle((int)(rect.X*scale),(int)(rect.Y*scale),(int)(rect.Width*scale),(int)(rect.Height*scale)), UseVisualStyleBackColor=false, Cursor=Cursors.Hand };
            button.FlatAppearance.BorderSize=0; button.FlatAppearance.MouseOverBackColor=background==surface ? soft : background==green ? ControlPaint.Dark(green,0.1f) : greenSoft;
            using(GraphicsPath shape=Round(new RectangleF(0,0,button.Width,button.Height),7*scale)) button.Region=new Region(shape);
            Controls.Add(button); return button;
        }
        protected override CreateParams CreateParams { get { CreateParams p=base.CreateParams; p.ClassStyle|=0x20000; p.ExStyle|=0x80; return p; } }
        void Post(Action action) { if(IsDisposed || !IsHandleCreated) return; try { BeginInvoke(action); } catch(InvalidOperationException) { } }
        public void Context(string appName,string expected) { Post(()=>{name=appName; expectedIp=expected ?? ""; AccessibleDescription=name+"，锁定 IP："+expectedIp; Invalidate();}); }
        public void Progress(ProbeProgress item) {
            Post(()=>{
                if(phase!="running") return;
                Step step=steps.Find(s=>s.id==item.step);
                if(step==null) { step=new Step { id=item.step, appeared=steps.Count==0 ? clock.Elapsed.TotalMilliseconds : Math.Max(clock.Elapsed.TotalMilliseconds,steps[steps.Count-1].appeared+(motion ? 85 : 0)) }; steps.Add(step); }
                step.label=item.label; step.status=item.status; step.detail=item.detail;
                if(item.step=="ipv4" && item.status=="ok") currentIp=item.detail;
                AccessibleDescription=name+"，"+item.label+"："+item.detail;
                Invalidate();
            });
        }
        public void Success(string ip,string expected) { Post(()=>{currentIp=ip; expectedIp=expected; phase="complete"; AccessibleDescription="校验通过，公网 IP："+ip; completed=clock.Elapsed.TotalMilliseconds; Invalidate();}); }
        public void Block(string message,string ip,string expected,bool firewall) {
            Post(()=>{
                if(cancelled) return;
                currentIp=ip ?? currentIp; expectedIp=expected ?? expectedIp; reason=message; phase="blocked"; completed=clock.Elapsed.TotalMilliseconds;
                AccessibleDescription="启动已阻断，"+reason+"，当前 IP："+currentIp+"，锁定 IP："+expectedIp;
                foreach(Step step in steps) if(step.status=="running") step.status="error";
                timer.Start(); Opacity=1; ackButton.Visible=true; firewallButton.Visible=firewall;
                if(!Visible) Show(); Activate(); ackButton.Focus(); Invalidate();
            });
        }
        public bool WaitForRelease(Func<bool> alive) {
            while(!released.Task.Wait(80)) { if(cancelled || !alive()) return false; }
            return released.Task.Result && !cancelled && alive();
        }
        public void End() { Post(()=>{if(phase!="blocked") { finishing=true; Close(); }}); }
        public void Cancel() { if(cancelled) return; cancelled=true; released.TrySetResult(false); Action action=CancelRequested; if(action!=null) action(); }
        void TickScene() {
            double now=clock.Elapsed.TotalMilliseconds;
            if(Visible && phase=="running" && motion) Opacity=Math.Min(1,now/160);
            if(phase=="complete") {
                double end=Math.Max(completed+2200,steps.Count==0 ? 0 : steps[steps.Count-1].appeared+180);
                if(now>=end) { Hide(); timer.Stop(); released.TrySetResult(true); }
                else if(motion && now>=end-200) Opacity=Math.Max(0.01,(end-now)/200);
                else Opacity=1;
            }
            if(phase=="blocked" && (steps.Count==0 || now>=steps[steps.Count-1].appeared+170)) timer.Stop();
            if(Visible) Invalidate();
        }
        protected override void OnFormClosing(FormClosingEventArgs e) { if(!finishing) Cancel(); base.OnFormClosing(e); }
        protected override void OnKeyDown(KeyEventArgs e) { if(e.KeyCode==Keys.Escape || (phase=="blocked" && e.KeyCode==Keys.Enter)) { Close(); e.Handled=true; } base.OnKeyDown(e); }
        PointF Logical(Point point) { return new PointF(point.X/scale,point.Y/scale); }
        RectangleF Ack { get { return new RectangleF(482,382,166,34); } }
        RectangleF Firewall { get { return new RectangleF(250,382,212,34); } }
        protected override void OnMouseDown(MouseEventArgs e) {
            PointF p=Logical(e.Location);
            if(e.Button==MouseButtons.Left && p.Y<66 && p.X<620) { ReleaseCapture(); SendMessage(Handle,0xA1,new IntPtr(2),IntPtr.Zero); }
            base.OnMouseDown(e);
        }
        static GraphicsPath Round(RectangleF r,float radius) { GraphicsPath p=new GraphicsPath(); float d=radius*2; p.AddArc(r.X,r.Y,d,d,180,90); p.AddArc(r.Right-d,r.Y,d,d,270,90); p.AddArc(r.Right-d,r.Bottom-d,d,d,0,90); p.AddArc(r.X,r.Bottom-d,d,d,90,90); p.CloseFigure(); return p; }
        void Fill(Graphics g,Color color,RectangleF rect,float radius) { using(Brush b=new SolidBrush(color)) using(GraphicsPath p=Round(rect,radius)) g.FillPath(b,p); }
        void Label(Graphics g,string value,Font font,Color color,RectangleF rect,StringAlignment alignment=StringAlignment.Near) {
            using(Brush brush=new SolidBrush(color)) using(StringFormat format=new StringFormat { Alignment=alignment, LineAlignment=StringAlignment.Center, Trimming=StringTrimming.EllipsisCharacter, FormatFlags=font==smallFont && rect.Height>30 ? 0 : StringFormatFlags.NoWrap }) g.DrawString(value ?? "",font,brush,rect,format);
        }
        void Checkmark(Graphics g,PointF center,float amount,Color color,float size=1) {
            PointF a=new PointF(center.X-10*size,center.Y), b=new PointF(center.X-3*size,center.Y+7*size), c=new PointF(center.X+12*size,center.Y-9*size);
            using(Pen pen=new Pen(color,2.7f*size) { StartCap=LineCap.Round, EndCap=LineCap.Round, LineJoin=LineJoin.Round }) {
                if(amount<0.35) g.DrawLine(pen,a,new PointF(a.X+(b.X-a.X)*amount/0.35f,a.Y+(b.Y-a.Y)*amount/0.35f));
                else { g.DrawLine(pen,a,b); float n=Math.Min(1,(amount-0.35f)/0.65f); g.DrawLine(pen,b,new PointF(b.X+(c.X-b.X)*n,b.Y+(c.Y-b.Y)*n)); }
            }
        }
        protected override void OnPaint(PaintEventArgs e) {
            Graphics g=e.Graphics; g.SmoothingMode=SmoothingMode.AntiAlias; g.TextRenderingHint=TextRenderingHint.ClearTypeGridFit; g.ScaleTransform(scale,scale); g.Clear(surface);
            using(Pen border=new Pen(line,1)) using(GraphicsPath edge=Round(new RectangleF(0.5f,0.5f,679,437),18)) g.DrawPath(border,edge);
            Fill(g,greenSoft,new RectangleF(24,22,27,27),8); Checkmark(g,new PointF(37,35),1,green,0.45f);
            Label(g,"IP GUARD",brandFont,ink,new RectangleF(60,22,110,27));
            Label(g,name,textFont,muted,new RectangleF(180,22,430,27));
            using(Pen separator=new Pen(line,1)) { g.DrawLine(separator,24,68,656,68); g.DrawLine(separator,224,92,224,340); }
            Label(g,"启动校验",textFont,muted,new RectangleF(27,86,170,24));
            for(int i=0;i<steps.Count && i<6;i++) {
                Step s=steps[i]; double elapsed=clock.Elapsed.TotalMilliseconds-s.appeared; if(elapsed<0) continue;
                float reveal=motion ? (float)Math.Min(1,elapsed/150) : 1;
                GraphicsState state=g.Save(); g.TranslateTransform(0,(1-reveal)*5);
                float y=123+i*38; Color color=s.status=="error" ? red : s.status=="warning" ? amber : s.status=="info"||s.status=="unknown" ? muted : green;
                Color toned=Color.FromArgb((int)(255*reveal),color);
                if(s.status=="ok") { using(Brush b=new SolidBrush(Color.FromArgb((int)(35*reveal),green))) g.FillEllipse(b,28,y+2,18,18); Checkmark(g,new PointF(37,y+11),1,toned,0.37f); }
                else if(s.status=="running") { using(Pen pen=new Pen(toned,1.8f)) g.DrawArc(pen,30,y+4,14,14,motion ? (float)(clock.Elapsed.TotalSeconds*240)%360 : -90,260); }
                else { using(Pen pen=new Pen(toned,1.5f)) g.DrawEllipse(pen,30,y+4,14,14); Label(g,s.status=="error" ? "×" : "·",textFont,toned,new RectangleF(28,y+1,18,18),StringAlignment.Center); }
                Label(g,s.label,textFont,Color.FromArgb((int)(255*reveal),ink),new RectangleF(55,y-2,155,22));
                Label(g,s.detail,smallFont,Color.FromArgb((int)(255*reveal),muted),new RectangleF(55,y+17,155,16)); g.Restore(state);
            }
            PointF center=new PointF(442,163); Color accent=phase=="blocked" ? red : green;
            using(Brush b=new SolidBrush(phase=="blocked" ? Color.FromArgb(18,red) : greenSoft)) g.FillEllipse(b,398,119,88,88);
            if(phase=="running") {
                using(Pen track=new Pen(line,2)) g.DrawEllipse(track,385,106,114,114);
                float angle=motion ? (float)(clock.Elapsed.TotalSeconds*190)%360 : -90;
                using(Pen arc=new Pen(green,2.4f) { StartCap=LineCap.Round, EndCap=LineCap.Round }) g.DrawArc(arc,385,106,114,114,angle,246);
                float rad=(angle+246)*(float)Math.PI/180; using(Brush b=new SolidBrush(green)) g.FillEllipse(b,center.X+57*(float)Math.Cos(rad)-4,center.Y+57*(float)Math.Sin(rad)-4,8,8);
                using(Pen shield=new Pen(green,2.2f) { LineJoin=LineJoin.Round }) g.DrawPolygon(shield,new[] {new PointF(442,142),new PointF(460,149),new PointF(457,171),new PointF(442,183),new PointF(427,171),new PointF(424,149)});
                using(Brush b=new SolidBrush(green)) g.FillEllipse(b,439,158,6,6);
            } else if(phase=="complete") {
                float p=motion ? (float)Math.Min(1,(clock.Elapsed.TotalMilliseconds-completed)/330) : 1;
                using(Pen ring=new Pen(Color.FromArgb((int)(100*(1-p)),green),1.5f)) g.DrawEllipse(ring,390-p*10,111-p*10,104+p*20,104+p*20);
                Checkmark(g,center,1-(float)Math.Pow(1-p,3),green,1.25f);
            } else {
                using(Pen pen=new Pen(red,3) { StartCap=LineCap.Round, EndCap=LineCap.Round }) { g.DrawLine(pen,442,144,442,166); g.DrawEllipse(pen,440.5f,177,3,3); }
            }
            Label(g,phase=="running" ? "正在核验网络" : phase=="complete" ? "允许启动" : "启动已阻断",headingFont,ink,new RectangleF(250,233,385,34),StringAlignment.Center);
            Label(g,currentIp=="" ? (phase=="blocked" ? "未取得公网 IPv4" : "正在获取公网 IPv4") : currentIp,currentIp=="" ? textFont : ipFont,currentIp=="" ? muted : ink,new RectangleF(250,276,385,34),StringAlignment.Center);
            Label(g,"锁定 IP  ·  "+(expectedIp=="" ? "未取得" : expectedIp),textFont,muted,new RectangleF(250,314,385,24),StringAlignment.Center);
            if(phase=="blocked") {
                Label(g,reason,smallFont,red,new RectangleF(250,340,398,36));
            } else Label(g,phase=="complete" ? "校验完成，正在启动" : "正在校验锁定的公网 IPv4",smallFont,muted,new RectangleF(250,378,385,26),StringAlignment.Center);
            base.OnPaint(e);
        }
        protected override void Dispose(bool disposing) { if(disposing) { timer.Dispose(); textFont.Dispose(); smallFont.Dispose(); headingFont.Dispose(); ipFont.Dispose(); brandFont.Dispose(); buttonFont.Dispose(); } base.Dispose(disposing); }
    }
}
