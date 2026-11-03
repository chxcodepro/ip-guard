using System; using IpGuard;
// Mirrors Guard.Check() decision: 'T'=timeout/network error, 'S'=success, 'M'=IP mismatch. healthy starts true (app running).
static class P {
  static int fails;
  static bool Run(string name, string seq, bool expectKill) {
    var f = new FailurePolicy(); bool healthy = true, killed = false;
    foreach (char c in seq) {
      if (c == 'S') { f.Success(); healthy = true; }
      else if (c == 'M') { if (f.Mismatch()) { killed = true; healthy = false; } }
      else { bool stop = !healthy || f.NetworkFailure(); if (stop) { killed = true; healthy = false; } }
    }
    bool ok = killed == expectKill; if (!ok) fails++;
    Console.WriteLine($"{(ok ? "PASS" : "FAIL")}  {name,-42} seq={seq,-6} killed={killed} count={f.Count}");
    return ok;
  }
  static int Main() {
    Run("1 timeout -> no kill", "T", false);
    Run("2 consecutive timeouts -> no kill", "TT", false);
    Run("3 consecutive timeouts -> kill", "TTT", true);
    Run("T,T,S,T,T -> no kill (success resets)", "TTSTT", false);
    Run("mismatch -> immediate kill", "M", true);
    Run("T,T,M -> immediate kill", "TTM", true);
    Run("S,T,T,S,T,T,S -> no kill", "STTSTTS", false);
    Console.WriteLine($"Limit={FailurePolicy.Limit} RetrySeconds={FailurePolicy.RetrySeconds} GraceSeconds={FailurePolicy.GraceSeconds}");
    Console.WriteLine(fails == 0 ? "ALL PASSED" : $"{fails} FAILED"); return fails;
  }
}
