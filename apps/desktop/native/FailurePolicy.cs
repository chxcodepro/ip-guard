namespace IpGuard {
    // Counts consecutive network-type check failures. An IP mismatch is never counted here; it trips immediately.
    public sealed class FailurePolicy {
        public const int Limit = 3;
        public const int RetrySeconds = 2;
        // Extra lease time while failures are being retried: each attempt can take up to 8 s (probe wait) + retry delay + loop tick.
        public const int GraceSeconds = Limit * (8 + RetrySeconds + 1);
        int count;
        public int Count { get { return count; } }
        public void Success() { count = 0; }
        // Returns true when the protected program must be stopped now.
        public bool NetworkFailure() { count++; if(count < Limit) return false; count = 0; return true; }
        public bool Mismatch() { count = 0; return true; }
    }
}
