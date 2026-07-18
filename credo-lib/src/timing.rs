//! Interval jitter for periodic loops.
//!
//! Every periodic loop in the fleet should jitter its sleep so that many
//! nodes (or many per-node tasks) configured with the same interval do not
//! fire in lockstep against the same peer.

use std::time::Duration;

/// Return `base_secs` scaled by a uniformly random factor in
/// `[1 - frac, 1 + frac]`. `frac` is clamped to `[0, 1]`.
pub fn jittered_duration(base_secs: u64, frac: f64) -> Duration {
    let frac = frac.clamp(0.0, 1.0);
    if frac == 0.0 || base_secs == 0 {
        return Duration::from_secs(base_secs);
    }
    let factor = 1.0 + frac * (rand::random::<f64>() * 2.0 - 1.0);
    Duration::from_secs_f64(base_secs as f64 * factor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn zero_fraction_returns_exact_interval() {
        assert_eq!(jittered_duration(300, 0.0), Duration::from_secs(300));
    }

    #[test]
    fn jitter_stays_within_bounds() {
        for _ in 0..1000 {
            let d = jittered_duration(300, 0.1);
            assert!(d >= Duration::from_secs(270), "below lower bound: {d:?}");
            assert!(d <= Duration::from_secs(330), "above upper bound: {d:?}");
        }
    }

    #[test]
    fn jitter_actually_varies() {
        let first = jittered_duration(3600, 0.2);
        let varied = (0..100).any(|_| jittered_duration(3600, 0.2) != first);
        assert!(varied, "100 samples identical; jitter is not being applied");
    }

    #[test]
    fn zero_interval_stays_zero() {
        assert_eq!(jittered_duration(0, 0.1), Duration::from_secs(0));
    }
}
