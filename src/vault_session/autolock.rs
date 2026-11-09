use rust_i18n::t;
use std::time::{Duration, Instant};

const SLEEP_THRESHOLD: Duration = Duration::from_secs(1);

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15 * 60);

pub const MIN_TIMEOUT: Duration = Duration::from_secs(60);
pub const MAX_TIMEOUT: Duration = Duration::from_secs(8 * 60 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Keep,
    Idle,
    Slept,
}

impl Verdict {
    pub fn locks(self) -> bool {
        !matches!(self, Self::Keep)
    }

    pub fn reason(self) -> Option<std::borrow::Cow<'static, str>> {
        match self {
            Self::Keep => None,
            Self::Idle => Some(t!("vault.lock_idle")),
            Self::Slept => Some(t!("vault.lock_slept")),
        }
    }
}

#[derive(Debug)]
pub struct AutoLock {
    timeout: Duration,
    last_activity: Instant,
    checked_wall_ms: u64,
    checked_awake: Duration,
}

impl AutoLock {
    pub fn new(timeout: Duration, now: Instant, wall_ms: u64, awake: Duration) -> Self {
        Self {
            timeout: timeout.clamp(MIN_TIMEOUT, MAX_TIMEOUT),
            last_activity: now,
            checked_wall_ms: wall_ms,
            checked_awake: awake,
        }
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout.clamp(MIN_TIMEOUT, MAX_TIMEOUT);
    }

    pub fn touch(&mut self, now: Instant) {
        self.last_activity = now;
    }

    /// Restart the countdown, forgetting elapsed time and sleep. Needed when
    /// auto-lock is re-enabled: otherwise it would fire immediately.
    pub fn rearm(&mut self, now: Instant, wall_ms: u64, awake: Duration) {
        self.last_activity = now;
        self.checked_wall_ms = wall_ms;
        self.checked_awake = awake;
    }

    pub fn remaining(&self, now: Instant) -> Duration {
        self.timeout
            .checked_sub(now.saturating_duration_since(self.last_activity))
            .unwrap_or_default()
    }

    pub fn check(&mut self, now: Instant, wall_ms: u64, awake: Duration) -> Verdict {
        let awake_passed = awake.saturating_sub(self.checked_awake);
        let wall = Duration::from_millis(wall_ms.saturating_sub(self.checked_wall_ms));

        self.checked_awake = awake;
        self.checked_wall_ms = wall_ms;

        if wall.saturating_sub(awake_passed) >= SLEEP_THRESHOLD {
            return Verdict::Slept;
        }

        if now.saturating_duration_since(self.last_activity) >= self.timeout {
            return Verdict::Idle;
        }

        Verdict::Keep
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start() -> (AutoLock, Instant, u64) {
        let now = Instant::now();
        let wall = 1_700_000_000_000;
        (
            AutoLock::new(Duration::from_secs(600), now, wall, Duration::ZERO),
            now,
            wall,
        )
    }

    fn awake(start: Instant, now: Instant) -> Duration {
        now.saturating_duration_since(start)
    }

    #[test]
    fn rearm_forgets_inactivity_and_sleep() {
        let (mut lock, now, wall) = start();

        // An hour passed, 50 minutes of it asleep: auto-lock was disabled.
        let later = now + Duration::from_secs(3_600);
        let wall_later = wall + 3_600_000;
        let awake_later = Duration::from_secs(600);
        lock.rearm(later, wall_later, awake_later);

        assert_eq!(
            lock.check(
                later + Duration::from_secs(1),
                wall_later + 1_000,
                awake_later + Duration::from_secs(1)
            ),
            Verdict::Keep,
            "the countdown must restart after enabling"
        );
    }

    #[test]
    fn inactivity_locks_the_vault() {
        let (mut lock, now, wall) = start();

        let step = Duration::from_secs(60);
        assert_eq!(
            lock.check(now + step, wall + 60_000, awake(now, now + step)),
            Verdict::Keep,
            "one minute of inactivity — too early"
        );
        assert_eq!(
            lock.check(
                now + Duration::from_secs(600),
                wall + 600_000,
                awake(now, now + Duration::from_secs(600))
            ),
            Verdict::Idle
        );
    }

    #[test]
    fn activity_postpones_locking() {
        let (mut lock, now, wall) = start();

        for minute in 1..=9 {
            let at = now + Duration::from_secs(60 * minute);
            lock.touch(at);
            assert_eq!(
                lock.check(at, wall + 60_000 * minute, awake(now, at)),
                Verdict::Keep
            );
        }

        let at = now + Duration::from_secs(60 * 9 + 600);
        assert_eq!(
            lock.check(at, wall + (60 * 9 + 600) * 1000, awake(now, at)),
            Verdict::Idle
        );
    }

    #[test]
    fn sleep_locks_the_vault_immediately() {
        let (mut lock, now, wall) = start();

        let after = now + Duration::from_millis(500);
        assert_eq!(
            lock.check(after, wall + 3_600_000, awake(now, after)),
            Verdict::Slept,
            "the wall clock jumped an hour ahead while the monotonic clock stood still"
        );
    }

    #[test]
    fn sleep_is_seen_even_when_instant_kept_running() {
        let (mut lock, now, wall) = start();

        let after = now + Duration::from_secs(3600);
        assert_eq!(
            lock.check(after, wall + 3_600_000, Duration::from_millis(500)),
            Verdict::Slept
        );
    }

    #[test]
    fn sleep_with_running_monotonic_clock_is_caught_by_timeout() {
        let (mut lock, now, wall) = start();

        let after = now + Duration::from_secs(3600);
        assert_eq!(
            lock.check(after, wall + 3_600_000, awake(now, after)),
            Verdict::Idle
        );
    }

    #[test]
    fn clock_set_back_is_not_counted_as_sleep() {
        let (mut lock, now, wall) = start();

        let after = now + Duration::from_secs(1);
        assert_eq!(
            lock.check(after, wall - 3_600_000, awake(now, after)),
            Verdict::Keep,
            "the clock went backwards — no reason to lock the vault"
        );
    }

    #[test]
    fn timer_jitter_is_not_counted_as_sleep() {
        let (mut lock, now, wall) = start();

        let after = now + Duration::from_millis(500);
        assert_eq!(
            lock.check(after, wall + 700, awake(now, after)),
            Verdict::Keep
        );
    }

    #[test]
    fn timeout_is_clamped_to_bounds() {
        let now = Instant::now();
        let too_small = AutoLock::new(Duration::from_secs(1), now, 0, Duration::ZERO);
        assert_eq!(too_small.timeout(), MIN_TIMEOUT);

        let too_big = AutoLock::new(Duration::from_secs(100 * 3600), now, 0, Duration::ZERO);
        assert_eq!(too_big.timeout(), MAX_TIMEOUT);

        let mut lock = AutoLock::new(DEFAULT_TIMEOUT, now, 0, Duration::ZERO);
        lock.set_timeout(Duration::from_secs(0));
        assert_eq!(lock.timeout(), MIN_TIMEOUT);
    }

    #[test]
    fn remaining_time_decreases_and_never_goes_negative() {
        let (mut lock, now, _) = start();
        assert_eq!(lock.remaining(now), Duration::from_secs(600));
        assert_eq!(
            lock.remaining(now + Duration::from_secs(60)),
            Duration::from_secs(540)
        );
        assert_eq!(
            lock.remaining(now + Duration::from_secs(9000)),
            Duration::ZERO
        );

        lock.touch(now + Duration::from_secs(60));
        assert_eq!(
            lock.remaining(now + Duration::from_secs(60)),
            Duration::from_secs(600)
        );
    }

    #[test]
    fn every_verdict_has_a_lock_reason() {
        assert!(Verdict::Keep.reason().is_none());
        assert!(!Verdict::Keep.locks());
        for verdict in [Verdict::Idle, Verdict::Slept] {
            assert!(verdict.locks());
            assert!(verdict.reason().is_some());
        }
    }
}
