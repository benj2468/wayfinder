//! The driver's [`Clock`], backed by `embassy-time`.

use core::time::Duration;

use embassy_time::Duration as EmbassyDuration;
use embassy_time::Instant;
use embassy_time::Timer;
use wayfinder_embedded_driver::Clock;

/// An `embassy-time`-backed [`Clock`]: the monotonic RTC1 tick (via the
/// `time-driver-rtc1` feature) is what the router ages routes and paces OGM
/// emission against.
pub struct EmbassyClock;

impl Clock for EmbassyClock {
    fn now(&self) -> Duration {
        Duration::from_micros(Instant::now().as_micros())
    }

    async fn sleep(&self, duration: Duration) {
        Timer::after(EmbassyDuration::from_micros(duration.as_micros() as u64)).await;
    }
}
