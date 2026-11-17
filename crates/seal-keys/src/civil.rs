//! Dates for signing, from the injected clock: SigV4's `20150830T123600Z` and the
//! HTTP date Azure uses, `Sun, 30 Aug 2015 12:36:00 GMT`.

use std::time::{SystemTime, UNIX_EPOCH};

/// A UTC time, to the second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Civil {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    /// 0 is Sunday.
    pub weekday: u32,
}

impl Civil {
    /// The time, or the epoch for a clock set before it.
    #[must_use]
    pub fn at(now: SystemTime) -> Self {
        let seconds = now
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let days = i64::try_from(seconds / 86_400).unwrap_or(0);
        let of_day = u32::try_from(seconds % 86_400).unwrap_or(0);
        // Howard Hinnant's days-to-civil algorithm.
        let shifted = days + 719_468;
        let era = shifted.div_euclid(146_097);
        let day_of_era = shifted.rem_euclid(146_097);
        let year_of_era =
            (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_index = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month_index + 2) / 5 + 1;
        let month = if month_index < 10 {
            month_index + 3
        } else {
            month_index - 9
        };
        let year = year_of_era + era * 400 + i64::from(month <= 2);
        Self {
            year,
            month: u32::try_from(month).unwrap_or(1),
            day: u32::try_from(day).unwrap_or(1),
            hour: of_day / 3600,
            minute: of_day / 60 % 60,
            second: of_day % 60,
            // 1970-01-01 was a Thursday.
            weekday: u32::try_from((days + 4).rem_euclid(7)).unwrap_or(0),
        }
    }

    /// `20150830`.
    #[must_use]
    pub fn date_stamp(&self) -> String {
        format!("{:04}{:02}{:02}", self.year, self.month, self.day)
    }

    /// `20150830T123600Z`.
    #[must_use]
    pub fn amz_date(&self) -> String {
        format!(
            "{}T{:02}{:02}{:02}Z",
            self.date_stamp(),
            self.hour,
            self.minute,
            self.second
        )
    }

    /// `2015-08-30T12:36:00Z`, as a shared access signature has its expiry.
    #[must_use]
    pub fn iso8601(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }

    /// `Sun, 30 Aug 2015 12:36:00 GMT`, as in RFC 9110.
    #[must_use]
    pub fn http_date(&self) -> String {
        const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let weekday = DAYS.get(self.weekday as usize).copied().unwrap_or("Sun");
        let month = MONTHS
            .get(self.month.saturating_sub(1) as usize)
            .copied()
            .unwrap_or("Jan");
        format!(
            "{weekday}, {:02} {month} {:04} {:02}:{:02}:{:02} GMT",
            self.day, self.year, self.hour, self.minute, self.second
        )
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn at(seconds: u64) -> Civil {
        Civil::at(UNIX_EPOCH + Duration::from_secs(seconds))
    }

    #[test]
    fn formats_known_times() {
        assert_eq!(at(1_440_938_160).amz_date(), "20150830T123600Z");
        assert_eq!(
            at(1_440_938_160).http_date(),
            "Sun, 30 Aug 2015 12:36:00 GMT"
        );
        assert_eq!(at(1_440_938_160).iso8601(), "2015-08-30T12:36:00Z");
        assert_eq!(at(0).http_date(), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(at(951_782_400).amz_date(), "20000229T000000Z");
        assert_eq!(
            at(4_133_980_799).http_date(),
            "Fri, 31 Dec 2100 23:59:59 GMT"
        );
    }

    #[test]
    fn every_day_follows_the_one_before() {
        let mut previous = at(0);
        for day in 1..200_000_u64 {
            let next = at(day * 86_400);
            assert_eq!(next.weekday, (previous.weekday + 1) % 7);
            let same_month = next.month == previous.month && next.day == previous.day + 1;
            let new_month =
                next.day == 1 && (next.month == previous.month % 12 + 1) && previous.day >= 28;
            assert!(same_month || new_month, "{previous:?} then {next:?}");
            previous = next;
        }
    }
}
