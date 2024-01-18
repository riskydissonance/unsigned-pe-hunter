use std::fs;
use std::time::{Duration, SystemTime};
use chrono::{DateTime, Utc};

pub struct DateData {
    pub check: bool,
    pub creation_date: DateTime<Utc>,
}

pub unsafe fn check_date(path: &str, days: u64) -> Result<DateData, String> {
    let metadata_result = fs::metadata(path);
    return match metadata_result {
        Ok(metadata) => {
            let created_time_result = metadata.created();
            match created_time_result {
                Ok(created_time) => {
                    if days == 0 {
                        return Ok(DateData {
                            check: true,
                            creation_date: DateTime::from(created_time),
                        });
                    }
                    let current_time = SystemTime::now();
                    let x_days_ago = current_time - Duration::from_secs(days * 24 * 60 * 60);
                    if created_time > x_days_ago {
                        return Ok(DateData {
                            check: true,
                            creation_date: DateTime::from(created_time),
                        });
                    }
                    return Ok(DateData {
                        check: false,
                        creation_date: DateTime::from(created_time),
                    });
                }
                Err(err) => {
                    Err(String::from(&format!("Error getting creation time of {}: {}", path, err)))
                }
            }
        }
        Err(err) => {
            Err(String::from(&format!("Error getting metadata of {}: {}", path, err)))
        }
    };
}