//! GPS fix reader via the gpsd JSON protocol (TCP localhost:2947).

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

/// A GPS fix from gpsd.
#[derive(Debug, Clone)]
pub struct GpsFix {
    pub lat: f64,
    pub lon: f64,
    /// Altitude in metres (HAE if available, else MSL).
    pub alt: f64,
    /// Horizontal accuracy in metres (sqrt(epx²+epy²)).
    pub accuracy: f64,
}

/// Query gpsd for the current position fix.
///
/// Opens a TCP connection to localhost:2947, sends a WATCH enable, and reads
/// up to 10 JSON messages looking for a TPV report with mode >= 2 (2-D fix).
/// Returns None if gpsd is unreachable, the connection times out, or no valid
/// fix is available.
#[cfg(unix)]
pub fn query_gpsd() -> Option<GpsFix> {
    let addr = "127.0.0.1:2947".parse().unwrap();
    let stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(1)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .ok()?;

    let mut writer = stream.try_clone().ok()?;
    writer
        .write_all(b"?WATCH={\"enable\":true,\"json\":true}\n")
        .ok()?;

    let reader = BufReader::new(stream);
    for line in reader.lines().take(10) {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let v: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v["class"].as_str() != Some("TPV") {
            continue;
        }
        if v["mode"].as_u64().unwrap_or(0) < 2 {
            continue;
        }
        let lat = v["lat"].as_f64()?;
        let lon = v["lon"].as_f64()?;
        let alt = v["altHAE"]
            .as_f64()
            .or_else(|| v["alt"].as_f64())
            .unwrap_or(0.0);
        let epx = v["epx"].as_f64().unwrap_or(0.0);
        let epy = v["epy"].as_f64().unwrap_or(0.0);
        return Some(GpsFix {
            lat,
            lon,
            alt,
            accuracy: epx.hypot(epy),
        });
    }
    None
}

#[cfg(not(unix))]
pub fn query_gpsd() -> Option<GpsFix> {
    None
}
