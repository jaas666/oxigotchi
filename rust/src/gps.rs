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

/// Parse a single gpsd JSON line into a GpsFix.
///
/// Returns Some only for TPV messages with mode >= 2 and valid lat/lon.
/// Extracted so the parsing logic is testable without a real TCP connection.
pub fn parse_tpv(line: &str) -> Option<GpsFix> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    if v["class"].as_str() != Some("TPV") {
        return None;
    }
    if v["mode"].as_u64().unwrap_or(0) < 2 {
        return None;
    }
    let lat = v["lat"].as_f64()?;
    let lon = v["lon"].as_f64()?;
    let alt = v["altHAE"]
        .as_f64()
        .or_else(|| v["alt"].as_f64())
        .unwrap_or(0.0);
    let epx = v["epx"].as_f64().unwrap_or(0.0);
    let epy = v["epy"].as_f64().unwrap_or(0.0);
    Some(GpsFix {
        lat,
        lon,
        alt,
        accuracy: epx.hypot(epy),
    })
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
        if let Some(fix) = parse_tpv(&line) {
            return Some(fix);
        }
    }
    None
}

#[cfg(not(unix))]
pub fn query_gpsd() -> Option<GpsFix> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tpv_3d_fix() {
        let line = r#"{"class":"TPV","mode":3,"lat":51.5074,"lon":-0.1278,"altHAE":24.5,"epx":3.2,"epy":4.1}"#;
        let fix = parse_tpv(line).expect("should parse 3D fix");
        assert!((fix.lat - 51.5074).abs() < 1e-6);
        assert!((fix.lon - (-0.1278)).abs() < 1e-6);
        assert!((fix.alt - 24.5).abs() < 1e-6);
        assert!((fix.accuracy - 3.2f64.hypot(4.1)).abs() < 1e-6);
    }

    #[test]
    fn test_parse_tpv_2d_fix_uses_alt_fallback() {
        let line = r#"{"class":"TPV","mode":2,"lat":48.8566,"lon":2.3522,"alt":35.0}"#;
        let fix = parse_tpv(line).expect("should parse 2D fix");
        assert!((fix.alt - 35.0).abs() < 1e-6);
        assert_eq!(fix.accuracy, 0.0); // no epx/epy
    }

    #[test]
    fn test_parse_tpv_no_fix_mode1() {
        let line = r#"{"class":"TPV","mode":1}"#;
        assert!(parse_tpv(line).is_none());
    }

    #[test]
    fn test_parse_tpv_wrong_class() {
        let line = r#"{"class":"SKY","mode":3,"lat":51.5,"lon":-0.1}"#;
        assert!(parse_tpv(line).is_none());
    }

    #[test]
    fn test_parse_tpv_missing_lat() {
        // Valid mode but no lat — not a usable fix
        let line = r#"{"class":"TPV","mode":2,"lon":-0.1278}"#;
        assert!(parse_tpv(line).is_none());
    }

    #[test]
    fn test_parse_tpv_version_and_devices_ignored() {
        // These are the first messages gpsd sends before TPV
        let version = r#"{"class":"VERSION","release":"3.25","rev":"3.25","proto_major":3}"#;
        let devices = r#"{"class":"DEVICES","devices":[]}"#;
        assert!(parse_tpv(version).is_none());
        assert!(parse_tpv(devices).is_none());
    }

    #[test]
    fn test_query_gpsd_returns_none_when_unreachable() {
        // No gpsd running in CI — must return None gracefully, not panic.
        let result = query_gpsd();
        assert!(result.is_none());
    }
}
