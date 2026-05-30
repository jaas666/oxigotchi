//! WIGLE wardriving upload integration.
//!
//! Appends observed APs (with GPS coordinates) to a WigleCSV staging file
//! each epoch, then periodically uploads the file to the WIGLE API using a
//! curl subprocess — the same pattern used for WPA-SEC uploads.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use crate::gps::GpsFix;
use crate::ssid::SsidResolver;

/// WIGLE upload configuration.
#[derive(Debug, Clone)]
pub struct WigleConfig {
    pub enabled: bool,
    /// WIGLE API name (username shown in network settings).
    pub api_name: String,
    /// WIGLE API token (from network settings page).
    pub api_token: String,
    pub url: String,
}

impl Default for WigleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_name: String::new(),
            api_token: String::new(),
            url: "https://api.wigle.net/api/v3/upload/file".into(),
        }
    }
}

/// A single AP observation to log.
pub struct WigleObservation {
    /// BSSID as 12-char lowercase hex without colons (AoApInfo format).
    pub bssid: String,
    pub channel: u8,
}

/// Convert 12-char lowercase hex BSSID to `AA:BB:CC:DD:EE:FF`.
fn format_bssid(bssid: &str) -> String {
    if bssid.len() != 12 {
        return bssid.to_uppercase();
    }
    (0..6)
        .map(|i| bssid[i * 2..i * 2 + 2].to_uppercase())
        .collect::<Vec<_>>()
        .join(":")
}

/// Parse 12-char lowercase hex BSSID to `[u8; 6]` for ssid_resolver lookup.
fn bssid_to_mac(bssid: &str) -> Option<[u8; 6]> {
    if bssid.len() != 12 {
        return None;
    }
    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = u8::from_str_radix(&bssid[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(mac)
}

/// Append new AP observations to the WigleCSV staging file.
///
/// Writes the file header if the file does not yet exist. Returns the number
/// of rows written, or an error string.
pub fn append_observations(
    staging_path: &Path,
    observations: &[WigleObservation],
    fix: &GpsFix,
    ssid_resolver: &SsidResolver,
    device_name: &str,
) -> Result<usize, String> {
    if observations.is_empty() {
        return Ok(0);
    }

    let file_exists = staging_path.exists();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(staging_path)
        .map_err(|e| format!("open staging file: {e}"))?;

    if !file_exists {
        writeln!(
            file,
            "WigleWifi-1.4,appRelease=3.3.6,model=Raspberry Pi Zero 2W,\
release=3.3.6,device={name},display={name},board=RPiZero2W,brand=Raspberry Pi",
            name = device_name
        )
        .map_err(|e| format!("write wigle header: {e}"))?;
        writeln!(
            file,
            "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,\
CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type"
        )
        .map_err(|e| format!("write wigle column header: {e}"))?;
    }

    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let mut written = 0usize;

    for obs in observations {
        let mac_str = format_bssid(&obs.bssid);
        let ssid = bssid_to_mac(&obs.bssid)
            .and_then(|mac| ssid_resolver.get(&mac))
            .unwrap_or("");
        // Basic CSV escaping: wrap in quotes and double any internal quotes.
        let ssid_csv = if ssid.contains(',') || ssid.contains('"') {
            format!("\"{}\"", ssid.replace('"', "\"\""))
        } else {
            ssid.to_string()
        };
        writeln!(
            file,
            "{mac},{ssid},[WPA2],{ts},{ch},0,{lat:.6},{lon:.6},{alt:.1},{acc:.1},WIFI",
            mac = mac_str,
            ssid = ssid_csv,
            ts = now,
            ch = obs.channel,
            lat = fix.lat,
            lon = fix.lon,
            alt = fix.alt,
            acc = fix.accuracy,
        )
        .map_err(|e| format!("write wigle row: {e}"))?;
        written += 1;
    }

    Ok(written)
}

/// Upload the staging WigleCSV file to WIGLE using curl.
///
/// On success the staging file is removed. Returns Ok(()) immediately if the
/// config is disabled, credentials are missing, or there is nothing to upload.
#[cfg(unix)]
pub fn upload_to_wigle(staging_path: &Path, config: &WigleConfig) -> Result<(), String> {
    if !config.enabled {
        return Ok(());
    }
    if config.api_name.is_empty() || config.api_token.is_empty() {
        return Err("WIGLE credentials not configured".into());
    }
    if !staging_path.exists() {
        return Ok(());
    }

    let credentials = format!("{}:{}", config.api_name, config.api_token);
    let output = std::process::Command::new("curl")
        .arg("-s")
        .arg("-S")
        .arg("--fail")
        .arg("--connect-timeout")
        .arg("8")
        .arg("--max-time")
        .arg("60")
        .arg("-u")
        .arg(&credentials)
        .arg("-F")
        .arg(format!("file=@{}", staging_path.display()))
        .arg(&config.url)
        .output()
        .map_err(|e| format!("curl exec error: {e}"))?;

    if output.status.success() {
        std::fs::remove_file(staging_path)
            .map_err(|e| format!("remove staging file: {e}"))?;
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("WIGLE upload failed: {stderr}"))
    }
}

#[cfg(not(unix))]
pub fn upload_to_wigle(_staging_path: &Path, _config: &WigleConfig) -> Result<(), String> {
    Err("WIGLE upload requires Unix".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bssid() {
        assert_eq!(format_bssid("aabbccddeeff"), "AA:BB:CC:DD:EE:FF");
        assert_eq!(format_bssid("001122334455"), "00:11:22:33:44:55");
    }

    #[test]
    fn test_bssid_to_mac() {
        let mac = bssid_to_mac("aabbccddeeff").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_bssid_to_mac_invalid() {
        assert!(bssid_to_mac("short").is_none());
        assert!(bssid_to_mac("zzzzzzzzzzzz").is_none());
    }

    #[test]
    fn test_append_observations_creates_valid_csv() {
        use crate::gps::GpsFix;
        use crate::ssid::SsidResolver;
        use std::fs;

        let dir = std::env::temp_dir().join("wigle_test_append");
        fs::create_dir_all(&dir).unwrap();
        let staging = dir.join("test.wiglecsv");
        let _ = fs::remove_file(&staging); // start clean

        let fix = GpsFix { lat: 51.5074, lon: -0.1278, alt: 24.0, accuracy: 5.0 };
        let resolver = SsidResolver::new(dir.join("ssid.json"));
        let obs = vec![
            WigleObservation { bssid: "aabbccddeeff".into(), channel: 6 },
            WigleObservation { bssid: "001122334455".into(), channel: 11 },
        ];

        let written = append_observations(&staging, &obs, &fix, &resolver, "testbot").unwrap();
        assert_eq!(written, 2);

        let content = fs::read_to_string(&staging).unwrap();
        // Header lines present
        assert!(content.contains("WigleWifi-1.4"));
        assert!(content.contains("MAC,SSID,AuthMode"));
        // Data rows present with correct MAC format and coordinates
        assert!(content.contains("AA:BB:CC:DD:EE:FF"));
        assert!(content.contains("00:11:22:33:44:55"));
        assert!(content.contains("51.507400"));
        assert!(content.contains("-0.127800"));
        assert!(content.contains(",6,"));
        assert!(content.contains(",11,"));

        // Appending again should NOT re-write the header
        let obs2 = vec![WigleObservation { bssid: "ffeeddccbbaa".into(), channel: 1 }];
        append_observations(&staging, &obs2, &fix, &resolver, "testbot").unwrap();
        let content2 = fs::read_to_string(&staging).unwrap();
        assert_eq!(content2.matches("WigleWifi-1.4").count(), 1);
        assert!(content2.contains("FF:EE:DD:CC:BB:AA"));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_append_observations_empty_is_noop() {
        use crate::gps::GpsFix;
        use crate::ssid::SsidResolver;

        let dir = std::env::temp_dir().join("wigle_test_noop");
        std::fs::create_dir_all(&dir).unwrap();
        let staging = dir.join("noop.wiglecsv");

        let fix = GpsFix { lat: 0.0, lon: 0.0, alt: 0.0, accuracy: 0.0 };
        let resolver = SsidResolver::new(dir.join("ssid.json"));

        let written = append_observations(&staging, &[], &fix, &resolver, "testbot").unwrap();
        assert_eq!(written, 0);
        assert!(!staging.exists()); // file should not be created for empty input

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_ssid_with_comma_is_quoted() {
        use crate::gps::GpsFix;
        use crate::ssid::SsidResolver;
        use std::fs;

        let dir = std::env::temp_dir().join("wigle_test_csv_escape");
        fs::create_dir_all(&dir).unwrap();
        let staging = dir.join("escape.wiglecsv");
        let _ = fs::remove_file(&staging);

        let fix = GpsFix { lat: 1.0, lon: 2.0, alt: 0.0, accuracy: 0.0 };
        let mut resolver = SsidResolver::new(dir.join("ssid.json"));
        // Insert an SSID containing a comma
        resolver.insert([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], "Free,WiFi");
        let obs = vec![WigleObservation { bssid: "aabbccddeeff".into(), channel: 6 }];

        append_observations(&staging, &obs, &fix, &resolver, "testbot").unwrap();
        let content = fs::read_to_string(&staging).unwrap();
        assert!(content.contains("\"Free,WiFi\""));

        fs::remove_dir_all(&dir).unwrap();
    }
}
