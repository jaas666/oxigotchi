//! Web dashboard module (axum HTTP server).
//!
//! Provides a REST API and embedded HTML dashboard for monitoring
//! and configuring oxigotchi. The axum router shares DaemonState via
//! Arc<Mutex<DaemonState>>.
//!
//! 21 dashboard cards organized by user-journey (At-a-Glance, Hardware,
//! Hunting, Loot, Connectivity, Status, Management) with vanilla JS auto-refresh.

use axum::{
    Router,
    extract::{
        FromRef, Path as AxumPath, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::{Html, IntoResponse, Json},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::broadcast;

mod html;
use html::DASHBOARD_HTML;

/// Truncate a string to at most `max_bytes` bytes on a valid UTF-8 char boundary.
fn safe_truncate(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

// ---------------------------------------------------------------------------
// Shared daemon state (the web server reads/writes this via Arc<Mutex>)
// ---------------------------------------------------------------------------

/// Snapshot of all daemon state that the web server needs access to.
pub struct DaemonState {
    // -- status --
    pub name: String,
    pub uptime_str: String,
    pub epoch: u64,
    pub channel: u8,
    pub aps_seen: u32,
    pub handshakes: u32,
    pub blind_epochs: u32,
    pub mood: f32,
    pub face: String,
    pub status_message: String,
    pub mode: String,

    // -- attacks --
    pub total_attacks: u64,
    pub total_handshakes_attacks: u64,
    pub attack_rate: u32,
    pub deauths_this_epoch: u32,
    /// Per-attack-type toggles: deauth, pmkid, csa, disassoc, anon_reassoc, rogue_m2
    pub attack_deauth: bool,
    pub attack_pmkid: bool,
    pub attack_csa: bool,
    pub attack_disassoc: bool,
    pub attack_anon_reassoc: bool,
    pub attack_rogue_m2: bool,

    // -- captures --
    pub capture_dir: String,
    pub capture_files: usize,
    pub handshake_files: usize,
    pub pending_upload: usize,
    pub total_capture_size: u64,
    pub capture_list: Vec<CaptureEntry>,
    /// Session captures: pcapng files created by AO in tmpfs this session.
    pub session_captures: u32,
    /// Session handshakes: validated captures moved to SD this session.
    pub session_handshakes: u32,
    /// Whether Collect All mode is active (AO writes directly to SD).
    pub capture_all: bool,
    /// Filename queued for deletion by the daemon.
    pub pending_delete: Option<String>,

    // -- battery --
    pub battery_level: u8,
    pub battery_charging: bool,
    pub battery_voltage_mv: u16,
    pub battery_low: bool,
    pub battery_critical: bool,
    pub battery_available: bool,

    // -- wifi --
    pub wifi_state: String,
    pub wifi_aps_tracked: usize,
    pub wifi_channels: Vec<u8>,
    pub wifi_dwell_ms: u64,
    pub autohunt_enabled: bool,
    pub skip_captured: bool,
    pub min_rssi: i8,
    pub ap_ttl_secs: u64,

    // -- display settings --
    pub display_invert: bool,
    pub display_rotation: u16,
    pub display_refresh_interval: u32,
    pub pending_display_reinit: bool,

    // -- bluetooth --
    pub bt_state: String,
    pub bt_connected: bool,
    pub bt_device_name: String,
    pub bt_ip: String,
    pub bt_internet_available: bool,
    pub bt_retry_count: u32,
    pub bt_feature_mode: String,
    pub bt_feature_devices_now: u32,
    pub bt_feature_contention_score: u32,
    /// User-actionable hint from the last BT connect failure.
    pub bt_last_error_hint: String,

    // -- bt attacks --
    pub bt_attack_enabled: bool,
    pub bt_rage_level: String,
    pub bt_scan_mode: String,
    pub bt_attack_smp_downgrade: bool,
    pub bt_attack_knob: bool,
    pub bt_attack_l2cap_fuzz: bool,
    pub bt_attack_l2cap_conn_flood: bool,
    pub bt_attack_att_gatt_fuzz: bool,
    pub bt_total_attacks: u64,
    pub bt_total_captures: u64,
    pub bt_active_attacks: u32,
    pub bt_devices_seen: u32,
    pub bt_patchram_state: String,
    pub bt_capture_keys: u32,
    pub bt_capture_transcripts: u32,
    pub bt_capture_crashes: u32,
    pub bt_capture_vendor: u32,
    pub bt_device_list: Vec<BtDeviceInfo>,

    // -- bt attack action requests --
    pub pending_bt_attack_toggle: Option<BtAttackToggle>,
    pub pending_bt_rage_level: Option<String>,
    pub pending_bt_scan_mode: Option<String>,
    pub pending_bt_manual_attack: Option<BtManualAttackRequest>,
    pub bt_manual_result: Option<BtManualResult>,
    /// Broadcasts remaining before clearing bt_manual_result.
    pub bt_manual_result_ttl: u8,

    // BT tether web-command fields. Pairing itself is phone-initiated and
    // handled entirely in the bluetooth module via Agent1 + PropertiesChanged;
    // the fields below are just user-action commands we receive from the UI.
    pub pending_bt_forget: Option<String>,        // D-Bus device path to forget
    pub bt_passkey: Option<u32>,                  // Passkey for display while Agent1 waits for phone confirm
    pub bt_passkey_device: String,                // Device name being paired
    pub pending_bt_disconnect: Option<bool>,      // Disconnect request (suppresses auto-reconnect)
    /// User-requested "Reset all BT pairings" escape hatch.
    pub pending_bt_reset_pairings: bool,
    /// User-requested refresh of the paired_devices cache.
    /// Triggers an on-demand scan only; not populated by sync_to_web
    /// to avoid powering on BT as a side effect every 2 seconds.
    pub pending_bt_refresh_paired: bool,
    /// Cached paired devices for the /api/bluetooth/paired endpoint.
    /// Populated ONLY when pending_bt_refresh_paired fires — never from
    /// passive sync, so viewing the dashboard does not initialize D-Bus.
    pub paired_devices: Vec<PairedDeviceBrief>,

    // -- gpu --
    pub gpu_mode: String,
    pub gpu_signal: String,
    pub gpu_submit_seen: bool,
    pub gpu_snapshot_policy: String,
    pub gpu_flush_threshold: u32,

    // -- qpu --
    pub qpu_enabled: bool,
    pub qpu_available: bool,
    pub qpu_num_cores: u32,
    pub qpu_frames_submitted: u64,
    pub qpu_frames_classified: u64,
    pub qpu_batches_processed: u64,
    pub qpu_overflow_count: u64,
    pub qpu_last_batch_size: u32,
    pub qpu_last_batch_duration_us: u64,
    pub qpu_beacon_rate: f32,
    pub qpu_probe_rate: f32,
    pub qpu_deauth_rate: f32,
    pub qpu_data_rate: f32,
    pub qpu_unique_bssids: u32,
    pub qpu_total_frames: u32,
    pub qpu_dominant_class: String,

    // -- ao --
    pub ao_state: String,
    pub ao_pid: u32,
    pub ao_crash_count: u32,
    pub ao_uptime: String,

    // -- gps --
    pub gpsd_available: bool,

    // -- personality / XP --
    pub xp: u64,
    pub level: u32,

    // -- system info --
    pub cpu_temp_c: f32,
    pub mem_used_mb: u32,
    pub mem_total_mb: u32,
    pub disk_used_mb: u32,
    pub disk_total_mb: u32,
    pub cpu_percent: f32,
    pub boot_time: Instant,

    // -- firmware health --
    pub fw_crash_suppress: u32,
    pub fw_hardfault: u32,
    pub fw_health: String,

    // -- recovery --
    pub recovery_state: String,
    pub recovery_total: u32,
    pub recovery_soft_retries: u32,
    pub recovery_hard_retries: u32,
    pub recovery_last_str: String,

    // -- cracked passwords --
    pub cracked: Vec<CrackedEntry>,

    // -- display framebuffer snapshot (250x122, 1-bit packed, MSB first) --
    pub screen_width: u32,
    pub screen_height: u32,
    pub screen_bytes: Vec<u8>,

    // -- action requests from web -> daemon --
    pub pending_mode_switch: Option<String>,
    pub pending_rate_change: Option<u32>,
    pub pending_restart: bool,
    pub pending_shutdown: bool,
    pub pending_attack_toggle: Option<AttackToggle>,
    pub pending_bt_toggle: Option<bool>,
    /// Button tap event from pisugar-server shell script (1=single, 2=double, 3=long).
    pub pending_button_tap: Option<u8>,
    pub bt_scan_results: Vec<BtScanDevice>,
    pub bt_scan_in_progress: bool,
    pub pending_settings: Option<SettingsUpdate>,

    // -- plugins --
    pub plugin_list: Vec<PluginInfo>,
    pub pending_plugin_updates: Vec<PluginUpdate>,

    // -- nearby APs --
    pub ap_list: Vec<ApEntry>,

    // -- whitelist --
    pub whitelist: Vec<WhitelistEntry>,
    pub pending_whitelist_adds: Vec<WhitelistAdd>,
    pub pending_whitelist_removes: Vec<String>,

    // -- channel config --
    pub pending_channel_config: Option<ChannelConfig>,

    // -- rage slider --
    pub rage_enabled: bool,
    pub rage_level: u8,
    pub pending_rage_change: Option<Option<u8>>, // Some(Some(n)) = set level n, Some(None) = disable

    // -- smart skip --
    pub pending_skip_captured: Option<bool>,

    // -- capture mode --
    pub pending_capture_all: Option<bool>,

    // -- wpa-sec --
    pub wpasec_api_key: String,
    pub pending_wpasec_key: Option<String>,

    // -- wigle --
    pub wigle_api_name: String,
    pub wigle_api_token: String,
    pub pending_wigle_config: Option<(String, String)>,

    // -- discord --
    pub discord_webhook_url: String,
    pub discord_enabled: bool,
    pub pending_discord_config: Option<DiscordConfig>,

    // -- radio lock manager --
    pub radio_mode: String,
    pub radio_pid: u32,
    pub pending_radio_request: Option<String>,

    // -- mood interaction --
    pub interact_cooldowns: std::collections::HashMap<String, std::time::Instant>,
    pub pending_mood_boost: Option<f32>,

    // -- face packs --
    /// Currently active face pack name.
    pub active_face_pack: String,
    /// Discovered face packs (cached from last scan).
    pub face_packs: Vec<FacePackInfo>,
    /// User-requested pack switch — processed by daemon.
    pub pending_face_pack: Option<String>,
    /// Last face pack error message (for dashboard display).
    pub face_pack_last_error: Option<String>,
}

impl DaemonState {
    /// Create a default state for startup.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            uptime_str: "00:00:00".into(),
            epoch: 0,
            channel: 0,
            aps_seen: 0,
            handshakes: 0,
            blind_epochs: 0,
            mood: 0.5,
            face: "(O_O)".into(),
            status_message: "Booting...".into(),
            mode: "AO".into(),
            total_attacks: 0,
            total_handshakes_attacks: 0,
            attack_rate: 1,
            deauths_this_epoch: 0,
            attack_deauth: true,
            attack_pmkid: true,
            attack_csa: true,
            attack_disassoc: true,
            attack_anon_reassoc: true,
            attack_rogue_m2: true,
            capture_dir: "/home/pi/captures".into(),
            capture_files: 0,
            handshake_files: 0,
            pending_upload: 0,
            total_capture_size: 0,
            capture_list: Vec::new(),
            session_captures: 0,
            session_handshakes: 0,
            capture_all: false,
            pending_delete: None,
            battery_level: 100,
            battery_charging: false,
            battery_voltage_mv: 4200,
            battery_low: false,
            battery_critical: false,
            battery_available: false,
            wifi_state: "Down".into(),
            wifi_aps_tracked: 0,
            wifi_channels: vec![1, 6, 11],
            wifi_dwell_ms: 2000,
            autohunt_enabled: true,
            skip_captured: true,
            min_rssi: -100,
            ap_ttl_secs: 120,
            display_invert: true,
            display_rotation: 180,
            display_refresh_interval: 100,
            pending_display_reinit: false,
            // Seed the web-facing BT state with the "not yet connected"
            // status string rather than "Off". The daemon's first sync_to_web
            // overwrites this with the real BtTether::status_str(), but the
            // web server is reachable before that first sync runs, so the
            // seed value is what external queries see for the first second
            // or two after boot. "Off" misled users into thinking the
            // adapter was powered down.
            bt_state: "BT DISC".into(),
            bt_connected: false,
            bt_device_name: String::new(),
            bt_ip: String::new(),
            bt_internet_available: false,
            bt_retry_count: 0,
            bt_feature_mode: "Off".into(),
            bt_feature_devices_now: 0,
            bt_feature_contention_score: 0,
            bt_last_error_hint: String::new(),
            bt_attack_enabled: true,
            bt_rage_level: "Medium".into(),
            bt_scan_mode: "both".into(),
            bt_attack_smp_downgrade: true,
            bt_attack_knob: true,
            bt_attack_l2cap_fuzz: false,
            bt_attack_l2cap_conn_flood: false,
            bt_attack_att_gatt_fuzz: false,
            bt_total_attacks: 0,
            bt_total_captures: 0,
            bt_active_attacks: 0,
            bt_devices_seen: 0,
            bt_patchram_state: String::new(),
            bt_capture_keys: 0,
            bt_capture_transcripts: 0,
            bt_capture_crashes: 0,
            bt_capture_vendor: 0,
            bt_device_list: Vec::new(),
            pending_bt_attack_toggle: None,
            pending_bt_rage_level: None,
            pending_bt_scan_mode: None,
            pending_bt_manual_attack: None,
            bt_manual_result: None,
            bt_manual_result_ttl: 0,
            pending_bt_forget: None,
            bt_passkey: None,
            bt_passkey_device: String::new(),
            pending_bt_disconnect: None,
            pending_bt_reset_pairings: false,
            pending_bt_refresh_paired: false,
            paired_devices: Vec::new(),
            gpu_mode: "Off".into(),
            gpu_signal: "None".into(),
            gpu_submit_seen: false,
            gpu_snapshot_policy: "flush_immediate".into(),
            gpu_flush_threshold: 1,
            qpu_enabled: false,
            qpu_available: false,
            qpu_num_cores: 0,
            qpu_frames_submitted: 0,
            qpu_frames_classified: 0,
            qpu_batches_processed: 0,
            qpu_overflow_count: 0,
            qpu_last_batch_size: 0,
            qpu_last_batch_duration_us: 0,
            qpu_beacon_rate: 0.0,
            qpu_probe_rate: 0.0,
            qpu_deauth_rate: 0.0,
            qpu_data_rate: 0.0,
            qpu_unique_bssids: 0,
            qpu_total_frames: 0,
            qpu_dominant_class: String::new(),
            ao_state: "STOPPED".into(),
            ao_pid: 0,
            ao_crash_count: 0,
            ao_uptime: "N/A".into(),
            gpsd_available: false,
            xp: 0,
            level: 1,
            cpu_temp_c: 0.0,
            mem_used_mb: 0,
            mem_total_mb: 0,
            disk_used_mb: 0,
            disk_total_mb: 0,
            cpu_percent: 0.0,
            boot_time: Instant::now(),
            fw_crash_suppress: 0,
            fw_hardfault: 0,
            fw_health: "Unknown".into(),
            recovery_state: "Healthy".into(),
            recovery_total: 0,
            recovery_soft_retries: 0,
            recovery_hard_retries: 0,
            recovery_last_str: "never".into(),
            cracked: Vec::new(),
            screen_width: 250,
            screen_height: 122,
            screen_bytes: Vec::new(),
            pending_mode_switch: None,
            pending_rate_change: None,
            pending_restart: false,
            pending_shutdown: false,

            pending_attack_toggle: None,
            pending_bt_toggle: None,
            pending_button_tap: None,
            bt_scan_results: Vec::new(),
            bt_scan_in_progress: false,
            pending_settings: None,
            plugin_list: Vec::new(),
            pending_plugin_updates: Vec::new(),
            ap_list: Vec::new(),
            whitelist: Vec::new(),
            pending_whitelist_adds: Vec::new(),
            pending_whitelist_removes: Vec::new(),
            pending_channel_config: None,
            rage_enabled: false,
            rage_level: 1,
            pending_rage_change: None,
            pending_skip_captured: None,
            pending_capture_all: None,
            wpasec_api_key: String::new(),
            pending_wpasec_key: None,
            wigle_api_name: String::new(),
            wigle_api_token: String::new(),
            pending_wigle_config: None,
            discord_webhook_url: String::new(),
            discord_enabled: false,
            pending_discord_config: None,
            radio_mode: "FREE".into(),
            radio_pid: 0,
            pending_radio_request: None,
            interact_cooldowns: std::collections::HashMap::new(),
            pending_mood_boost: None,
            active_face_pack: "default".to_string(),
            face_packs: Vec::new(),
            pending_face_pack: None,
            face_pack_last_error: None,
        }
    }
}

/// Shared state type used by axum handlers.
pub type SharedState = Arc<Mutex<DaemonState>>;

/// Combined axum state: daemon shared state + WebSocket broadcast sender.
#[derive(Clone)]
pub struct AppState {
    pub shared: SharedState,
    pub ws_tx: broadcast::Sender<String>,
}

impl FromRef<AppState> for SharedState {
    fn from_ref(app: &AppState) -> Self {
        app.shared.clone()
    }
}

// ---------------------------------------------------------------------------
// WebSocket full-state snapshot (all dashboard data in one JSON push)
// ---------------------------------------------------------------------------

/// Combined snapshot of all dashboard-visible state, broadcast over WebSocket.
/// Field names intentionally match the individual REST API responses so the
/// frontend `updateAllCards()` can consume the same keys.
#[derive(Debug, Clone, Serialize)]
struct WsSnapshot {
    // -- status --
    name: String,
    version: String,
    uptime: String,
    epoch: u64,
    channel: u8,
    aps_seen: u32,
    handshakes: u32,
    blind_epochs: u32,
    mood: f32,
    face: String,
    status_message: String,
    mode: String,
    // -- battery --
    battery: BatteryInfo,
    // -- attacks --
    attacks: AttackStats,
    // -- wifi --
    wifi: WifiInfo,
    // -- bluetooth --
    bluetooth: BluetoothInfo,
    // -- bt attacks --
    bt_attacks: BtAttackResponse,
    bt_devices: BtDevicesResponse,
    bt_captures: BtCapturesResponse,
    bt_patchram: BtPatchramResponse,
    // -- gpu --
    gpu: GpuInfo,
    // -- qpu / rf classification --
    qpu: QpuInfo,
    // -- personality --
    personality: PersonalityInfo,
    // -- system --
    system: SystemInfoSnapshot,
    // -- recovery + health --
    recovery: RecoveryInfo,
    health: HealthResponse,
    // -- captures --
    captures: CaptureInfo,
    // -- cracked --
    cracked: Vec<CrackedEntry>,
    // -- aps --
    aps: Vec<ApEntry>,
    // -- whitelist --
    whitelist: Vec<WhitelistEntry>,
    // -- plugins --
    plugins: Vec<PluginInfo>,
    // -- radio --
    radio: RadioResponse,
    // -- settings --
    display_invert: bool,
    display_rotation: u16,
    display_refresh_interval: u32,
    min_rssi: i8,
    ap_ttl_secs: u64,
    // -- bt manual attack result --
    bt_manual_result: Option<BtManualResult>,
}

/// System info snapshot for WS (uses cached values, not live reads).
#[derive(Debug, Clone, Serialize)]
struct SystemInfoSnapshot {
    cpu_temp_c: f32,
    mem_used_mb: u32,
    mem_total_mb: u32,
    disk_used_mb: u32,
    disk_total_mb: u32,
    cpu_percent: f32,
    uptime_secs: u64,
}

/// Build a full WsSnapshot from the current DaemonState.
fn build_ws_snapshot(s: &DaemonState) -> WsSnapshot {
    WsSnapshot {
        name: s.name.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime: s.uptime_str.clone(),
        epoch: s.epoch,
        channel: s.channel,
        aps_seen: s.aps_seen,
        handshakes: s.handshakes,
        blind_epochs: s.blind_epochs,
        mood: s.mood,
        face: s.face.clone(),
        status_message: s.status_message.clone(),
        mode: s.mode.clone(),
        battery: BatteryInfo {
            level: s.battery_level,
            charging: s.battery_charging,
            voltage_mv: s.battery_voltage_mv,
            low: s.battery_low,
            critical: s.battery_critical,
            available: s.battery_available,
        },
        attacks: AttackStats {
            total_attacks: s.total_attacks,
            total_handshakes: s.total_handshakes_attacks,
            attack_rate: s.attack_rate,
            deauths_this_epoch: s.deauths_this_epoch,
            deauth: s.attack_deauth,
            pmkid: s.attack_pmkid,
            csa: s.attack_csa,
            disassoc: s.attack_disassoc,
            anon_reassoc: s.attack_anon_reassoc,
            rogue_m2: s.attack_rogue_m2,
        },
        wifi: WifiInfo {
            state: s.wifi_state.clone(),
            channel: s.channel,
            aps_tracked: s.wifi_aps_tracked,
            channels: s.wifi_channels.clone(),
            dwell_ms: s.wifi_dwell_ms,
            autohunt_enabled: s.autohunt_enabled,
            skip_captured: s.skip_captured,
            rage_level: if s.rage_enabled {
                Some(s.rage_level)
            } else {
                None
            },
        },
        bluetooth: BluetoothInfo {
            connected: s.bt_connected,
            state: s.bt_state.clone(),
            device_name: s.bt_device_name.clone(),
            ip: s.bt_ip.clone(),
            internet_available: s.bt_internet_available,
            retry_count: s.bt_retry_count,
            feature_mode: s.bt_feature_mode.clone(),
            nearby_devices: s.bt_feature_devices_now,
            contention_score: s.bt_feature_contention_score,
            passkey: s.bt_passkey,
            passkey_device: s.bt_passkey_device.clone(),
            // "Pairing in progress" from the UI's POV == Agent1 is waiting for
            // the user to tap Pair on the phone. Derived purely from passkey
            // presence now that the explicit state machine is gone.
            pair_in_progress: s.bt_passkey.is_some(),
            last_error_hint: s.bt_last_error_hint.clone(),
        },
        bt_attacks: BtAttackResponse {
            enabled: s.bt_attack_enabled,
            rage_level: s.bt_rage_level.clone(),
            scan_mode: s.bt_scan_mode.clone(),
            toggles: BtAttackToggles {
                smp_downgrade: s.bt_attack_smp_downgrade,
                knob: s.bt_attack_knob,
                l2cap_fuzz: s.bt_attack_l2cap_fuzz,
                l2cap_conn_flood: s.bt_attack_l2cap_conn_flood,
                att_gatt_fuzz: s.bt_attack_att_gatt_fuzz,
            },
            stats: BtAttackStats {
                total_attacks: s.bt_total_attacks,
                total_captures: s.bt_total_captures,
                active_attacks: s.bt_active_attacks,
                devices_seen: s.bt_devices_seen,
            },
        },
        bt_devices: BtDevicesResponse {
            count: s.bt_devices_seen,
            devices: s.bt_device_list.clone(),
        },
        bt_captures: BtCapturesResponse {
            keys: s.bt_capture_keys,
            transcripts: s.bt_capture_transcripts,
            crashes: s.bt_capture_crashes,
            vendor: s.bt_capture_vendor,
            total: (s.bt_capture_keys
                + s.bt_capture_transcripts
                + s.bt_capture_crashes
                + s.bt_capture_vendor) as u64,
        },
        bt_patchram: BtPatchramResponse {
            state: s.bt_patchram_state.clone(),
        },
        gpu: GpuInfo {
            mode: s.gpu_mode.clone(),
            signal: s.gpu_signal.clone(),
            submit_seen: s.gpu_submit_seen,
            snapshot_policy: s.gpu_snapshot_policy.clone(),
            flush_threshold: s.gpu_flush_threshold,
        },
        qpu: QpuInfo {
            enabled: s.qpu_enabled,
            available: s.qpu_available,
            num_cores: s.qpu_num_cores,
            frames_submitted: s.qpu_frames_submitted,
            frames_classified: s.qpu_frames_classified,
            batches_processed: s.qpu_batches_processed,
            overflow_count: s.qpu_overflow_count,
            last_batch_size: s.qpu_last_batch_size,
            last_batch_duration_us: s.qpu_last_batch_duration_us,
            beacon_rate: s.qpu_beacon_rate,
            probe_rate: s.qpu_probe_rate,
            deauth_rate: s.qpu_deauth_rate,
            data_rate: s.qpu_data_rate,
            unique_bssids: s.qpu_unique_bssids,
            total_frames: s.qpu_total_frames,
            dominant_class: s.qpu_dominant_class.clone(),
        },
        personality: PersonalityInfo {
            mood: s.mood,
            face: s.face.clone(),
            blind_epochs: s.blind_epochs,
            total_handshakes: s.handshakes,
            total_aps_seen: s.aps_seen,
            xp: s.xp,
            level: s.level,
        },
        system: SystemInfoSnapshot {
            cpu_temp_c: s.cpu_temp_c,
            mem_used_mb: s.mem_used_mb,
            mem_total_mb: s.mem_total_mb,
            disk_used_mb: s.disk_used_mb,
            disk_total_mb: s.disk_total_mb,
            cpu_percent: s.cpu_percent,
            uptime_secs: s.boot_time.elapsed().as_secs(),
        },
        recovery: RecoveryInfo {
            state: s.recovery_state.clone(),
            total_recoveries: s.recovery_total,
            soft_retries: s.recovery_soft_retries,
            hard_retries: s.recovery_hard_retries,
            last_recovery: s.recovery_last_str.clone(),
            diagnostic_count: 0,
            fw_crash_suppress: s.fw_crash_suppress,
            fw_hardfault: s.fw_hardfault,
            fw_health: s.fw_health.clone(),
        },
        health: HealthResponse {
            wifi_state: s.wifi_state.clone(),
            battery_level: s.battery_level,
            battery_charging: s.battery_charging,
            battery_available: s.battery_available,
            uptime_secs: s.boot_time.elapsed().as_secs(),
            ao_state: s.ao_state.clone(),
            ao_pid: s.ao_pid,
            ao_crash_count: s.ao_crash_count,
            ao_uptime: s.ao_uptime.clone(),
            gpsd_available: s.gpsd_available,
        },
        captures: CaptureInfo {
            total_files: s.capture_files,
            handshake_files: s.handshake_files,
            pending_upload: s.pending_upload,
            total_size_bytes: s.total_capture_size,
            session_captures: s.session_captures,
            session_handshakes: s.session_handshakes,
            capture_all: s.capture_all,
            files: s.capture_list.clone(),
        },
        cracked: s.cracked.clone(),
        aps: s.ap_list.clone(),
        whitelist: s.whitelist.clone(),
        plugins: s.plugin_list.clone(),
        radio: RadioResponse {
            mode: s.radio_mode.clone(),
            pid: s.radio_pid,
            owner: "daemon".into(),
        },
        display_invert: s.display_invert,
        display_rotation: s.display_rotation,
        display_refresh_interval: s.display_refresh_interval,
        min_rssi: s.min_rssi,
        ap_ttl_secs: s.ap_ttl_secs,
        bt_manual_result: s.bt_manual_result.clone(),
    }
}

/// Broadcast the current state to all connected WebSocket clients.
/// Called by the daemon after each `sync_to_web()`.
pub fn broadcast_state(shared: &SharedState, ws_tx: &broadcast::Sender<String>) {
    let s = shared.lock().unwrap();
    let snapshot = build_ws_snapshot(&s);
    drop(s); // release mutex before serializing
    if let Ok(json) = serde_json::to_string(&snapshot) {
        let _ = ws_tx.send(json); // ignore error if no subscribers
    }
}

// ---------------------------------------------------------------------------
// API response types
// ---------------------------------------------------------------------------

/// System status snapshot returned by /api/status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub name: String,
    pub version: String,
    pub uptime: String,
    pub epoch: u64,
    pub channel: u8,
    pub aps_seen: u32,
    pub handshakes: u32,
    pub blind_epochs: u32,
    pub mood: f32,
    pub face: String,
    pub status_message: String,
    pub mode: String,
    pub display_invert: bool,
    pub display_rotation: u16,
    pub display_refresh_interval: u32,
    pub min_rssi: i8,
    pub ap_ttl_secs: u64,
}

/// Attack stats returned by GET /api/attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStats {
    pub total_attacks: u64,
    pub total_handshakes: u64,
    pub attack_rate: u32,
    pub deauths_this_epoch: u32,
    pub deauth: bool,
    pub pmkid: bool,
    pub csa: bool,
    pub disassoc: bool,
    pub anon_reassoc: bool,
    pub rogue_m2: bool,
}

/// Attack toggle request for POST /api/attacks.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AttackToggle {
    #[serde(default)]
    pub deauth: Option<bool>,
    #[serde(default)]
    pub pmkid: Option<bool>,
    #[serde(default)]
    pub csa: Option<bool>,
    #[serde(default)]
    pub disassoc: Option<bool>,
    #[serde(default)]
    pub anon_reassoc: Option<bool>,
    #[serde(default)]
    pub rogue_m2: Option<bool>,
}

/// Capture info returned by /api/captures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureInfo {
    pub total_files: usize,
    pub handshake_files: usize,
    pub pending_upload: usize,
    pub total_size_bytes: u64,
    pub session_captures: u32,
    pub session_handshakes: u32,
    pub capture_all: bool,
    pub files: Vec<CaptureEntry>,
}

/// A single capture file entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureEntry {
    pub filename: String,
    pub size_bytes: u64,
    pub ssid: String,
    pub bssid_mac: String,
    pub captured_date: String,
    pub has_handshake: bool,
}

/// Health response returned by /api/health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub wifi_state: String,
    pub battery_level: u8,
    pub battery_charging: bool,
    pub battery_available: bool,
    pub uptime_secs: u64,
    pub ao_state: String,
    pub ao_pid: u32,
    pub ao_crash_count: u32,
    pub ao_uptime: String,
    pub gpsd_available: bool,
}

/// Mode switch request for POST /api/mode.
#[derive(Debug, Clone, Deserialize)]
pub struct ModeSwitch {
    pub mode: String,
}

/// Rate change request for POST /api/rate.
#[derive(Debug, Clone, Deserialize)]
pub struct RateChange {
    pub rate: u32,
}

/// Rage slider change request for POST /api/rage.
#[derive(Debug, Clone, Deserialize)]
pub struct RageChange {
    pub level: Option<u8>,
}

/// Radio status response for GET /api/radio.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadioResponse {
    pub mode: String,
    pub pid: u32,
    pub owner: String,
}

/// Radio request for POST /api/radio.
#[derive(Debug, Clone, Deserialize)]
pub struct RadioRequest {
    pub request: String,
}

/// Generic action response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResponse {
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct InteractRequest {
    pub action: String,
}

#[derive(Debug, Serialize)]
pub struct InteractResponse {
    pub ok: bool,
    pub message: String,
    pub cooldown_secs: u32,
}

#[derive(Debug, Serialize)]
pub struct InteractStatusResponse {
    pub pet: u32,
    pub treat: u32,
    pub praise: u32,
}

/// BT attack toggle request for POST /api/bt/attacks/toggle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtAttackToggle {
    pub attack: String,
    pub enabled: bool,
}

/// BT rage level change request for POST /api/bt/attacks/rage.
#[derive(Debug, Clone, Deserialize)]
pub struct BtRageLevelRequest {
    pub level: String,
}

/// BT scan mode change request for POST /api/bt/scan-mode.
#[derive(Debug, Clone, Deserialize)]
pub struct BtScanModeRequest {
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtManualAttackRequest {
    pub address: Option<String>,
    pub attack: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtManualResult {
    pub address: Option<String>,
    pub attack: String,
    pub success: bool,
    pub message: String,
}

/// BT attack state response for GET /api/bt/attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtAttackResponse {
    pub enabled: bool,
    pub rage_level: String,
    pub scan_mode: String,
    pub toggles: BtAttackToggles,
    pub stats: BtAttackStats,
}

/// BT attack toggle states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtAttackToggles {
    pub smp_downgrade: bool,
    pub knob: bool,
    pub l2cap_fuzz: bool,
    pub l2cap_conn_flood: bool,
    pub att_gatt_fuzz: bool,
}

/// BT attack statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtAttackStats {
    pub total_attacks: u64,
    pub total_captures: u64,
    pub active_attacks: u32,
    pub devices_seen: u32,
}

/// Brief paired device info for /api/bluetooth/paired.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedDeviceBrief {
    pub name: String,
    pub mac: String,
}

/// Lightweight device info for the web API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtDeviceInfo {
    pub address: String,
    pub name: Option<String>,
    pub rssi: Option<i16>,
    pub category: String,
    pub transport: String,
    pub attack_state: String,
    pub seen_count: u32,
    pub vendor: Option<String>,
    pub last_attack: Option<String>,
    pub last_attack_detail: Option<String>,
}

/// BT devices response for GET /api/bt/devices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtDevicesResponse {
    pub count: u32,
    pub devices: Vec<BtDeviceInfo>,
}

/// BT captures response for GET /api/bt/captures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtCapturesResponse {
    pub keys: u32,
    pub transcripts: u32,
    pub crashes: u32,
    pub vendor: u32,
    pub total: u64,
}

/// BT patchram response for GET /api/bt/patchram.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtPatchramResponse {
    pub state: String,
}

/// Config update request for /api/config.
#[derive(Debug, Clone, Deserialize)]
pub struct ConfigUpdate {
    pub name: Option<String>,
    pub attack_rate: Option<u32>,
    pub channel_dwell_ms: Option<u64>,
    pub whitelist_add: Option<String>,
    pub whitelist_remove: Option<String>,
}

/// Battery info returned by /api/battery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatteryInfo {
    pub level: u8,
    pub charging: bool,
    pub voltage_mv: u16,
    pub low: bool,
    pub critical: bool,
    pub available: bool,
}

/// WiFi info returned by /api/wifi.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiInfo {
    pub state: String,
    pub channel: u8,
    pub aps_tracked: usize,
    pub channels: Vec<u8>,
    pub dwell_ms: u64,
    pub autohunt_enabled: bool,
    pub skip_captured: bool,
    pub rage_level: Option<u8>,
}

/// WiFi update request for POST /api/wifi.
#[derive(Debug, Clone, Deserialize)]
pub struct WifiUpdate {
    pub skip_captured: Option<bool>,
}

/// Face pack information returned by GET /api/face_packs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FacePackInfo {
    pub name: String,
    pub is_default: bool,
    /// Number of cached .raw files ready to use.
    pub face_count: usize,
    /// Number of .png files awaiting conversion.
    pub converting: usize,
}

/// Request body for POST /api/face_packs.
#[derive(Debug, Clone, Deserialize)]
pub struct FacePackSelect {
    pub pack: String,
}

/// Response for GET /api/face_packs.
#[derive(Debug, Clone, Serialize)]
pub struct FacePacksResponse {
    pub active: String,
    pub packs: Vec<FacePackInfo>,
    pub last_error: Option<String>,
}

/// Bluetooth info returned by /api/bluetooth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothInfo {
    pub connected: bool,
    pub state: String,
    pub device_name: String,
    pub ip: String,
    pub internet_available: bool,
    pub retry_count: u32,
    pub feature_mode: String,
    pub nearby_devices: u32,
    pub contention_score: u32,
    pub passkey: Option<u32>,
    pub passkey_device: String,
    pub pair_in_progress: bool,
    /// User-actionable hint from the last failed PAN connect or DHCP
    /// attempt. Empty string when there's nothing to show. Rendered in
    /// the Phone Tethering card so users see "Bluetooth tethering isn't
    /// enabled on the phone" instead of a silent spinner.
    #[serde(default)]
    pub last_error_hint: String,
}

/// GPU info surfaced through the shared state/web snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    pub mode: String,
    pub signal: String,
    pub submit_seen: bool,
    pub snapshot_policy: String,
    pub flush_threshold: u32,
}

/// QPU info surfaced through the shared state/web snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QpuInfo {
    pub enabled: bool,
    pub available: bool,
    pub num_cores: u32,
    pub frames_submitted: u64,
    pub frames_classified: u64,
    pub batches_processed: u64,
    pub overflow_count: u64,
    pub last_batch_size: u32,
    pub last_batch_duration_us: u64,
    pub beacon_rate: f32,
    pub probe_rate: f32,
    pub deauth_rate: f32,
    pub data_rate: f32,
    pub unique_bssids: u32,
    pub total_frames: u32,
    pub dominant_class: String,
}

/// Bluetooth visibility toggle request.
#[derive(Debug, Clone, Deserialize)]
pub struct BtVisibilityToggle {
    pub visible: bool,
}

/// BT scan result entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtScanDevice {
    pub mac: String,
    pub name: String,
}

/// BT device reference by MAC. Used by the `/api/bluetooth/forget` handler;
/// the historical name is kept to avoid a gratuitous rename in web code.
#[derive(Debug, Clone, Deserialize)]
pub struct BtPairRequest {
    pub mac: String,
}

/// Recovery/health info returned by /api/recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryInfo {
    pub state: String,
    pub total_recoveries: u32,
    pub soft_retries: u32,
    pub hard_retries: u32,
    pub last_recovery: String,
    pub diagnostic_count: usize,
    pub fw_crash_suppress: u32,
    pub fw_hardfault: u32,
    pub fw_health: String,
}

/// Personality/mood info returned by /api/personality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalityInfo {
    pub mood: f32,
    pub face: String,
    pub blind_epochs: u32,
    pub total_handshakes: u32,
    pub total_aps_seen: u32,
    pub xp: u64,
    pub level: u32,
}

/// System info returned by /api/system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfoResponse {
    pub cpu_temp_c: f32,
    pub mem_used_mb: u32,
    pub mem_total_mb: u32,
    pub disk_used_mb: u32,
    pub disk_total_mb: u32,
    pub cpu_percent: f32,
    pub uptime_secs: u64,
}

/// Handshake file entry returned by /api/handshakes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeEntry {
    pub filename: String,
    pub ssid: String,
    pub size_bytes: u64,
    pub uploaded: bool,
}

/// A cracked password entry returned by /api/cracked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackedEntry {
    pub ssid: String,
    pub bssid: String,
    pub password: String,
    /// Date the password was fetched from WPA-SEC (YYYY-MM-DD UTC).
    #[serde(default)]
    pub date: String,
}

/// Plugin info for the web API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub name: String,
    pub version: String,
    pub author: String,
    pub tag: String,
    pub enabled: bool,
    pub x: i32,
    pub y: i32,
}

/// A plugin config update from the web dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginUpdate {
    pub name: String,
    pub enabled: Option<bool>,
    pub x: Option<i32>,
    pub y: Option<i32>,
}

/// A nearby access point entry returned by /api/aps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApEntry {
    pub bssid: String,
    pub ssid: String,
    pub rssi: i16,
    pub channel: u8,
    pub clients: u32,
    pub has_handshake: bool,
    #[serde(default)]
    pub whitelisted: bool,
}

/// A whitelist entry returned by /api/whitelist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistEntry {
    pub value: String,
    pub entry_type: String,
}

/// Request body for POST /api/whitelist/add.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistAdd {
    pub value: String,
    pub entry_type: String,
}

/// Request body for POST /api/whitelist/remove.
#[derive(Debug, Clone, Deserialize)]
pub struct WhitelistRemove {
    pub value: String,
}

/// Channel configuration request for POST /api/channels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelConfig {
    pub channels: Option<Vec<u8>>,
    pub dwell_ms: Option<u64>,
    #[serde(default)]
    pub autohunt: Option<bool>,
}

/// WPA-SEC config response returned by GET /api/wpasec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WpaSecResponse {
    pub api_key: String,
    pub enabled: bool,
}

/// WPA-SEC config update request for POST /api/wpasec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WpaSecUpdate {
    pub api_key: String,
}

/// WIGLE config response returned by GET /api/wigle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WigleResponse {
    pub api_name: String,
    pub enabled: bool,
}

/// WIGLE config update request for POST /api/wigle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WigleUpdate {
    pub api_name: String,
    pub api_token: String,
}

/// Discord webhook configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordConfig {
    pub webhook_url: String,
    pub enabled: bool,
}

/// Discord config response returned by GET /api/discord.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordResponse {
    pub webhook_url: String,
    pub enabled: bool,
}

/// Logs response returned by GET /api/logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogsResponse {
    pub lines: Vec<String>,
}

/// Settings update request for POST /api/settings.
#[derive(Debug, Clone, Deserialize)]
pub struct SettingsUpdate {
    pub name: Option<String>,
    pub display_invert: Option<bool>,
    pub display_rotation: Option<u16>,
    pub display_refresh_interval: Option<u32>,
    pub min_rssi: Option<i8>,
    pub ap_ttl_secs: Option<u64>,
}

// ---------------------------------------------------------------------------
// API route constants
// ---------------------------------------------------------------------------

pub const API_STATUS: &str = "/api/status";
pub const API_ATTACKS: &str = "/api/attacks";
pub const API_CAPTURES: &str = "/api/captures";
pub const API_CONFIG: &str = "/api/config";
pub const API_DISPLAY: &str = "/api/display.png";
pub const API_BATTERY: &str = "/api/battery";
pub const API_WIFI: &str = "/api/wifi";
pub const API_BLUETOOTH: &str = "/api/bluetooth";
pub const API_GPU: &str = "/api/gpu";
pub const API_QPU: &str = "/api/qpu";
pub const API_RECOVERY: &str = "/api/recovery";
pub const API_PERSONALITY: &str = "/api/personality";
pub const API_SYSTEM: &str = "/api/system";
pub const API_HANDSHAKES: &str = "/api/handshakes";
pub const API_HANDSHAKE_DL: &str = "/api/handshakes/:filename";
pub const API_MODE: &str = "/api/mode";
pub const API_RESTART: &str = "/api/restart";
pub const API_SHUTDOWN: &str = "/api/shutdown";
pub const API_BUTTON: &str = "/api/button";
pub const API_WHITELIST: &str = "/api/whitelist";
pub const API_CRACKED: &str = "/api/cracked";
pub const API_HEALTH: &str = "/api/health";
pub const API_RATE: &str = "/api/rate";
pub const API_APS: &str = "/api/aps";
pub const API_WHITELIST_ADD: &str = "/api/whitelist/add";
pub const API_WHITELIST_REMOVE: &str = "/api/whitelist/remove";
pub const API_CHANNELS: &str = "/api/channels";
pub const API_RAGE: &str = "/api/rage";
pub const API_LOGS: &str = "/api/logs";
pub const API_WPASEC: &str = "/api/wpasec";
pub const API_WIGLE: &str = "/api/wigle";
pub const API_DISCORD: &str = "/api/discord";
pub const API_DOWNLOAD_SINGLE: &str = "/api/download/:filename";
pub const API_DELETE_CAPTURE: &str = "/api/captures/:filename";
pub const API_RESTART_PI: &str = "/api/restart-pi";
pub const API_RESTART_SSH: &str = "/api/restart-ssh";
pub const API_RESTART_PWN: &str = "/api/restart-pwn";
pub const API_SETTINGS: &str = "/api/settings";
pub const API_BT_SCAN: &str = "/api/bluetooth/scan";
pub const API_RADIO: &str = "/api/radio";
pub const API_CAPTURE_ALL: &str = "/api/capture-all";
pub const API_BT_ATTACKS: &str = "/api/bt/attacks";
pub const API_BT_ATTACKS_TOGGLE: &str = "/api/bt/attacks/toggle";
pub const API_BT_ATTACKS_RAGE: &str = "/api/bt/attacks/rage";
pub const API_BT_ATTACKS_MANUAL: &str = "/api/bt/attacks/manual";
pub const API_BT_DEVICES: &str = "/api/bt/devices";
pub const API_BT_CAPTURES: &str = "/api/bt/captures";
pub const API_BT_PATCHRAM: &str = "/api/bt/patchram";
pub const API_BT_SCAN_MODE: &str = "/api/bt/scan-mode";
pub const API_BT_FORGET: &str = "/api/bluetooth/forget";
pub const API_BT_DISCONNECT: &str = "/api/bluetooth/disconnect";
pub const API_BT_RESET_PAIRINGS: &str = "/api/bluetooth/reset-pairings";
pub const API_BT_LIST_PAIRED: &str = "/api/bluetooth/paired";
pub const API_BT_REFRESH_PAIRED: &str = "/api/bluetooth/refresh-paired";
pub const API_INTERACT: &str = "/api/interact";
pub const API_FACE_PACKS: &str = "/api/face_packs";

// ---------------------------------------------------------------------------
// StatusParams helper (used by main.rs to build StatusResponse)
// ---------------------------------------------------------------------------

/// Parameters for building a [`StatusResponse`].
pub struct StatusParams<'a> {
    pub name: &'a str,
    pub uptime: &'a str,
    pub epoch: u64,
    pub channel: u8,
    pub aps_seen: u32,
    pub handshakes: u32,
    pub blind_epochs: u32,
    pub mood: f32,
    pub face: &'a str,
    pub status_message: &'a str,
    pub mode: &'a str,
    pub display_invert: bool,
    pub display_rotation: u16,
    pub display_refresh_interval: u32,
    pub min_rssi: i8,
    pub ap_ttl_secs: u64,
}

/// Build a [`StatusResponse`] from a [`StatusParams`] snapshot.
pub fn build_status(p: &StatusParams<'_>) -> StatusResponse {
    StatusResponse {
        name: p.name.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime: p.uptime.to_string(),
        epoch: p.epoch,
        channel: p.channel,
        aps_seen: p.aps_seen,
        handshakes: p.handshakes,
        blind_epochs: p.blind_epochs,
        mood: p.mood,
        face: p.face.to_string(),
        status_message: p.status_message.to_string(),
        mode: p.mode.to_string(),
        display_invert: p.display_invert,
        display_rotation: p.display_rotation,
        display_refresh_interval: p.display_refresh_interval,
        min_rssi: p.min_rssi,
        ap_ttl_secs: p.ap_ttl_secs,
    }
}

// ---------------------------------------------------------------------------
// System info helpers (read from /proc on Linux, stubs elsewhere)
// ---------------------------------------------------------------------------

/// Read CPU temperature from /sys/class/thermal on Linux.
pub fn read_cpu_temp() -> f32 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/sys/class/thermal/thermal_zone0/temp") {
            if let Ok(millideg) = content.trim().parse::<f32>() {
                return millideg / 1000.0;
            }
        }
    }
    0.0
}

/// Read memory info from /proc/meminfo on Linux.
pub fn read_mem_info() -> (u32, u32) {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
            let mut total_kb: u64 = 0;
            let mut available_kb: u64 = 0;
            for line in content.lines() {
                if line.starts_with("MemTotal:") {
                    total_kb = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                } else if line.starts_with("MemAvailable:") {
                    available_kb = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                }
            }
            let total_mb = (total_kb / 1024) as u32;
            let used_mb = ((total_kb.saturating_sub(available_kb)) / 1024) as u32;
            return (used_mb, total_mb);
        }
    }
    (0, 0)
}

/// Read disk usage for the root partition.
pub fn read_disk_info() -> (u32, u32) {
    #[cfg(target_os = "linux")]
    {
        // Use statvfs via libc
        unsafe {
            let path = std::ffi::CString::new("/").unwrap();
            let mut stat: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(path.as_ptr(), &mut stat) == 0 {
                let total = (stat.f_blocks as u64 * stat.f_frsize as u64) / (1024 * 1024);
                let avail = (stat.f_bavail as u64 * stat.f_frsize as u64) / (1024 * 1024);
                return ((total - avail) as u32, total as u32);
            }
        }
    }
    (0, 0)
}

// ---------------------------------------------------------------------------
// Axum route handlers
// ---------------------------------------------------------------------------

/// GET / -> dashboard HTML
async fn dashboard_handler() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

/// GET /api/status -> JSON status
async fn status_handler(State(state): State<SharedState>) -> Json<StatusResponse> {
    let s = state.lock().unwrap();
    Json(StatusResponse {
        name: s.name.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime: s.uptime_str.clone(),
        epoch: s.epoch,
        channel: s.channel,
        aps_seen: s.aps_seen,
        handshakes: s.handshakes,
        blind_epochs: s.blind_epochs,
        mood: s.mood,
        face: s.face.clone(),
        status_message: s.status_message.clone(),
        mode: s.mode.clone(),
        display_invert: s.display_invert,
        display_rotation: s.display_rotation,
        display_refresh_interval: s.display_refresh_interval,
        min_rssi: s.min_rssi,
        ap_ttl_secs: s.ap_ttl_secs,
    })
}

/// GET /api/captures -> JSON capture list
async fn captures_handler(State(state): State<SharedState>) -> Json<CaptureInfo> {
    let s = state.lock().unwrap();
    Json(CaptureInfo {
        total_files: s.capture_files,
        handshake_files: s.handshake_files,
        pending_upload: s.pending_upload,
        total_size_bytes: s.total_capture_size,
        session_captures: s.session_captures,
        session_handshakes: s.session_handshakes,
        capture_all: s.capture_all,
        files: s.capture_list.clone(),
    })
}

/// POST /api/capture-all -> toggle collect-all capture mode
async fn capture_all_handler(
    State(state): State<SharedState>,
    Json(body): Json<CaptureAllRequest>,
) -> Json<ActionResponse> {
    let mut s = state.lock().unwrap();
    s.capture_all = body.enabled; // optimistic: prevents WS from flipping checkbox back
    s.pending_capture_all = Some(body.enabled);
    Json(ActionResponse {
        ok: true,
        message: "Capture mode update queued — AO restarting".into(),
    })
}

#[derive(Debug, Deserialize)]
struct CaptureAllRequest {
    enabled: bool,
}

/// DELETE /api/captures/:filename -> queue a capture file for deletion
async fn delete_capture_handler(
    AxumPath(filename): AxumPath<String>,
    State(state): State<SharedState>,
) -> Json<ActionResponse> {
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return Json(ActionResponse {
            ok: false,
            message: "invalid filename".into(),
        });
    }
    let mut s = state.lock().unwrap();
    // Optimistic: remove from capture_list immediately so WS doesn't re-add it
    s.capture_list.retain(|f| f.filename != filename);
    s.capture_files = s.capture_list.len();
    s.handshake_files = s.capture_list.iter().filter(|f| f.has_handshake).count();
    s.pending_delete = Some(filename);
    Json(ActionResponse {
        ok: true,
        message: "queued for deletion".into(),
    })
}

/// GET /api/health -> JSON system health
async fn health_handler(State(state): State<SharedState>) -> Json<HealthResponse> {
    let s = state.lock().unwrap();
    Json(HealthResponse {
        wifi_state: s.wifi_state.clone(),
        battery_level: s.battery_level,
        battery_charging: s.battery_charging,
        battery_available: s.battery_available,
        uptime_secs: s.boot_time.elapsed().as_secs(),
        ao_state: s.ao_state.clone(),
        ao_pid: s.ao_pid,
        ao_crash_count: s.ao_crash_count,
        ao_uptime: s.ao_uptime.clone(),
        gpsd_available: s.gpsd_available,
    })
}

/// GET /api/battery -> JSON battery info
async fn battery_handler(State(state): State<SharedState>) -> Json<BatteryInfo> {
    let s = state.lock().unwrap();
    Json(BatteryInfo {
        level: s.battery_level,
        charging: s.battery_charging,
        voltage_mv: s.battery_voltage_mv,
        low: s.battery_low,
        critical: s.battery_critical,
        available: s.battery_available,
    })
}

/// GET /api/wifi -> JSON wifi info
async fn wifi_handler(State(state): State<SharedState>) -> Json<WifiInfo> {
    let s = state.lock().unwrap();
    Json(WifiInfo {
        state: s.wifi_state.clone(),
        channel: s.channel,
        aps_tracked: s.wifi_aps_tracked,
        channels: s.wifi_channels.clone(),
        dwell_ms: s.wifi_dwell_ms,
        autohunt_enabled: s.autohunt_enabled,
        skip_captured: s.skip_captured,
        rage_level: if s.rage_enabled {
            Some(s.rage_level)
        } else {
            None
        },
    })
}

/// POST /api/wifi -> update wifi settings (e.g. smart skip toggle)
async fn wifi_update_handler(
    State(state): State<SharedState>,
    Json(body): Json<WifiUpdate>,
) -> Json<ActionResponse> {
    let mut s = state.lock().unwrap();
    if let Some(skip) = body.skip_captured {
        s.skip_captured = skip; // optimistic: prevents toggle from jumping back on next refresh
        s.pending_skip_captured = Some(skip);
    }
    Json(ActionResponse {
        ok: true,
        message: "WiFi settings update queued".into(),
    })
}

/// GET /api/bluetooth -> JSON bluetooth info
async fn bluetooth_handler(State(state): State<SharedState>) -> Json<BluetoothInfo> {
    let s = state.lock().unwrap();
    Json(BluetoothInfo {
        connected: s.bt_connected,
        state: s.bt_state.clone(),
        device_name: s.bt_device_name.clone(),
        ip: s.bt_ip.clone(),
        internet_available: s.bt_internet_available,
        retry_count: s.bt_retry_count,
        feature_mode: s.bt_feature_mode.clone(),
        nearby_devices: s.bt_feature_devices_now,
        contention_score: s.bt_feature_contention_score,
        passkey: s.bt_passkey,
        passkey_device: s.bt_passkey_device.clone(),
        pair_in_progress: s.bt_passkey.is_some(),
        last_error_hint: s.bt_last_error_hint.clone(),
    })
}

/// GET /api/gpu -> JSON gpu/runtime info
async fn gpu_handler(State(state): State<SharedState>) -> Json<GpuInfo> {
    let s = state.lock().unwrap();
    Json(GpuInfo {
        mode: s.gpu_mode.clone(),
        signal: s.gpu_signal.clone(),
        submit_seen: s.gpu_submit_seen,
        snapshot_policy: s.gpu_snapshot_policy.clone(),
        flush_threshold: s.gpu_flush_threshold,
    })
}

/// GET /api/qpu -> JSON qpu classification stats
async fn qpu_handler(State(state): State<SharedState>) -> Json<QpuInfo> {
    let s = state.lock().unwrap();
    Json(QpuInfo {
        enabled: s.qpu_enabled,
        available: s.qpu_available,
        num_cores: s.qpu_num_cores,
        frames_submitted: s.qpu_frames_submitted,
        frames_classified: s.qpu_frames_classified,
        batches_processed: s.qpu_batches_processed,
        overflow_count: s.qpu_overflow_count,
        last_batch_size: s.qpu_last_batch_size,
        last_batch_duration_us: s.qpu_last_batch_duration_us,
        beacon_rate: s.qpu_beacon_rate,
        probe_rate: s.qpu_probe_rate,
        deauth_rate: s.qpu_deauth_rate,
        data_rate: s.qpu_data_rate,
        unique_bssids: s.qpu_unique_bssids,
        total_frames: s.qpu_total_frames,
        dominant_class: s.qpu_dominant_class.clone(),
    })
}

/// POST /api/bluetooth -> toggle bluetooth visibility
async fn bluetooth_toggle_handler(
    State(state): State<SharedState>,
    Json(body): Json<BtVisibilityToggle>,
) -> Json<ActionResponse> {
    let mut s = state.lock().unwrap();
    s.pending_bt_toggle = Some(body.visible);
    Json(ActionResponse {
        ok: true,
        message: format!(
            "Bluetooth visibility {} queued",
            if body.visible { "ON" } else { "OFF" }
        ),
    })
}

/// GET /api/personality -> JSON personality/mood info
async fn personality_handler(State(state): State<SharedState>) -> Json<PersonalityInfo> {
    let s = state.lock().unwrap();
    Json(PersonalityInfo {
        mood: s.mood,
        face: s.face.clone(),
        blind_epochs: s.blind_epochs,
        total_handshakes: s.handshakes,
        total_aps_seen: s.aps_seen,
        xp: s.xp,
        level: s.level,
    })
}

const INTERACT_COOLDOWN_SECS: u64 = 60; // 1 minute

/// Snarky/fun responses per action type.
fn interact_responses(action: &str, pct: i32) -> String {
    // Use epoch-based pseudo-random index for variety
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as usize;

    if pct <= 0 {
        let near_cap = match action {
            "pet" => vec!["*purrs* ...wait, I'm already maxed out", "Too much love! I'm gonna overheat"],
            "treat" => vec!["I'm stuffed, but thanks for trying", "My mood buffer is full, save it for later"],
            "praise" => vec!["My ego can't get any bigger", "Flattery won't work, I'm already at 100%"],
            _ => vec!["Mood near cap"],
        };
        return near_cap[seed % near_cap.len()].to_string();
    }

    match action {
        "pet" => {
            let msgs = vec![
                format!("*happy beeping* +{pct}% mood"),
                format!("Oh yes, right behind the antenna! +{pct}%"),
                format!("*wiggles pixels* +{pct}% mood"),
                format!("I'm not a cat, but I'll take it! +{pct}%"),
                format!("My e-ink is tingling! +{pct}% mood"),
            ];
            msgs[seed % msgs.len()].clone()
        }
        "treat" => {
            let msgs = vec![
                format!("*nom nom* Delicious handshakes! +{pct}% mood"),
                format!("Is that a WPA2 treat? Yummy! +{pct}%"),
                format!("Feed me more packets! +{pct}% mood"),
                format!("*crunches on deauth frames* +{pct}%"),
                format!("Better than a USB power bank! +{pct}% mood"),
            ];
            msgs[seed % msgs.len()].clone()
        }
        "praise" => {
            let msgs = vec![
                format!("Aww, you noticed! +{pct}% mood"),
                format!("I AM the goodest WiFi boi! +{pct}%"),
                format!("*blushes in monochrome* +{pct}% mood"),
                format!("Tell me more about my captures! +{pct}%"),
                format!("Flattery gets you everywhere! +{pct}% mood"),
            ];
            msgs[seed % msgs.len()].clone()
        }
        _ => format!("+{pct}% mood"),
    }
}

/// POST /api/interact — mood boost with cooldown and soft cap.
async fn interact_handler(
    State(state): State<SharedState>,
    Json(body): Json<InteractRequest>,
) -> Json<InteractResponse> {
    let base_boost = match body.action.as_str() {
        "pet" => 0.03f32,
        "treat" => 0.05f32,
        "praise" => 0.04f32,
        _ => {
            return Json(InteractResponse {
                ok: false,
                message: "Unknown action".into(),
                cooldown_secs: 0,
            });
        }
    };

    let mut s = state.lock().unwrap();
    let now = std::time::Instant::now();

    // Check global cooldown — any recent interaction blocks all buttons
    let most_recent = s.interact_cooldowns.values().max().copied();
    if let Some(last) = most_recent {
        let elapsed = now.duration_since(last).as_secs();
        if elapsed < INTERACT_COOLDOWN_SECS {
            let remaining = (INTERACT_COOLDOWN_SECS - elapsed) as u32;
            let cooldown_msgs = match body.action.as_str() {
                "pet" => "Easy there, I need a breather!",
                "treat" => "Still digesting the last one...",
                "praise" => "One compliment at a time, please!",
                _ => "On cooldown",
            };
            return Json(InteractResponse {
                ok: false,
                message: cooldown_msgs.into(),
                cooldown_secs: remaining,
            });
        }
    }

    // Compute effective boost
    let effective = crate::personality::interact_boost(base_boost, s.mood);
    let pct = (effective * 100.0).round() as i32;

    // Apply optimistically to shared state
    s.mood = (s.mood + effective).clamp(0.0, 1.0);

    // Queue for daemon to apply to real personality state
    let existing = s.pending_mood_boost.unwrap_or(0.0);
    s.pending_mood_boost = Some(existing + effective);

    // Update cooldown for this action
    s.interact_cooldowns.insert(body.action.clone(), now);

    let message = interact_responses(&body.action, pct);

    Json(InteractResponse {
        ok: true,
        message,
        cooldown_secs: INTERACT_COOLDOWN_SECS as u32,
    })
}

/// GET /api/interact — current cooldown status for all buttons.
async fn interact_status_handler(
    State(state): State<SharedState>,
) -> Json<InteractStatusResponse> {
    let s = state.lock().unwrap();
    let now = std::time::Instant::now();
    let remaining = |action: &str| -> u32 {
        s.interact_cooldowns
            .get(action)
            .map(|&last| {
                let elapsed = now.duration_since(last).as_secs();
                if elapsed < INTERACT_COOLDOWN_SECS {
                    (INTERACT_COOLDOWN_SECS - elapsed) as u32
                } else {
                    0
                }
            })
            .unwrap_or(0)
    };
    Json(InteractStatusResponse {
        pet: remaining("pet"),
        treat: remaining("treat"),
        praise: remaining("praise"),
    })
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

/// GET /api/system -> JSON system info (CPU, memory, disk)
async fn system_handler(State(state): State<SharedState>) -> Json<SystemInfoResponse> {
    // Read live system info where available
    let cpu_temp = read_cpu_temp();
    let (mem_used, mem_total) = read_mem_info();
    let (disk_used, disk_total) = read_disk_info();
    let s = state.lock().unwrap();
    Json(SystemInfoResponse {
        cpu_temp_c: if cpu_temp > 0.0 {
            cpu_temp
        } else {
            s.cpu_temp_c
        },
        mem_used_mb: if mem_total > 0 {
            mem_used
        } else {
            s.mem_used_mb
        },
        mem_total_mb: if mem_total > 0 {
            mem_total
        } else {
            s.mem_total_mb
        },
        disk_used_mb: if disk_total > 0 {
            disk_used
        } else {
            s.disk_used_mb
        },
        disk_total_mb: if disk_total > 0 {
            disk_total
        } else {
            s.disk_total_mb
        },
        cpu_percent: s.cpu_percent,
        uptime_secs: s.boot_time.elapsed().as_secs(),
    })
}

/// GET /api/attacks -> JSON attack stats + toggles
async fn attacks_get_handler(State(state): State<SharedState>) -> Json<AttackStats> {
    let s = state.lock().unwrap();
    Json(AttackStats {
        total_attacks: s.total_attacks,
        total_handshakes: s.total_handshakes_attacks,
        attack_rate: s.attack_rate,
        deauths_this_epoch: s.deauths_this_epoch,
        deauth: s.attack_deauth,
        pmkid: s.attack_pmkid,
        csa: s.attack_csa,
        disassoc: s.attack_disassoc,
        anon_reassoc: s.attack_anon_reassoc,
        rogue_m2: s.attack_rogue_m2,
    })
}

/// POST /api/attacks -> toggle attack types
async fn attacks_post_handler(
    State(state): State<SharedState>,
    Json(body): Json<AttackToggle>,
) -> Json<ActionResponse> {
    let mut s = state.lock().unwrap();
    // Apply toggles immediately to state; daemon will pick them up
    if let Some(v) = body.deauth {
        s.attack_deauth = v;
    }
    if let Some(v) = body.pmkid {
        s.attack_pmkid = v;
    }
    if let Some(v) = body.csa {
        s.attack_csa = v;
    }
    if let Some(v) = body.disassoc {
        s.attack_disassoc = v;
    }
    if let Some(v) = body.anon_reassoc {
        s.attack_anon_reassoc = v;
    }
    if let Some(v) = body.rogue_m2 {
        s.attack_rogue_m2 = v;
    }
    s.pending_attack_toggle = Some(body);
    Json(ActionResponse {
        ok: true,
        message: "Attack toggles updated".into(),
    })
}

/// GET /api/recovery -> JSON recovery info
async fn recovery_handler(State(state): State<SharedState>) -> Json<RecoveryInfo> {
    let s = state.lock().unwrap();
    Json(RecoveryInfo {
        state: s.recovery_state.clone(),
        total_recoveries: s.recovery_total,
        soft_retries: s.recovery_soft_retries,
        hard_retries: s.recovery_hard_retries,
        last_recovery: s.recovery_last_str.clone(),
        diagnostic_count: 0,
        fw_crash_suppress: s.fw_crash_suppress,
        fw_hardfault: s.fw_hardfault,
        fw_health: s.fw_health.clone(),
    })
}

/// GET /api/cracked -> JSON list of cracked passwords
async fn cracked_handler(State(state): State<SharedState>) -> Json<Vec<CrackedEntry>> {
    let s = state.lock().unwrap();
    Json(s.cracked.clone())
}

/// POST /api/mode -> switch mode
async fn mode_handler(
    State(state): State<SharedState>,
    Json(body): Json<ModeSwitch>,
) -> Json<ActionResponse> {
    let mut s = state.lock().unwrap();
    let mode = body.mode.to_uppercase();
    s.pending_mode_switch = Some(mode.clone());
    Json(ActionResponse {
        ok: true,
        message: format!("Mode switch to {} queued", mode),
    })
}

/// GET /api/radio -> current radio lock status
async fn radio_get_handler(State(state): State<SharedState>) -> Json<RadioResponse> {
    let s = state.lock().unwrap();
    Json(RadioResponse {
        mode: s.radio_mode.clone(),
        pid: s.radio_pid,
        owner: "daemon".into(),
    })
}

/// POST /api/radio -> request a radio mode switch
async fn radio_post_handler(
    State(state): State<SharedState>,
    Json(body): Json<RadioRequest>,
) -> Json<ActionResponse> {
    let request = body.request.to_uppercase();
    match request.as_str() {
        "WIFI" | "BT" | "FREE" => {
            let mut s = state.lock().unwrap();
            s.pending_radio_request = Some(request.clone());
            Json(ActionResponse {
                ok: true,
                message: format!("Radio mode switch to {} queued", request),
            })
        }
        _ => Json(ActionResponse {
            ok: false,
            message: format!("Invalid radio mode: {}. Use WIFI, BT, or FREE", request),
        }),
    }
}

/// POST /api/rate -> change attack rate
async fn rate_handler(
    State(state): State<SharedState>,
    Json(body): Json<RateChange>,
) -> Json<ActionResponse> {
    let rate = body.rate.clamp(1, 3);
    let mut s = state.lock().unwrap();
    s.attack_rate = rate; // optimistic: prevents rate buttons from jumping back on next refresh
    s.pending_rate_change = Some(rate);
    s.pending_rage_change = Some(None); // manual rate change breaks out of RAGE
    Json(ActionResponse {
        ok: true,
        message: format!("Rate change to {} queued", rate),
    })
}

/// POST /api/rage -> set or clear rage slider level
async fn rage_handler(
    State(state): State<SharedState>,
    Json(body): Json<RageChange>,
) -> Json<ActionResponse> {
    let mut s = state.lock().unwrap();
    match body.level {
        Some(level) => {
            let clamped = level.clamp(1, 7);
            // Optimistic: update all preset-controlled fields so UI reflects them instantly
            s.rage_enabled = true;
            s.rage_level = clamped;
            if let Some(p) = crate::rage::preset(clamped) {
                s.attack_rate = p.rate;
                s.wifi_channels = p.channels.to_vec();
                s.wifi_dwell_ms = p.dwell_ms;
                s.autohunt_enabled = false;
            }
            s.pending_rage_change = Some(Some(clamped));
            Json(ActionResponse {
                ok: true,
                message: format!("RAGE level {} queued", clamped),
            })
        }
        None => {
            s.rage_enabled = false; // optimistic
            s.pending_rage_change = Some(None);
            Json(ActionResponse {
                ok: true,
                message: "RAGE disabled, Custom mode".into(),
            })
        }
    }
}

/// POST /api/restart -> restart AO
async fn restart_handler(State(state): State<SharedState>) -> Json<ActionResponse> {
    let mut s = state.lock().unwrap();
    s.pending_restart = true;
    Json(ActionResponse {
        ok: true,
        message: "AO restart queued".into(),
    })
}

/// POST /api/shutdown -> system shutdown
async fn shutdown_handler(State(state): State<SharedState>) -> Json<ActionResponse> {
    let mut s = state.lock().unwrap();
    s.pending_shutdown = true;
    Json(ActionResponse {
        ok: true,
        message: "System shutdown queued".into(),
    })
}

/// GET /api/face_packs -> list packs with conversion status
async fn face_packs_get_handler(State(state): State<SharedState>) -> Json<FacePacksResponse> {
    let s = state.lock().unwrap();
    Json(FacePacksResponse {
        active: s.active_face_pack.clone(),
        packs: s.face_packs.clone(),
        last_error: s.face_pack_last_error.clone(),
    })
}

/// POST /api/face_packs -> select active pack. Body: {"pack": "name"}
async fn face_packs_post_handler(
    State(state): State<SharedState>,
    Json(body): Json<FacePackSelect>,
) -> Json<ActionResponse> {
    // Validate pack name: reject path traversal (../, /, \) and control chars.
    // Only allow alphanumeric, dash, underscore, space, dot.
    let name = &body.pack;
    if name.contains("..") || name.contains('/') || name.contains('\\')
        || name.chars().any(|c| c.is_control())
        || name.is_empty()
    {
        return Json(ActionResponse {
            ok: false,
            message: "Invalid pack name".into(),
        });
    }
    let mut s = state.lock().unwrap();
    s.pending_face_pack = Some(body.pack.clone());
    Json(ActionResponse {
        ok: true,
        message: format!("face pack '{}' queued", body.pack),
    })
}

/// POST /api/button -> queue a button tap event (called by pisugar-server shell scripts).
/// Body: {"tap": "single"} | {"tap": "double"} | {"tap": "long"}
async fn button_handler(
    State(state): State<SharedState>,
    Json(body): Json<serde_json::Value>,
) -> Json<ActionResponse> {
    let tap = body.get("tap").and_then(|v| v.as_str()).unwrap_or("");
    let tap_value = match tap {
        "single" => 1u8,
        "double" => 2,
        "long" => 3,
        _ => {
            return Json(ActionResponse {
                ok: false,
                message: format!("unknown tap type: {tap:?}"),
            });
        }
    };
    let mut s = state.lock().unwrap();
    s.pending_button_tap = Some(tap_value);
    Json(ActionResponse {
        ok: true,
        message: format!("button {tap} queued"),
    })
}

/// GET /api/plugins -> JSON list of all plugins
async fn plugins_get_handler(State(state): State<SharedState>) -> Json<Vec<PluginInfo>> {
    let s = state.lock().unwrap();
    Json(s.plugin_list.clone())
}

/// POST /api/plugins -> update plugin configs (array of updates)
async fn plugins_post_handler(
    State(state): State<SharedState>,
    Json(body): Json<Vec<PluginUpdate>>,
) -> Json<ActionResponse> {
    let mut s = state.lock().unwrap();
    s.pending_plugin_updates.extend(body);
    Json(ActionResponse {
        ok: true,
        message: "Plugin updates queued".into(),
    })
}

/// GET /api/aps -> JSON list of nearby access points (sorted by RSSI)
async fn aps_handler(State(state): State<SharedState>) -> Json<Vec<ApEntry>> {
    let s = state.lock().unwrap();
    let mut aps = s.ap_list.clone();
    aps.sort_by(|a, b| a.rssi.cmp(&b.rssi)); // strongest (least negative) last; JS will display strongest first
    Json(aps)
}

/// GET /api/whitelist -> JSON list of whitelist entries
async fn whitelist_get_handler(State(state): State<SharedState>) -> Json<Vec<WhitelistEntry>> {
    let s = state.lock().unwrap();
    Json(s.whitelist.clone())
}

/// POST /api/whitelist/add -> add a whitelist entry
async fn whitelist_add_handler(
    State(state): State<SharedState>,
    Json(body): Json<WhitelistAdd>,
) -> Json<ActionResponse> {
    let mut s = state.lock().unwrap();
    // Optimistic: add to list immediately so UI shows it without waiting for epoch
    s.whitelist.push(WhitelistEntry {
        value: body.value.clone(),
        entry_type: body.entry_type.clone(),
    });
    s.pending_whitelist_adds.push(body);
    Json(ActionResponse {
        ok: true,
        message: "Whitelist add queued".into(),
    })
}

/// POST /api/whitelist/remove -> remove a whitelist entry
async fn whitelist_remove_handler(
    State(state): State<SharedState>,
    Json(body): Json<WhitelistRemove>,
) -> Json<ActionResponse> {
    let mut s = state.lock().unwrap();
    // Optimistic: remove from list immediately so UI reflects it without waiting for epoch
    s.whitelist.retain(|e| e.value != body.value);
    s.pending_whitelist_removes.push(body.value);
    Json(ActionResponse {
        ok: true,
        message: "Whitelist remove queued".into(),
    })
}

/// POST /api/channels -> update channel configuration
async fn channels_handler(
    State(state): State<SharedState>,
    Json(body): Json<ChannelConfig>,
) -> Json<ActionResponse> {
    let mut s = state.lock().unwrap();
    // Update autohunt_enabled immediately so the UI doesn't jump back on next refresh.
    // The daemon will still pick up the full config at the start of the next epoch.
    if let Some(ah) = body.autohunt {
        s.autohunt_enabled = ah;
    }
    s.pending_channel_config = Some(body);
    s.pending_rage_change = Some(None); // manual channel change breaks out of RAGE
    Json(ActionResponse {
        ok: true,
        message: "Channel config update queued".into(),
    })
}

/// GET /api/logs -> last 50 lines of journalctl output
async fn logs_handler() -> Json<LogsResponse> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("journalctl")
            .args(["-u", "rusty-oxigotchi", "-n", "50", "--no-pager"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
            return Json(LogsResponse { lines });
        }
    }
    Json(LogsResponse { lines: Vec::new() })
}

// ---------------------------------------------------------------------------
// WPA-SEC endpoints
// ---------------------------------------------------------------------------

/// GET /api/wpasec -> JSON wpa-sec config (key masked)
async fn wpasec_get_handler(State(state): State<SharedState>) -> Json<WpaSecResponse> {
    let s = state.lock().unwrap();
    let key = &s.wpasec_api_key;
    let masked = if key.len() > 4 {
        format!("{}****", safe_truncate(key, 4))
    } else if !key.is_empty() {
        "****".into()
    } else {
        String::new()
    };
    Json(WpaSecResponse {
        api_key: masked,
        enabled: !s.wpasec_api_key.is_empty(),
    })
}

/// POST /api/wpasec -> set wpa-sec API key
async fn wpasec_post_handler(
    State(state): State<SharedState>,
    Json(body): Json<WpaSecUpdate>,
) -> Json<ActionResponse> {
    let mut s = state.lock().unwrap();
    s.wpasec_api_key = body.api_key.clone(); // optimistic: UI reads this via GET /api/wpasec
    s.pending_wpasec_key = Some(body.api_key);
    Json(ActionResponse {
        ok: true,
        message: "WPA-SEC key update queued".into(),
    })
}

// ---------------------------------------------------------------------------
// WIGLE endpoints
// ---------------------------------------------------------------------------

/// GET /api/wigle -> JSON WIGLE config (token never returned)
async fn wigle_get_handler(State(state): State<SharedState>) -> Json<WigleResponse> {
    let s = state.lock().unwrap();
    Json(WigleResponse {
        api_name: s.wigle_api_name.clone(),
        enabled: !s.wigle_api_name.is_empty() && !s.wigle_api_token.is_empty(),
    })
}

/// POST /api/wigle -> set WIGLE API name and token
async fn wigle_post_handler(
    State(state): State<SharedState>,
    Json(body): Json<WigleUpdate>,
) -> Json<ActionResponse> {
    let mut s = state.lock().unwrap();
    s.wigle_api_name = body.api_name.clone();
    s.pending_wigle_config = Some((body.api_name, body.api_token));
    Json(ActionResponse {
        ok: true,
        message: "WIGLE config update queued".into(),
    })
}

// ---------------------------------------------------------------------------
// Discord webhook endpoints
// ---------------------------------------------------------------------------

/// GET /api/discord -> JSON discord config
async fn discord_get_handler(State(state): State<SharedState>) -> Json<DiscordResponse> {
    let s = state.lock().unwrap();
    let url = &s.discord_webhook_url;
    let masked = if url.len() > 30 {
        format!("{}****", safe_truncate(url, 30))
    } else if !url.is_empty() {
        "****".into()
    } else {
        String::new()
    };
    Json(DiscordResponse {
        webhook_url: masked,
        enabled: s.discord_enabled,
    })
}

/// POST /api/discord -> set discord config
async fn discord_post_handler(
    State(state): State<SharedState>,
    Json(body): Json<DiscordConfig>,
) -> Json<ActionResponse> {
    let mut s = state.lock().unwrap();
    // Optimistic: UI reads these via GET /api/discord
    s.discord_webhook_url = body.webhook_url.clone();
    s.discord_enabled = body.enabled;
    s.pending_discord_config = Some(body);
    Json(ActionResponse {
        ok: true,
        message: "Discord config update queued".into(),
    })
}

// ---------------------------------------------------------------------------
// Single capture download endpoint
// ---------------------------------------------------------------------------

/// GET /api/download/:filename -> serve a single capture file
async fn download_single_handler(
    AxumPath(filename): AxumPath<String>,
    State(state): State<SharedState>,
) -> axum::response::Response<axum::body::Body> {
    use axum::http::{StatusCode, header};

    let capture_dir = {
        let s = state.lock().unwrap();
        s.capture_dir.clone()
    };

    // Sanitize filename: reject path traversal
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return axum::response::Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(axum::body::Body::from("invalid filename"))
            .unwrap();
    }

    let path = std::path::Path::new(&capture_dir).join(&filename);
    if !path.exists() || !path.is_file() {
        return axum::response::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(axum::body::Body::from("file not found"))
            .unwrap();
    }

    match std::fs::read(&path) {
        Ok(data) => axum::response::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", filename),
            )
            .body(axum::body::Body::from(data))
            .unwrap(),
        Err(_) => axum::response::Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(axum::body::Body::from("failed to read file"))
            .unwrap(),
    }
}

// ---------------------------------------------------------------------------
// System control endpoints
// ---------------------------------------------------------------------------

/// POST /api/restart-pi -> reboot the Pi
async fn restart_pi_handler() -> Json<ActionResponse> {
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("sudo").arg("reboot").spawn();
    }
    Json(ActionResponse {
        ok: true,
        message: "Pi reboot initiated".into(),
    })
}

/// POST /api/restart-ssh -> restart SSH service
async fn restart_ssh_handler() -> Json<ActionResponse> {
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("sudo")
            .args(["systemctl", "restart", "ssh"])
            .spawn();
    }
    Json(ActionResponse {
        ok: true,
        message: "SSH restart initiated".into(),
    })
}

/// POST /api/bluetooth/scan -> trigger BT scan, return cached results.
/// Used by BT attack mode; phone tethering is phone-initiated and does not
/// go through this path.
async fn bt_scan_handler(State(state): State<SharedState>) -> Json<Vec<BtScanDevice>> {
    let mut s = state.lock().unwrap();
    if s.bt_scan_in_progress {
        // Return current cached results while scan is in progress
        return Json(s.bt_scan_results.clone());
    }
    // Signal main loop to run a scan
    s.bt_scan_in_progress = true;
    s.bt_scan_results.clear();
    Json(Vec::new())
}

/// GET /api/bluetooth/scan -> get cached scan results
async fn bt_scan_results_handler(State(state): State<SharedState>) -> Json<Vec<BtScanDevice>> {
    let s = state.lock().unwrap();
    Json(s.bt_scan_results.clone())
}

/// POST /api/bluetooth/forget -> remove a paired device
async fn bt_forget_handler(
    State(state): State<SharedState>,
    Json(body): Json<BtPairRequest>,
) -> impl IntoResponse {
    let mut s = state.lock().unwrap();
    // Convert MAC to D-Bus path: AA:BB:CC:DD:EE:FF -> /org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF
    let path = format!(
        "/org/bluez/hci0/dev_{}",
        body.mac.replace(':', "_")
    );
    s.pending_bt_forget = Some(path);
    Json(serde_json::json!({"ok": true}))
}

/// POST /api/bluetooth/disconnect -> disconnect PAN (suppresses auto-reconnect)
async fn bt_disconnect_handler(
    State(state): State<SharedState>,
) -> impl IntoResponse {
    let mut s = state.lock().unwrap();
    s.pending_bt_disconnect = Some(true);
    Json(serde_json::json!({"ok": true}))
}

/// GET /api/bluetooth/paired -> return the currently cached paired-device list.
/// This reads only from shared state — the daemon does NOT refresh it here.
/// Callers that want fresh data must POST /api/bluetooth/refresh-paired first
/// and then GET this endpoint on the next epoch.
async fn bt_list_paired_handler(State(state): State<SharedState>) -> Json<Vec<PairedDeviceBrief>> {
    let s = state.lock().unwrap();
    Json(s.paired_devices.clone())
}

/// POST /api/bluetooth/refresh-paired -> queue a refresh of the paired cache.
/// Deliberate user opt-in so the daemon only initializes D-Bus when asked.
async fn bt_refresh_paired_handler(State(state): State<SharedState>) -> Json<ActionResponse> {
    let mut s = state.lock().unwrap();
    s.pending_bt_refresh_paired = true;
    Json(ActionResponse {
        ok: true,
        message: "BT paired refresh queued".into(),
    })
}

/// POST /api/bluetooth/reset-pairings -> queue removal of all paired devices.
/// Danger: this forgets every paired BT device.
async fn bt_reset_pairings_handler(State(state): State<SharedState>) -> Json<ActionResponse> {
    let mut s = state.lock().unwrap();
    s.pending_bt_reset_pairings = true;
    Json(ActionResponse {
        ok: true,
        message: "BT reset pairings queued".into(),
    })
}

/// POST /api/settings -> update device settings (name, etc.)
async fn settings_handler(
    State(state): State<SharedState>,
    Json(body): Json<SettingsUpdate>,
) -> Json<ActionResponse> {
    let mut s = state.lock().unwrap();
    // Optimistic: update all fields immediately so UI doesn't show stale values
    if let Some(ref name) = body.name {
        if !name.is_empty() {
            s.name = name.clone();
        }
    }
    if let Some(invert) = body.display_invert {
        if invert != s.display_invert {
            s.display_invert = invert;
            s.pending_display_reinit = true;
        }
    }
    if let Some(rotation) = body.display_rotation {
        let r = if rotation == 180 { 180 } else { 0 };
        if r != s.display_rotation {
            s.display_rotation = r;
            s.pending_display_reinit = true;
        }
    }
    if let Some(interval) = body.display_refresh_interval {
        s.display_refresh_interval = interval.clamp(10, 500);
    }
    if let Some(rssi) = body.min_rssi {
        s.min_rssi = rssi.clamp(-100, -30);
    }
    if let Some(ttl) = body.ap_ttl_secs {
        s.ap_ttl_secs = ttl.clamp(30, 600);
    }
    s.pending_settings = Some(body);
    Json(ActionResponse {
        ok: true,
        message: "Settings update queued".into(),
    })
}

/// POST /api/restart-pwn -> restart the oxigotchi service itself
async fn restart_pwn_handler() -> Json<ActionResponse> {
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("sudo")
            .args(["systemctl", "restart", "rusty-oxigotchi"])
            .spawn();
    }
    Json(ActionResponse {
        ok: true,
        message: "Oxigotchi restart initiated".into(),
    })
}

// ---------------------------------------------------------------------------
// Display framebuffer endpoint
// ---------------------------------------------------------------------------

/// GET /api/display.png -> 1-bit BMP of the current e-ink framebuffer.
/// Returns a 250x122 monochrome BMP image.
async fn display_handler(
    State(state): State<SharedState>,
) -> axum::response::Response<axum::body::Body> {
    use axum::http::{StatusCode, header};

    let s = state.lock().unwrap();
    let w = s.screen_width;
    let h = s.screen_height;
    let fb = s.screen_bytes.clone();
    drop(s);

    if fb.is_empty() {
        return axum::response::Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(axum::body::Body::from("no framebuffer yet"))
            .unwrap();
    }

    // Build a 1-bit BMP (monochrome, uncompressed).
    // BMP stores rows bottom-to-top, each row padded to 4-byte boundary.
    let fb_stride = ((w + 7) / 8) as usize; // 32 bytes per row in our framebuffer
    let bmp_stride = ((w + 31) / 32 * 4) as usize; // 32 bytes (250 bits -> 32 bytes, already 4-byte aligned)
    let pixel_data_size = bmp_stride * h as usize;
    let file_header_size = 14u32;
    let dib_header_size = 40u32;
    let color_table_size = 8u32; // 2 entries * 4 bytes each
    let pixel_offset = file_header_size + dib_header_size + color_table_size;
    let file_size = pixel_offset + pixel_data_size as u32;

    let mut bmp = Vec::with_capacity(file_size as usize);

    // File header (14 bytes)
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(&file_size.to_le_bytes());
    bmp.extend_from_slice(&[0u8; 4]); // reserved
    bmp.extend_from_slice(&pixel_offset.to_le_bytes());

    // DIB header (BITMAPINFOHEADER, 40 bytes)
    bmp.extend_from_slice(&dib_header_size.to_le_bytes());
    bmp.extend_from_slice(&(w as i32).to_le_bytes());
    bmp.extend_from_slice(&(h as i32).to_le_bytes());
    bmp.extend_from_slice(&1u16.to_le_bytes()); // planes
    bmp.extend_from_slice(&1u16.to_le_bytes()); // bits per pixel
    bmp.extend_from_slice(&0u32.to_le_bytes()); // compression (none)
    bmp.extend_from_slice(&(pixel_data_size as u32).to_le_bytes());
    bmp.extend_from_slice(&2835i32.to_le_bytes()); // h resolution (72 DPI)
    bmp.extend_from_slice(&2835i32.to_le_bytes()); // v resolution
    bmp.extend_from_slice(&0u32.to_le_bytes()); // colors used
    bmp.extend_from_slice(&0u32.to_le_bytes()); // important colors

    // Color table: index 0 = black (0x00), index 1 = white (0xFF)
    // In our framebuffer: bit 1 = black (On), bit 0 = white (Off)
    // BMP: palette[0] for bit=0, palette[1] for bit=1
    // So palette[0] = white, palette[1] = black
    bmp.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0x00]); // palette[0] = white (bit 0 = Off)
    bmp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // palette[1] = black (bit 1 = On)

    // Pixel data: BMP is bottom-to-top, our framebuffer is top-to-bottom
    for row in (0..h as usize).rev() {
        let fb_row_start = row * fb_stride;
        let fb_row_end = fb_row_start + fb_stride;
        if fb_row_end <= fb.len() {
            bmp.extend_from_slice(&fb[fb_row_start..fb_row_end]);
        } else {
            bmp.extend_from_slice(&vec![0u8; bmp_stride]);
        }
        // Pad to bmp_stride if needed
        if fb_stride < bmp_stride {
            bmp.extend_from_slice(&vec![0u8; bmp_stride - fb_stride]);
        }
    }

    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "image/bmp")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(axum::body::Body::from(bmp))
        .unwrap()
}

// ---------------------------------------------------------------------------
// Router builder
/// GET /api/download/all -> ZIP of all capture files
async fn download_zip_handler(State(state): State<SharedState>) -> axum::response::Response {
    use axum::http::{StatusCode, header};
    use std::io::Write;

    let capture_dir = {
        let s = state.lock().unwrap();
        s.capture_dir.clone()
    };

    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        if let Ok(entries) = std::fs::read_dir(&capture_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    if let Ok(data) = std::fs::read(&path) {
                        let _ = zip.start_file(&name, options);
                        let _ = zip.write_all(&data);
                    }
                }
            }
        }
        let _ = zip.finish();
    }

    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/zip")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"captures.zip\"",
        )
        .body(axum::body::Body::from(buf.into_inner()))
        .unwrap()
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// BT attack API handlers
// ---------------------------------------------------------------------------

/// GET /api/bt/attacks -> JSON BT attack state
async fn bt_attacks_get_handler(State(state): State<SharedState>) -> Json<BtAttackResponse> {
    let s = state.lock().unwrap();
    Json(BtAttackResponse {
        enabled: s.bt_attack_enabled,
        rage_level: s.bt_rage_level.clone(),
        scan_mode: s.bt_scan_mode.clone(),
        toggles: BtAttackToggles {
            smp_downgrade: s.bt_attack_smp_downgrade,
            knob: s.bt_attack_knob,
            l2cap_fuzz: s.bt_attack_l2cap_fuzz,
            l2cap_conn_flood: s.bt_attack_l2cap_conn_flood,
            att_gatt_fuzz: s.bt_attack_att_gatt_fuzz,
        },
        stats: BtAttackStats {
            total_attacks: s.bt_total_attacks,
            total_captures: s.bt_total_captures,
            active_attacks: s.bt_active_attacks,
            devices_seen: s.bt_devices_seen,
        },
    })
}

/// POST /api/bt/attacks/toggle -> toggle a BT attack type
async fn bt_attacks_toggle_handler(
    State(state): State<SharedState>,
    Json(body): Json<BtAttackToggle>,
) -> Json<ActionResponse> {
    let mut s = state.lock().unwrap();
    // Optimistic update: immediately set the matching field
    match body.attack.as_str() {
        "smp_downgrade" => s.bt_attack_smp_downgrade = body.enabled,
        "knob" => s.bt_attack_knob = body.enabled,
        "l2cap_fuzz" => s.bt_attack_l2cap_fuzz = body.enabled,
        "l2cap_conn_flood" => s.bt_attack_l2cap_conn_flood = body.enabled,
        "att_gatt_fuzz" => s.bt_attack_att_gatt_fuzz = body.enabled,
        _ => {}
    }
    s.pending_bt_attack_toggle = Some(body);
    Json(ActionResponse {
        ok: true,
        message: "BT attack toggle updated".into(),
    })
}

/// POST /api/bt/attacks/rage -> set BT rage level
async fn bt_attacks_rage_handler(
    State(state): State<SharedState>,
    Json(body): Json<BtRageLevelRequest>,
) -> Json<ActionResponse> {
    if !matches!(body.level.as_str(), "Low" | "Medium" | "High") {
        return Json(ActionResponse {
            ok: false,
            message: "Invalid rage level".into(),
        });
    }
    let mut s = state.lock().unwrap();
    s.bt_rage_level = body.level.clone(); // optimistic
    s.pending_bt_rage_level = Some(body.level.clone());
    Json(ActionResponse {
        ok: true,
        message: format!("BT rage level set to {}", body.level),
    })
}

/// POST /api/bt/scan-mode -> set BT scan mode
async fn bt_scan_mode_handler(
    State(state): State<SharedState>,
    Json(body): Json<BtScanModeRequest>,
) -> Json<ActionResponse> {
    if crate::bluetooth::attacks::BtScanMode::from_str(&body.mode).is_none() {
        return Json(ActionResponse {
            ok: false,
            message: "Invalid scan mode (ble, classic, both)".into(),
        });
    }
    let mut s = state.lock().unwrap();
    s.bt_scan_mode = body.mode.clone(); // optimistic
    s.pending_bt_scan_mode = Some(body.mode.clone());
    Json(ActionResponse {
        ok: true,
        message: format!("BT scan mode set to {}", body.mode),
    })
}

/// Returns true if the given string is a valid Bluetooth address (XX:XX:XX:XX:XX:XX, hex digits).
fn is_valid_bt_address(addr: &str) -> bool {
    let parts: Vec<&str> = addr.split(':').collect();
    parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// POST /api/bt/attacks/manual -> queue a manual BT attack
async fn bt_manual_attack_handler(
    State(state): State<SharedState>,
    Json(body): Json<BtManualAttackRequest>,
) -> Json<ActionResponse> {
    // 1. Validate attack name is manual-capable
    let attack_type = match body.attack.as_str() {
        "knob" => crate::bluetooth::attacks::BtAttackType::Knob,
        "ble_adv_injection" => crate::bluetooth::attacks::BtAttackType::BleAdvInjection,
        "l2cap_fuzz" => crate::bluetooth::attacks::BtAttackType::L2capFuzz,
        "l2cap_conn_flood" => crate::bluetooth::attacks::BtAttackType::L2capConnFlood,
        "att_gatt_fuzz" => crate::bluetooth::attacks::BtAttackType::AttGattFuzz,
        "vendor_cmd_unlock" => crate::bluetooth::attacks::BtAttackType::VendorCmdUnlock,
        _ => {
            return Json(ActionResponse {
                ok: false,
                message: format!("Unknown or non-manual attack: {}", body.attack),
            });
        }
    };

    // 2. Validate address if required (not needed for vendor_cmd_unlock)
    if attack_type != crate::bluetooth::attacks::BtAttackType::VendorCmdUnlock {
        match &body.address {
            Some(addr) if is_valid_bt_address(addr) => {}
            Some(_) => {
                return Json(ActionResponse {
                    ok: false,
                    message: "Invalid BT address".into(),
                });
            }
            None => {
                return Json(ActionResponse {
                    ok: false,
                    message: "Address required for this attack".into(),
                });
            }
        }
    }

    let mut s = state.lock().unwrap();

    // 3. Reject if another manual attack is pending
    if s.pending_bt_manual_attack.is_some() {
        return Json(ActionResponse {
            ok: false,
            message: "Manual attack already pending".into(),
        });
    }

    // 4. Check rage level
    let current_rage = crate::bluetooth::attacks::BtRageLevel::from_str(&s.bt_rage_level)
        .unwrap_or(crate::bluetooth::attacks::BtRageLevel::Low);
    if attack_type.min_rage_level() > current_rage {
        return Json(ActionResponse {
            ok: false,
            message: format!(
                "{} requires rage level {:?} or higher",
                body.attack,
                attack_type.min_rage_level()
            ),
        });
    }

    // 5. Optimistic update — mark device as Attacking if address provided
    if let Some(ref addr) = body.address {
        for dev in &mut s.bt_device_list {
            if dev.address == *addr {
                dev.attack_state = "Attacking".to_string();
                break;
            }
        }
    }

    s.pending_bt_manual_attack = Some(body);
    Json(ActionResponse {
        ok: true,
        message: "Manual attack queued".into(),
    })
}

/// GET /api/bt/devices -> JSON device list with count
async fn bt_devices_handler(State(state): State<SharedState>) -> Json<BtDevicesResponse> {
    let s = state.lock().unwrap();
    Json(BtDevicesResponse {
        count: s.bt_devices_seen,
        devices: s.bt_device_list.clone(),
    })
}

/// GET /api/bt/captures -> JSON capture counts
async fn bt_captures_handler(State(state): State<SharedState>) -> Json<BtCapturesResponse> {
    let s = state.lock().unwrap();
    Json(BtCapturesResponse {
        keys: s.bt_capture_keys,
        transcripts: s.bt_capture_transcripts,
        crashes: s.bt_capture_crashes,
        vendor: s.bt_capture_vendor,
        total: (s.bt_capture_keys
            + s.bt_capture_transcripts
            + s.bt_capture_crashes
            + s.bt_capture_vendor) as u64,
    })
}

/// GET /api/bt/patchram -> JSON patchram state
async fn bt_patchram_handler(State(state): State<SharedState>) -> Json<BtPatchramResponse> {
    let s = state.lock().unwrap();
    Json(BtPatchramResponse {
        state: s.bt_patchram_state.clone(),
    })
}

// WebSocket handler
// ---------------------------------------------------------------------------

/// GET /ws -> WebSocket upgrade for live state push.
async fn ws_handler(ws: WebSocketUpgrade, State(app): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, app.ws_tx.subscribe()))
}

/// Handle a single WebSocket connection: forward broadcast messages to the client.
async fn handle_ws(mut socket: WebSocket, mut rx: broadcast::Receiver<String>) {
    loop {
        tokio::select! {
            // Server push: broadcast state to client
            result = rx.recv() => {
                match result {
                    Ok(json) => {
                        if socket.send(Message::Text(json)).await.is_err() {
                            break; // client disconnected
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        log::debug!("ws client lagged by {n} messages");
                        // continue — next recv() will get the latest
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            // Client message (ping/pong or close)
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(data))) => {
                        if socket.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    _ => {} // ignore other messages
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------

/// Create a broadcast channel for WebSocket live updates.
/// Returns the sender (for the daemon to broadcast) and a receiver (dropped immediately).
/// The sender is passed to `build_router` and stored by the daemon.
pub fn create_ws_broadcast() -> broadcast::Sender<String> {
    let (tx, _) = broadcast::channel::<String>(16);
    tx
}

/// Build the axum router with all routes, sharing daemon state.
pub fn build_router(state: SharedState, ws_tx: broadcast::Sender<String>) -> Router {
    let app = AppState {
        shared: state,
        ws_tx,
    };
    Router::new()
        .route("/", get(dashboard_handler))
        .route("/ws", get(ws_handler))
        .route(API_STATUS, get(status_handler))
        .route(API_CAPTURES, get(captures_handler))
        .route(API_HEALTH, get(health_handler))
        .route(API_BATTERY, get(battery_handler))
        .route(API_WIFI, get(wifi_handler).post(wifi_update_handler))
        .route(
            API_BLUETOOTH,
            get(bluetooth_handler).post(bluetooth_toggle_handler),
        )
        .route(API_GPU, get(gpu_handler))
        .route(API_QPU, get(qpu_handler))
        .route(API_PERSONALITY, get(personality_handler))
        .route(API_SYSTEM, get(system_handler))
        .route(
            API_ATTACKS,
            get(attacks_get_handler).post(attacks_post_handler),
        )
        .route(API_RECOVERY, get(recovery_handler))
        .route(API_CRACKED, get(cracked_handler))
        .route(API_MODE, post(mode_handler))
        .route(API_RATE, post(rate_handler))
        .route(API_RESTART, post(restart_handler))
        .route(API_SHUTDOWN, post(shutdown_handler))
        .route(API_BUTTON, post(button_handler))
        .route(API_DISPLAY, get(display_handler))
        .route("/api/download/all", get(download_zip_handler))
        .route(
            "/api/plugins",
            get(plugins_get_handler).post(plugins_post_handler),
        )
        .route(API_APS, get(aps_handler))
        .route(API_WHITELIST, get(whitelist_get_handler))
        .route(API_WHITELIST_ADD, post(whitelist_add_handler))
        .route(API_WHITELIST_REMOVE, post(whitelist_remove_handler))
        .route(API_CHANNELS, post(channels_handler))
        .route(API_RAGE, post(rage_handler))
        .route(API_LOGS, get(logs_handler))
        .route(
            API_WPASEC,
            get(wpasec_get_handler).post(wpasec_post_handler),
        )
        .route(
            API_WIGLE,
            get(wigle_get_handler).post(wigle_post_handler),
        )
        .route(
            API_DISCORD,
            get(discord_get_handler).post(discord_post_handler),
        )
        .route(API_DOWNLOAD_SINGLE, get(download_single_handler))
        .route(API_RESTART_PI, post(restart_pi_handler))
        .route(API_RESTART_SSH, post(restart_ssh_handler))
        .route(API_RESTART_PWN, post(restart_pwn_handler))
        .route(API_SETTINGS, post(settings_handler))
        .route(
            API_BT_SCAN,
            get(bt_scan_results_handler).post(bt_scan_handler),
        )
        .route(API_BT_FORGET, post(bt_forget_handler))
        .route(API_BT_DISCONNECT, post(bt_disconnect_handler))
        .route(API_BT_LIST_PAIRED, get(bt_list_paired_handler))
        .route(API_BT_REFRESH_PAIRED, post(bt_refresh_paired_handler))
        .route(API_BT_RESET_PAIRINGS, post(bt_reset_pairings_handler))
        .route(API_RADIO, get(radio_get_handler).post(radio_post_handler))
        .route(API_CAPTURE_ALL, post(capture_all_handler))
        .route(API_DELETE_CAPTURE, delete(delete_capture_handler))
        .route(API_BT_ATTACKS, get(bt_attacks_get_handler))
        .route(API_BT_ATTACKS_TOGGLE, post(bt_attacks_toggle_handler))
        .route(API_BT_ATTACKS_RAGE, post(bt_attacks_rage_handler))
        .route(API_BT_SCAN_MODE, post(bt_scan_mode_handler))
        .route(API_BT_ATTACKS_MANUAL, post(bt_manual_attack_handler))
        .route(API_BT_DEVICES, get(bt_devices_handler))
        .route(API_BT_CAPTURES, get(bt_captures_handler))
        .route(API_BT_PATCHRAM, get(bt_patchram_handler))
        .route(API_INTERACT, get(interact_status_handler).post(interact_handler))
        .route(
            API_FACE_PACKS,
            get(face_packs_get_handler).post(face_packs_post_handler),
        )
        .with_state(app)
}

/// Start the axum web server on 0.0.0.0:8080.
/// This function is async and should be spawned as a tokio task.
pub async fn start_server(state: SharedState, ws_tx: broadcast::Sender<String>) {
    let app = build_router(state, ws_tx);
    let listener = match tokio::net::TcpListener::bind("0.0.0.0:8080").await {
        Ok(l) => l,
        Err(e) => {
            log::error!("failed to bind web server on 0.0.0.0:8080: {e}");
            return;
        }
    };
    log::info!("web dashboard listening on http://0.0.0.0:8080");
    if let Err(e) = axum::serve(listener, app).await {
        log::error!("web server error: {e}");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// Helper: create a SharedState with test defaults.
    fn test_state() -> SharedState {
        Arc::new(Mutex::new(DaemonState::new("testbot")))
    }

    /// Helper: build the router with test state.
    fn test_router() -> (Router, SharedState) {
        let state = test_state();
        let ws_tx = create_ws_broadcast();
        let router = build_router(state.clone(), ws_tx);
        (router, state)
    }

    /// Helper: make a GET request and return (status, body_string).
    async fn get(router: &Router, path: &str) -> (u16, String) {
        let req = axum::http::Request::builder()
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status().as_u16();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).to_string())
    }

    /// Helper: make a POST request with JSON body and return (status, body_string).
    async fn post_json(router: &Router, path: &str, json: &str) -> (u16, String) {
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(json.to_string()))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status().as_u16();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).to_string())
    }

    /// Helper: make a POST request with an explicit content type.
    async fn post_with_content_type(
        router: &Router,
        path: &str,
        content_type: &str,
        body: &str,
    ) -> (u16, String) {
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", content_type)
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status().as_u16();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).to_string())
    }

    // === Serialization tests (keep existing ones) ===

    #[test]
    fn test_build_status() {
        let status = build_status(&StatusParams {
            name: "oxi",
            uptime: "00:01:23",
            epoch: 42,
            channel: 6,
            aps_seen: 10,
            handshakes: 3,
            blind_epochs: 2,
            mood: 0.75,
            face: "(^_^)",
            status_message: "Having fun!",
            mode: "AO",
            display_invert: true,
            display_rotation: 180,
            min_rssi: -100,
            ap_ttl_secs: 120,
            display_refresh_interval: 100,
        });
        assert_eq!(status.name, "oxi");
        assert_eq!(status.epoch, 42);
        assert_eq!(status.channel, 6);
        assert_eq!(status.handshakes, 3);
        assert!(!status.version.is_empty());
    }

    #[test]
    fn test_status_serializes() {
        let status = build_status(&StatusParams {
            name: "oxi",
            uptime: "00:00:00",
            epoch: 0,
            channel: 1,
            aps_seen: 0,
            handshakes: 0,
            blind_epochs: 0,
            mood: 0.5,
            face: "(O_O)",
            status_message: "Booting",
            mode: "AO",
            display_invert: true,
            display_rotation: 180,
            min_rssi: -100,
            ap_ttl_secs: 120,
            display_refresh_interval: 100,
        });
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"name\":\"oxi\""));
        assert!(json.contains("\"epoch\":0"));
    }

    #[test]
    fn test_api_paths() {
        assert_eq!(API_STATUS, "/api/status");
        assert_eq!(API_ATTACKS, "/api/attacks");
        assert_eq!(API_CAPTURES, "/api/captures");
        assert_eq!(API_CONFIG, "/api/config");
        assert_eq!(API_DISPLAY, "/api/display.png");
        assert_eq!(API_BATTERY, "/api/battery");
        assert_eq!(API_WIFI, "/api/wifi");
        assert_eq!(API_BLUETOOTH, "/api/bluetooth");
        assert_eq!(API_RECOVERY, "/api/recovery");
        assert_eq!(API_PERSONALITY, "/api/personality");
        assert_eq!(API_SYSTEM, "/api/system");
        assert_eq!(API_HANDSHAKES, "/api/handshakes");
        assert_eq!(API_HANDSHAKE_DL, "/api/handshakes/:filename");
        assert_eq!(API_MODE, "/api/mode");
        assert_eq!(API_RESTART, "/api/restart");
        assert_eq!(API_SHUTDOWN, "/api/shutdown");
        assert_eq!(API_WHITELIST, "/api/whitelist");
        assert_eq!(API_CRACKED, "/api/cracked");
        assert_eq!(API_HEALTH, "/api/health");
        assert_eq!(API_RATE, "/api/rate");
        assert_eq!(API_APS, "/api/aps");
        assert_eq!(API_WHITELIST_ADD, "/api/whitelist/add");
        assert_eq!(API_WHITELIST_REMOVE, "/api/whitelist/remove");
        assert_eq!(API_CHANNELS, "/api/channels");
        assert_eq!(API_LOGS, "/api/logs");
        assert_eq!(API_WPASEC, "/api/wpasec");
        assert_eq!(API_DISCORD, "/api/discord");
        assert_eq!(API_DOWNLOAD_SINGLE, "/api/download/:filename");
        assert_eq!(API_RESTART_PI, "/api/restart-pi");
        assert_eq!(API_RESTART_SSH, "/api/restart-ssh");
    }

    #[test]
    fn test_battery_info_serialize() {
        let info = BatteryInfo {
            level: 75,
            charging: true,
            voltage_mv: 4100,
            low: false,
            critical: false,
            available: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"level\":75"));
        assert!(json.contains("\"charging\":true"));
        assert!(json.contains("\"available\":true"));
    }

    #[test]
    fn test_wifi_info_serialize() {
        let info = WifiInfo {
            state: "Monitor".into(),
            channel: 6,
            aps_tracked: 15,
            channels: vec![1, 6, 11],
            dwell_ms: 250,
            autohunt_enabled: true,
            skip_captured: true,
            rage_level: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"state\":\"Monitor\""));
        assert!(json.contains("\"aps_tracked\":15"));
        assert!(json.contains("\"skip_captured\":true"));
    }

    #[test]
    fn test_bluetooth_info_serialize() {
        let info = BluetoothInfo {
            connected: true,
            state: "Connected".into(),
            device_name: "Phone".into(),
            ip: "10.0.0.1".into(),
            internet_available: true,
            retry_count: 0,
            feature_mode: "tether".into(),
            nearby_devices: 0,
            contention_score: 0,
            passkey: None,
            passkey_device: String::new(),
            pair_in_progress: false,
            last_error_hint: String::new(),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"connected\":true"));
        assert!(json.contains("\"device_name\":\"Phone\""));
    }

    #[test]
    fn test_personality_info_serialize() {
        let info = PersonalityInfo {
            mood: 0.75,
            face: "(^_^)".into(),
            blind_epochs: 2,
            total_handshakes: 10,
            total_aps_seen: 50,
            xp: 420,
            level: 3,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"level\":3"));
        assert!(json.contains("\"xp\":420"));
    }

    #[test]
    fn test_system_info_serialize() {
        let info = SystemInfoResponse {
            cpu_temp_c: 45.2,
            mem_used_mb: 200,
            mem_total_mb: 512,
            disk_used_mb: 3000,
            disk_total_mb: 16000,
            cpu_percent: 35.0,
            uptime_secs: 7200,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"cpu_temp_c\":45.2"));
        assert!(json.contains("\"disk_used_mb\":3000"));
        assert!(json.contains("\"uptime_secs\":7200"));
    }

    #[test]
    fn test_attack_stats_serialize() {
        let stats = AttackStats {
            total_attacks: 100,
            total_handshakes: 5,
            attack_rate: 1,
            deauths_this_epoch: 3,
            deauth: true,
            pmkid: true,
            csa: false,
            disassoc: true,
            anon_reassoc: true,
            rogue_m2: false,
        };
        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("\"total_attacks\":100"));
        assert!(json.contains("\"deauth\":true"));
        assert!(json.contains("\"csa\":false"));
    }

    #[test]
    fn test_attack_toggle_deserialize() {
        let json = r#"{"deauth": false, "pmkid": true}"#;
        let toggle: AttackToggle = serde_json::from_str(json).unwrap();
        assert_eq!(toggle.deauth, Some(false));
        assert_eq!(toggle.pmkid, Some(true));
        assert_eq!(toggle.csa, None);
    }

    #[test]
    fn test_cracked_entry_serialize() {
        let entry = CrackedEntry {
            ssid: "MyWifi".into(),
            bssid: "AA:BB:CC:DD:EE:FF".into(),
            password: "hunter2".into(),
            date: "2026-01-01".into(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"ssid\":\"MyWifi\""));
        assert!(json.contains("\"password\":\"hunter2\""));
    }

    #[test]
    fn test_recovery_info_serialize() {
        let info = RecoveryInfo {
            state: "Healthy".into(),
            total_recoveries: 2,
            soft_retries: 1,
            hard_retries: 1,
            last_recovery: "5m ago".into(),
            diagnostic_count: 3,
            fw_crash_suppress: 0,
            fw_hardfault: 0,
            fw_health: "Unknown".into(),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"state\":\"Healthy\""));
        assert!(json.contains("\"total_recoveries\":2"));
        assert!(json.contains("\"last_recovery\":\"5m ago\""));
    }

    #[test]
    fn test_mode_switch_deserialize() {
        let json = r#"{"mode": "MANU"}"#;
        let ms: ModeSwitch = serde_json::from_str(json).unwrap();
        assert_eq!(ms.mode, "MANU");
    }

    #[test]
    fn test_config_update_deserialize() {
        let json = r#"{"name": "mybot", "attack_rate": 1}"#;
        let update: ConfigUpdate = serde_json::from_str(json).unwrap();
        assert_eq!(update.name.unwrap(), "mybot");
        assert_eq!(update.attack_rate.unwrap(), 1);
        assert!(update.whitelist_add.is_none());
    }

    #[test]
    fn test_capture_info_serialize() {
        let info = CaptureInfo {
            total_files: 10,
            handshake_files: 3,
            pending_upload: 2,
            total_size_bytes: 1024000,
            session_captures: 5,
            session_handshakes: 2,
            capture_all: false,
            files: vec![],
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"handshake_files\":3"));
    }

    #[test]
    fn test_health_response_serialize() {
        let health = HealthResponse {
            wifi_state: "Monitor".into(),
            battery_level: 80,
            battery_charging: false,
            battery_available: true,
            uptime_secs: 3600,
            ao_state: "RUNNING".into(),
            ao_pid: 1234,
            ao_crash_count: 0,
            ao_uptime: "01:00:00".into(),
            gpsd_available: true,
        };
        let json = serde_json::to_string(&health).unwrap();
        assert!(json.contains("\"ao_pid\":1234"));
    }

    #[test]
    fn test_rate_change_deserialize() {
        let json = r#"{"rate": 2}"#;
        let rc: RateChange = serde_json::from_str(json).unwrap();
        assert_eq!(rc.rate, 2);
    }

    #[test]
    fn test_action_response_serialize() {
        let resp = ActionResponse {
            ok: true,
            message: "done".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"ok\":true"));
    }

    #[test]
    fn test_daemon_state_new() {
        let ds = DaemonState::new("testbot");
        assert_eq!(ds.name, "testbot");
        assert_eq!(ds.mode, "AO");
        assert_eq!(ds.epoch, 0);
        assert!(!ds.pending_restart);
        assert!(!ds.pending_shutdown);
        assert!(ds.attack_deauth);
        assert!(ds.attack_pmkid);
        assert!(ds.attack_csa);
        assert!(ds.attack_disassoc);
        assert!(ds.attack_anon_reassoc);
        assert!(ds.attack_rogue_m2);
        assert_eq!(ds.xp, 0);
        assert_eq!(ds.level, 1);
        assert!(ds.cracked.is_empty());
        assert_eq!(ds.bt_state, "BT DISC");
        assert!(!ds.bt_connected);
        assert!(ds.wpasec_api_key.is_empty());
        assert!(ds.pending_wpasec_key.is_none());
        assert!(ds.discord_webhook_url.is_empty());
        assert!(!ds.discord_enabled);
        assert!(ds.pending_discord_config.is_none());
    }

    #[test]
    fn test_build_router_compiles() {
        let state = test_state();
        let ws_tx = create_ws_broadcast();
        let _router = build_router(state, ws_tx);
    }

    // === Dashboard HTML tests ===

    #[test]
    fn test_dashboard_html_contains_all_cards() {
        assert!(DASHBOARD_HTML.contains("<title>oxigotchi</title>"));
        // face card removed — e-ink preview replaces it
        assert!(
            DASHBOARD_HTML.contains("card-stats"),
            "missing core stats card"
        );
        assert!(DASHBOARD_HTML.contains("card-eink"), "missing e-ink card");
        assert!(
            DASHBOARD_HTML.contains("card-battery"),
            "missing battery card"
        );
        assert!(DASHBOARD_HTML.contains("card-bt"), "missing bluetooth card");
        assert!(DASHBOARD_HTML.contains("card-rf"), "missing RF card");
        assert!(DASHBOARD_HTML.contains("card-wifi"), "missing wifi card");
        assert!(
            DASHBOARD_HTML.contains("card-attacks"),
            "missing attacks card"
        );
        assert!(
            DASHBOARD_HTML.contains("card-captures"),
            "missing captures card"
        );
        assert!(
            DASHBOARD_HTML.contains("card-recovery"),
            "missing recovery card"
        );
        assert!(
            DASHBOARD_HTML.contains("card-personality"),
            "missing personality card"
        );
        assert!(
            DASHBOARD_HTML.contains("card-system"),
            "missing system card"
        );
        assert!(
            DASHBOARD_HTML.contains("card-cracked"),
            "missing cracked card"
        );
        // download card merged into captures card
        assert!(DASHBOARD_HTML.contains("card-mode"), "missing mode card");
        assert!(
            DASHBOARD_HTML.contains("card-actions"),
            "missing actions card"
        );
        assert!(
            DASHBOARD_HTML.contains("card-plugins"),
            "missing plugins card"
        );
        assert!(DASHBOARD_HTML.contains("card-aps"), "missing APs card");
        assert!(
            DASHBOARD_HTML.contains("card-whitelist"),
            "missing whitelist card"
        );
        // card-channels merged into card-attacks (dwell + channel buttons + autohunt now live there)
        assert!(DASHBOARD_HTML.contains("card-logs"), "missing logs card");
        assert!(
            DASHBOARD_HTML.contains("card-wpasec"),
            "missing wpasec card"
        );
        assert!(
            DASHBOARD_HTML.contains("card-discord"),
            "missing discord card"
        );
        assert!(
            DASHBOARD_HTML.contains("card-settings"),
            "missing settings card"
        );
    }

    #[test]
    fn test_dashboard_html_has_all_api_calls() {
        assert!(
            DASHBOARD_HTML.contains("/api/status"),
            "missing /api/status"
        );
        assert!(
            DASHBOARD_HTML.contains("/api/battery"),
            "missing /api/battery"
        );
        assert!(
            DASHBOARD_HTML.contains("/api/bluetooth"),
            "missing /api/bluetooth"
        );
        assert!(DASHBOARD_HTML.contains("/api/qpu"), "missing /api/qpu");
        assert!(DASHBOARD_HTML.contains("/api/wifi"), "missing /api/wifi");
        assert!(
            DASHBOARD_HTML.contains("/api/attacks"),
            "missing /api/attacks"
        );
        assert!(
            DASHBOARD_HTML.contains("/api/captures"),
            "missing /api/captures"
        );
        assert!(
            DASHBOARD_HTML.contains("/api/recovery"),
            "missing /api/recovery"
        );
        assert!(
            DASHBOARD_HTML.contains("/api/personality"),
            "missing /api/personality"
        );
        assert!(
            DASHBOARD_HTML.contains("/api/system"),
            "missing /api/system"
        );
        assert!(
            DASHBOARD_HTML.contains("/api/cracked"),
            "missing /api/cracked"
        );
        assert!(
            DASHBOARD_HTML.contains("/api/health"),
            "missing /api/health"
        );
        assert!(DASHBOARD_HTML.contains("/api/mode"), "missing /api/mode");
        assert!(DASHBOARD_HTML.contains("/api/rate"), "missing /api/rate");
        assert!(
            DASHBOARD_HTML.contains("/api/restart"),
            "missing /api/restart"
        );
        assert!(
            DASHBOARD_HTML.contains("/api/shutdown"),
            "missing /api/shutdown"
        );
        assert!(
            DASHBOARD_HTML.contains("/api/plugins"),
            "missing /api/plugins"
        );
        assert!(DASHBOARD_HTML.contains("/api/aps"), "missing /api/aps");
        assert!(
            DASHBOARD_HTML.contains("/api/whitelist"),
            "missing /api/whitelist"
        );
        assert!(
            DASHBOARD_HTML.contains("/api/channels"),
            "missing /api/channels"
        );
        assert!(DASHBOARD_HTML.contains("/api/logs"), "missing /api/logs");
        assert!(
            DASHBOARD_HTML.contains("/api/wpasec"),
            "missing /api/wpasec"
        );
        assert!(
            DASHBOARD_HTML.contains("/api/discord"),
            "missing /api/discord"
        );
        assert!(
            DASHBOARD_HTML.contains("/api/restart-pi"),
            "missing /api/restart-pi"
        );
        assert!(
            DASHBOARD_HTML.contains("/api/restart-ssh"),
            "missing /api/restart-ssh"
        );
        assert!(
            DASHBOARD_HTML.contains("/api/download/"),
            "missing /api/download"
        );
        assert!(DASHBOARD_HTML.contains("/api/rage"), "missing /api/rage");
    }

    #[test]
    fn test_dashboard_html_has_attack_toggles() {
        assert!(DASHBOARD_HTML.contains("atk-deauth"));
        assert!(DASHBOARD_HTML.contains("atk-pmkid"));
        assert!(DASHBOARD_HTML.contains("atk-csa"));
        assert!(DASHBOARD_HTML.contains("atk-disassoc"));
        assert!(DASHBOARD_HTML.contains("atk-anon_reassoc"));
        assert!(DASHBOARD_HTML.contains("atk-rogue_m2"));
        assert!(DASHBOARD_HTML.contains("toggleAttack"));
    }

    #[test]
    fn test_dashboard_html_has_rate_buttons() {
        assert!(DASHBOARD_HTML.contains("rate-1"));
        assert!(DASHBOARD_HTML.contains("rate-2"));
        assert!(DASHBOARD_HTML.contains("rate-3"));
        assert!(DASHBOARD_HTML.contains("setRate"));
    }

    #[test]
    fn test_dashboard_html_dark_theme() {
        assert!(
            DASHBOARD_HTML.contains("#1a1a2e"),
            "missing background color"
        );
        assert!(DASHBOARD_HTML.contains("#00d4aa"), "missing accent color");
        assert!(
            DASHBOARD_HTML.contains("#16213e"),
            "missing card background"
        );
    }

    #[test]
    fn test_dashboard_html_auto_refresh() {
        assert!(DASHBOARD_HTML.contains("setInterval(refreshStatus, 5000)"));
        assert!(DASHBOARD_HTML.contains("setInterval(refreshBattery, 15000)"));
        assert!(DASHBOARD_HTML.contains("setInterval(refreshWifi, 5000)"));
    }

    // === HTTP endpoint integration tests ===

    #[tokio::test]
    async fn test_get_dashboard_returns_html() {
        let (router, _) = test_router();
        let (status, body) = get(&router, "/").await;
        assert_eq!(status, 200);
        assert!(body.contains("<!DOCTYPE html>"));
        assert!(body.contains("<title>oxigotchi</title>"));
    }

    #[tokio::test]
    async fn test_get_status_json() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.epoch = 42;
            s.channel = 6;
            s.face = "(^_^)".into();
        }
        let (status, body) = get(&router, "/api/status").await;
        assert_eq!(status, 200);
        let resp: StatusResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(resp.name, "testbot");
        assert_eq!(resp.epoch, 42);
        assert_eq!(resp.channel, 6);
        assert_eq!(resp.face, "(^_^)");
    }

    #[tokio::test]
    async fn test_get_battery_json() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.battery_level = 73;
            s.battery_charging = true;
            s.battery_available = true;
            s.battery_voltage_mv = 4050;
        }
        let (status, body) = get(&router, "/api/battery").await;
        assert_eq!(status, 200);
        let resp: BatteryInfo = serde_json::from_str(&body).unwrap();
        assert_eq!(resp.level, 73);
        assert!(resp.charging);
        assert!(resp.available);
        assert_eq!(resp.voltage_mv, 4050);
    }

    #[tokio::test]
    async fn test_get_wifi_json() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.wifi_state = "Monitor".into();
            s.channel = 11;
            s.wifi_aps_tracked = 25;
            s.wifi_channels = vec![1, 6, 11];
            s.wifi_dwell_ms = 2000;
            s.skip_captured = true;
        }
        let (status, body) = get(&router, "/api/wifi").await;
        assert_eq!(status, 200);
        let resp: WifiInfo = serde_json::from_str(&body).unwrap();
        assert_eq!(resp.state, "Monitor");
        assert_eq!(resp.channel, 11);
        assert_eq!(resp.aps_tracked, 25);
        assert_eq!(resp.channels, vec![1, 6, 11]);
        assert_eq!(resp.dwell_ms, 2000);
        assert!(resp.skip_captured);
    }

    #[tokio::test]
    async fn test_get_bluetooth_json() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.bt_connected = true;
            s.bt_state = "Connected".into();
            s.bt_device_name = "Pixel 7".into();
            s.bt_ip = "10.0.0.2".into();
        }
        let (status, body) = get(&router, "/api/bluetooth").await;
        assert_eq!(status, 200);
        let resp: BluetoothInfo = serde_json::from_str(&body).unwrap();
        assert!(resp.connected);
        assert_eq!(resp.device_name, "Pixel 7");
        assert_eq!(resp.ip, "10.0.0.2");
    }

    #[tokio::test]
    async fn test_get_gpu_json() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.gpu_mode = "Observe".into();
            s.gpu_signal = "RenderSetupActive".into();
            s.gpu_submit_seen = true;
        }
        let (status, body) = get(&router, "/api/gpu").await;
        assert_eq!(status, 200);
        let resp: GpuInfo = serde_json::from_str(&body).unwrap();
        assert_eq!(resp.mode, "Observe");
        assert_eq!(resp.signal, "RenderSetupActive");
        assert!(resp.submit_seen);
        assert_eq!(resp.snapshot_policy, "flush_immediate");
        assert_eq!(resp.flush_threshold, 1);
    }

    #[tokio::test]
    async fn test_get_personality_json() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.mood = 0.85;
            s.face = "(^_^)".into();
            s.xp = 420;
            s.level = 3;
            s.blind_epochs = 2;
            s.handshakes = 10;
            s.aps_seen = 50;
        }
        let (status, body) = get(&router, "/api/personality").await;
        assert_eq!(status, 200);
        let resp: PersonalityInfo = serde_json::from_str(&body).unwrap();
        assert_eq!(resp.mood, 0.85);
        assert_eq!(resp.xp, 420);
        assert_eq!(resp.level, 3);
        assert_eq!(resp.total_handshakes, 10);
        assert_eq!(resp.total_aps_seen, 50);
    }

    #[tokio::test]
    async fn test_get_system_json() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.cpu_temp_c = 42.5;
            s.mem_used_mb = 200;
            s.mem_total_mb = 512;
            s.disk_used_mb = 3000;
            s.disk_total_mb = 16000;
        }
        let (status, body) = get(&router, "/api/system").await;
        assert_eq!(status, 200);
        let resp: SystemInfoResponse = serde_json::from_str(&body).unwrap();
        // On non-Linux, the live reads return 0, so fallback values are used
        assert!(resp.uptime_secs < 5); // just-created state
    }

    #[tokio::test]
    async fn test_get_attacks_json() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.total_attacks = 100;
            s.attack_deauth = true;
            s.attack_csa = false;
        }
        let (status, body) = get(&router, "/api/attacks").await;
        assert_eq!(status, 200);
        let resp: AttackStats = serde_json::from_str(&body).unwrap();
        assert_eq!(resp.total_attacks, 100);
        assert!(resp.deauth);
        assert!(!resp.csa);
    }

    #[tokio::test]
    async fn test_post_attacks_toggle() {
        let (router, state) = test_router();
        let (status, body) =
            post_json(&router, "/api/attacks", r#"{"deauth": false, "csa": true}"#).await;
        assert_eq!(status, 200);
        let resp: ActionResponse = serde_json::from_str(&body).unwrap();
        assert!(resp.ok);
        let s = state.lock().unwrap();
        assert!(!s.attack_deauth);
        assert!(s.attack_csa);
        let toggle = s.pending_attack_toggle.as_ref().expect("toggle should be queued");
        assert_eq!(toggle.deauth, Some(false));
        assert_eq!(toggle.csa, Some(true));
    }

    #[tokio::test]
    async fn test_get_captures_json() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.capture_files = 5;
            s.handshake_files = 2;
            s.capture_list = vec![CaptureEntry {
                filename: "test.pcapng".into(),
                size_bytes: 1024,
                ssid: String::new(),
                bssid_mac: String::new(),
                captured_date: String::new(),
                has_handshake: false,
            }];
        }
        let (status, body) = get(&router, "/api/captures").await;
        assert_eq!(status, 200);
        let resp: CaptureInfo = serde_json::from_str(&body).unwrap();
        assert_eq!(resp.total_files, 5);
        assert_eq!(resp.handshake_files, 2);
        assert_eq!(resp.files.len(), 1);
        assert_eq!(resp.files[0].filename, "test.pcapng");
    }

    #[tokio::test]
    async fn test_get_health_json() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.wifi_state = "Monitor".into();
            s.ao_state = "RUNNING".into();
            s.ao_pid = 1234;
        }
        let (status, body) = get(&router, "/api/health").await;
        assert_eq!(status, 200);
        let resp: HealthResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(resp.wifi_state, "Monitor");
        assert_eq!(resp.ao_state, "RUNNING");
        assert_eq!(resp.ao_pid, 1234);
    }

    #[tokio::test]
    async fn test_get_recovery_json() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.recovery_state = "Recovering".into();
            s.recovery_total = 3;
            s.recovery_last_str = "2m ago".into();
        }
        let (status, body) = get(&router, "/api/recovery").await;
        assert_eq!(status, 200);
        let resp: RecoveryInfo = serde_json::from_str(&body).unwrap();
        assert_eq!(resp.state, "Recovering");
        assert_eq!(resp.total_recoveries, 3);
        assert_eq!(resp.last_recovery, "2m ago");
    }

    #[tokio::test]
    async fn test_get_cracked_empty() {
        let (router, _) = test_router();
        let (status, body) = get(&router, "/api/cracked").await;
        assert_eq!(status, 200);
        let resp: Vec<CrackedEntry> = serde_json::from_str(&body).unwrap();
        assert!(resp.is_empty());
    }

    #[tokio::test]
    async fn test_get_cracked_with_entries() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.cracked.push(CrackedEntry {
                ssid: "MyWifi".into(),
                bssid: "AA:BB:CC:DD:EE:FF".into(),
                password: "hunter2".into(),
                date: "2026-01-01".into(),
            });
        }
        let (status, body) = get(&router, "/api/cracked").await;
        assert_eq!(status, 200);
        let resp: Vec<CrackedEntry> = serde_json::from_str(&body).unwrap();
        assert_eq!(resp.len(), 1);
        assert_eq!(resp[0].ssid, "MyWifi");
        assert_eq!(resp[0].password, "hunter2");
    }

    #[tokio::test]
    async fn test_post_mode_toggle() {
        let (router, state) = test_router();
        let (status, body) = post_json(&router, "/api/mode", r#"{"mode": "toggle"}"#).await;
        assert_eq!(status, 200);
        let resp: ActionResponse = serde_json::from_str(&body).unwrap();
        assert!(resp.ok);
        assert!(resp.message.contains("TOGGLE")); // toggle passed through to daemon
        let s = state.lock().unwrap();
        assert_eq!(s.pending_mode_switch.as_deref(), Some("TOGGLE"));
    }

    #[tokio::test]
    async fn test_post_mode_explicit() {
        let (router, state) = test_router();
        let (status, _) = post_json(&router, "/api/mode", r#"{"mode": "pwn"}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(s.pending_mode_switch.as_deref(), Some("PWN"));
    }

    #[tokio::test]
    async fn test_post_rate_clamps() {
        let (router, state) = test_router();
        // Rate 5 should clamp to 3
        let (status, body) = post_json(&router, "/api/rate", r#"{"rate": 5}"#).await;
        assert_eq!(status, 200);
        let resp: ActionResponse = serde_json::from_str(&body).unwrap();
        assert!(resp.ok);
        assert!(resp.message.contains("3"));
        let s = state.lock().unwrap();
        assert_eq!(s.pending_rate_change, Some(3));
    }

    #[tokio::test]
    async fn test_post_rate_valid() {
        let (router, state) = test_router();
        let (status, _) = post_json(&router, "/api/rate", r#"{"rate": 2}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(s.pending_rate_change, Some(2));
    }

    #[tokio::test]
    async fn test_post_restart() {
        let (router, state) = test_router();
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/restart")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let s = state.lock().unwrap();
        assert!(s.pending_restart);
    }

    #[tokio::test]
    async fn test_post_shutdown() {
        let (router, state) = test_router();
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/shutdown")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let action: ActionResponse = serde_json::from_slice(&body).unwrap();
        assert!(action.ok);
        assert!(action.message.contains("shutdown"));
        let s = state.lock().unwrap();
        assert!(s.pending_shutdown);
    }

    #[tokio::test]
    async fn test_post_capture_all_queues_and_optimistic() {
        let (router, state) = test_router();
        let (status, body) = post_json(&router, "/api/capture-all", r#"{"enabled":true}"#).await;
        assert_eq!(status, 200);
        let resp: ActionResponse = serde_json::from_str(&body).unwrap();
        assert!(resp.ok);
        let s = state.lock().unwrap();
        assert_eq!(s.pending_capture_all, Some(true));
        assert!(s.capture_all, "capture_all should be set optimistically");
    }

    #[tokio::test]
    async fn test_post_capture_all_disable() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.capture_all = true;
        }
        let (status, _) = post_json(&router, "/api/capture-all", r#"{"enabled":false}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(s.pending_capture_all, Some(false));
        assert!(!s.capture_all);
    }

    #[tokio::test]
    async fn test_post_bluetooth_toggle() {
        let (router, state) = test_router();
        let (status, body) = post_json(&router, "/api/bluetooth", r#"{"visible": true}"#).await;
        assert_eq!(status, 200);
        let resp: ActionResponse = serde_json::from_str(&body).unwrap();
        assert!(resp.ok);
        let s = state.lock().unwrap();
        assert_eq!(s.pending_bt_toggle, Some(true));
    }

    #[tokio::test]
    async fn test_404_unknown_route() {
        let (router, _) = test_router();
        let (status, _) = get(&router, "/api/nonexistent").await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn test_all_get_endpoints_200() {
        let (router, _) = test_router();
        let endpoints = [
            "/",
            "/api/status",
            "/api/captures",
            "/api/health",
            "/api/battery",
            "/api/wifi",
            "/api/bluetooth",
            "/api/gpu",
            "/api/personality",
            "/api/system",
            "/api/attacks",
            "/api/recovery",
            "/api/cracked",
            "/api/plugins",
            "/api/aps",
            "/api/whitelist",
            "/api/logs",
        ];
        for endpoint in endpoints {
            let (status, _) = get(&router, endpoint).await;
            assert_eq!(status, 200, "GET {} returned {}", endpoint, status);
        }
    }

    #[tokio::test]
    async fn test_state_independence() {
        // Two separate routers should have independent state
        let (router1, state1) = test_router();
        let (router2, _state2) = test_router();
        {
            let mut s = state1.lock().unwrap();
            s.epoch = 999;
        }
        let (_, body1) = get(&router1, "/api/status").await;
        let (_, body2) = get(&router2, "/api/status").await;
        let resp1: StatusResponse = serde_json::from_str(&body1).unwrap();
        let resp2: StatusResponse = serde_json::from_str(&body2).unwrap();
        assert_eq!(resp1.epoch, 999);
        assert_eq!(resp2.epoch, 0);
    }

    #[tokio::test]
    async fn test_download_zip_endpoint_exists() {
        let state = test_state();
        let ws_tx = create_ws_broadcast();
        let router = build_router(state, ws_tx);
        let (status, _body) = get(&router, "/api/download/all").await;
        // get() returns (u16, String); 200 = OK with empty zip for nonexistent capture dir
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn test_plugins_get_empty() {
        let (router, _state) = test_router();
        let (status, body) = get(&router, "/api/plugins").await;
        assert_eq!(status, 200);
        let plugins: Vec<PluginInfo> = serde_json::from_str(&body).unwrap();
        assert!(plugins.is_empty());
    }

    #[tokio::test]
    async fn test_plugins_post_queues_update() {
        let (router, state) = test_router();
        let (status, _body) = post_json(
            &router,
            "/api/plugins",
            r#"[{"name":"uptime","x":100,"y":50}]"#,
        )
        .await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(s.pending_plugin_updates.len(), 1);
        assert_eq!(s.pending_plugin_updates[0].name, "uptime");
    }

    #[tokio::test]
    async fn test_post_rage_sets_level() {
        let (router, state) = test_router();
        let (status, body) = post_json(&router, "/api/rage", r#"{"level": 2}"#).await;
        assert_eq!(status, 200);
        let resp: ActionResponse = serde_json::from_str(&body).unwrap();
        assert!(resp.ok);
        assert!(resp.message.contains("2"));
        let s = state.lock().unwrap();
        assert_eq!(s.pending_rage_change, Some(Some(2)));
    }

    #[tokio::test]
    async fn test_post_rage_null_clears() {
        let (router, state) = test_router();
        let (status, body) = post_json(&router, "/api/rage", r#"{"level": null}"#).await;
        assert_eq!(status, 200);
        let resp: ActionResponse = serde_json::from_str(&body).unwrap();
        assert!(resp.ok);
        let s = state.lock().unwrap();
        assert_eq!(s.pending_rage_change, Some(None));
    }

    #[tokio::test]
    async fn test_post_rage_clamps_to_7() {
        let (router, state) = test_router();
        let (status, _) = post_json(&router, "/api/rage", r#"{"level": 10}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(s.pending_rage_change, Some(Some(7)));
    }

    #[tokio::test]
    async fn test_post_rage_clamps_to_1() {
        let (router, state) = test_router();
        let (status, _) = post_json(&router, "/api/rage", r#"{"level": 0}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(s.pending_rage_change, Some(Some(1)));
    }

    #[tokio::test]
    async fn test_wifi_info_includes_rage_level() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.rage_enabled = true;
            s.rage_level = 3;
        }
        let (status, body) = get(&router, "/api/wifi").await;
        assert_eq!(status, 200);
        let info: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(info["rage_level"], 3);
    }

    #[tokio::test]
    async fn test_wifi_info_rage_null_when_custom() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.rage_enabled = false;
        }
        let (status, body) = get(&router, "/api/wifi").await;
        assert_eq!(status, 200);
        let info: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(info["rage_level"].is_null());
    }

    #[tokio::test]
    async fn test_rate_change_breaks_out_of_rage() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.rage_enabled = true;
            s.rage_level = 3;
        }
        let (status, _) = post_json(&router, "/api/rate", r#"{"rate":2}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(
            s.pending_rage_change,
            Some(None),
            "rate change should break out of RAGE"
        );
        assert_eq!(s.pending_rate_change, Some(2));
    }

    #[tokio::test]
    async fn test_channels_change_breaks_out_of_rage() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.rage_enabled = true;
            s.rage_level = 3;
        }
        let (status, _) = post_json(
            &router,
            "/api/channels",
            r#"{"channels":[1,6,11],"dwell_ms":2000,"autohunt":false}"#,
        )
        .await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(
            s.pending_rage_change,
            Some(None),
            "channel change should break out of RAGE"
        );
    }

    // ---- Autohunt toggle tests ----

    #[tokio::test]
    async fn test_autohunt_toggle_on_queues_config() {
        let (router, state) = test_router();
        let (status, body) = post_json(&router, "/api/channels", r#"{"autohunt":true}"#).await;
        assert_eq!(status, 200);
        let resp: ActionResponse = serde_json::from_str(&body).unwrap();
        assert!(resp.ok);
        let s = state.lock().unwrap();
        let cfg = s
            .pending_channel_config
            .as_ref()
            .expect("config should be queued");
        assert_eq!(cfg.autohunt, Some(true));
    }

    #[tokio::test]
    async fn test_autohunt_toggle_off_queues_config_with_channels() {
        let (router, state) = test_router();
        let (status, _) = post_json(
            &router,
            "/api/channels",
            r#"{"channels":[1,6,11],"dwell_ms":2000,"autohunt":false}"#,
        )
        .await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        let cfg = s
            .pending_channel_config
            .as_ref()
            .expect("config should be queued");
        assert_eq!(cfg.autohunt, Some(false));
        assert_eq!(cfg.channels, Some(vec![1, 6, 11]));
        assert_eq!(cfg.dwell_ms, Some(2000));
    }

    #[tokio::test]
    async fn test_autohunt_toggle_on_breaks_rage() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.rage_enabled = true;
            s.rage_level = 3;
        }
        let (status, _) = post_json(&router, "/api/channels", r#"{"autohunt":true}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(
            s.pending_rage_change,
            Some(None),
            "autohunt toggle should break out of RAGE"
        );
    }

    #[tokio::test]
    async fn test_autohunt_only_no_channels_no_dwell() {
        let (router, state) = test_router();
        let (status, _) = post_json(&router, "/api/channels", r#"{"autohunt":true}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        let cfg = s.pending_channel_config.as_ref().unwrap();
        assert_eq!(
            cfg.channels, None,
            "channels should be None when only toggling autohunt"
        );
        assert_eq!(
            cfg.dwell_ms, None,
            "dwell should be None when only toggling autohunt"
        );
        assert_eq!(cfg.autohunt, Some(true));
    }

    #[tokio::test]
    async fn test_autohunt_missing_defaults_to_none() {
        let (router, state) = test_router();
        // POST without autohunt field at all
        let (status, _) = post_json(
            &router,
            "/api/channels",
            r#"{"channels":[6],"dwell_ms":1000}"#,
        )
        .await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        let cfg = s.pending_channel_config.as_ref().unwrap();
        assert_eq!(
            cfg.autohunt, None,
            "missing autohunt field should deserialize as None"
        );
    }

    #[tokio::test]
    async fn test_empty_channels_with_autohunt_off() {
        let (router, _state) = test_router();
        // Autohunt off but empty channel list — should still 200 (daemon handles validation)
        let (status, body) = post_json(
            &router,
            "/api/channels",
            r#"{"channels":[],"autohunt":false}"#,
        )
        .await;
        assert_eq!(status, 200);
        let resp: ActionResponse = serde_json::from_str(&body).unwrap();
        assert!(resp.ok);
    }

    #[tokio::test]
    async fn test_channels_invalid_json_returns_error() {
        let (router, _state) = test_router();
        let (status, _) = post_json(&router, "/api/channels", r#"{"not_valid"#).await;
        assert_ne!(status, 200, "malformed JSON should not return 200");
    }

    #[tokio::test]
    async fn test_channels_empty_body_returns_error() {
        let (router, _state) = test_router();
        let (status, _) = post_json(&router, "/api/channels", r#""#).await;
        assert_ne!(status, 200, "empty body should not return 200");
    }

    #[tokio::test]
    async fn test_autohunt_on_immediately_updates_shared_state() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.autohunt_enabled = false; // start with autohunt off
        }
        let (status, _) = post_json(&router, "/api/channels", r#"{"autohunt":true}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert!(
            s.autohunt_enabled,
            "autohunt_enabled should be updated immediately so UI doesn't jump back"
        );
    }

    #[tokio::test]
    async fn test_autohunt_off_immediately_updates_shared_state() {
        let (router, state) = test_router();
        // autohunt_enabled defaults to true in test_state
        let (status, _) = post_json(
            &router,
            "/api/channels",
            r#"{"channels":[1,6,11],"autohunt":false}"#,
        )
        .await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert!(
            !s.autohunt_enabled,
            "autohunt_enabled should be updated immediately so UI doesn't jump back"
        );
    }

    // ---- Optimistic state update tests for all toggles/sliders ----

    #[tokio::test]
    async fn test_skip_captured_toggle_immediately_updates_state() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.skip_captured = false;
        }
        let (status, _) = post_json(&router, "/api/wifi", r#"{"skip_captured":true}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert!(
            s.skip_captured,
            "skip_captured should update immediately so toggle doesn't jump back"
        );
    }

    #[tokio::test]
    async fn test_rate_change_immediately_updates_state() {
        let (router, state) = test_router();
        let (status, _) = post_json(&router, "/api/rate", r#"{"rate":3}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(
            s.attack_rate, 3,
            "attack_rate should update immediately so rate buttons don't jump back"
        );
    }

    #[tokio::test]
    async fn test_rage_enable_immediately_updates_state() {
        let (router, state) = test_router();
        let (status, _) = post_json(&router, "/api/rage", r#"{"level":2}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert!(
            s.rage_enabled,
            "rage_enabled should update immediately so slider doesn't jump back"
        );
        assert_eq!(s.rage_level, 2, "rage_level should update immediately");
    }

    #[tokio::test]
    async fn test_rage_disable_immediately_updates_state() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.rage_enabled = true;
            s.rage_level = 2;
        }
        let (status, _) = post_json(&router, "/api/rage", r#"{"level":null}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert!(
            !s.rage_enabled,
            "rage_enabled should update immediately on disable"
        );
    }

    #[tokio::test]
    async fn test_whitelist_add_immediately_updates_state() {
        let (router, state) = test_router();
        let (status, _) = post_json(
            &router,
            "/api/whitelist/add",
            r#"{"value":"AA:BB:CC:DD:EE:FF","entry_type":"MAC"}"#,
        )
        .await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert!(
            s.whitelist.iter().any(|e| e.value == "AA:BB:CC:DD:EE:FF"),
            "whitelist should include new entry immediately so UI doesn't flash"
        );
    }

    #[tokio::test]
    async fn test_whitelist_remove_immediately_updates_state() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.whitelist.push(WhitelistEntry {
                value: "AA:BB:CC:DD:EE:FF".into(),
                entry_type: "MAC".into(),
            });
        }
        let (status, _) = post_json(
            &router,
            "/api/whitelist/remove",
            r#"{"value":"AA:BB:CC:DD:EE:FF"}"#,
        )
        .await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert!(
            !s.whitelist.iter().any(|e| e.value == "AA:BB:CC:DD:EE:FF"),
            "whitelist should remove entry immediately so UI doesn't flash"
        );
    }

    #[tokio::test]
    async fn test_wpasec_post_immediately_updates_state() {
        let (router, state) = test_router();
        let (status, _) =
            post_json(&router, "/api/wpasec", r#"{"api_key":"test_key_12345"}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(
            s.wpasec_api_key, "test_key_12345",
            "wpasec key should update immediately"
        );
    }

    #[tokio::test]
    async fn test_discord_post_immediately_updates_state() {
        let (router, state) = test_router();
        let (status, _) = post_json(
            &router,
            "/api/discord",
            r#"{"webhook_url":"https://discord.com/api/webhooks/test","enabled":true}"#,
        )
        .await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(
            s.discord_webhook_url,
            "https://discord.com/api/webhooks/test"
        );
        assert!(
            s.discord_enabled,
            "discord_enabled should update immediately"
        );
    }

    #[tokio::test]
    async fn test_settings_name_immediately_updates_state() {
        let (router, state) = test_router();
        let (status, _) = post_json(&router, "/api/settings", r#"{"name":"new-oxi"}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(
            s.name, "new-oxi",
            "name should update immediately so UI doesn't show stale name"
        );
    }

    #[tokio::test]
    async fn test_rate_clamp_immediately_updates_state() {
        let (router, state) = test_router();
        // Rate 99 should be clamped to 3
        let (status, _) = post_json(&router, "/api/rate", r#"{"rate":99}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(
            s.attack_rate, 3,
            "clamped rate should be reflected immediately"
        );
    }

    #[tokio::test]
    async fn test_rage_clamp_immediately_updates_state() {
        let (router, state) = test_router();
        // Level 99 should be clamped to 7
        let (status, _) = post_json(&router, "/api/rage", r#"{"level":99}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(
            s.rage_level, 7,
            "clamped rage level should be reflected immediately"
        );
    }

    #[tokio::test]
    async fn test_rage_preset_immediately_updates_rate_channels_dwell() {
        let (router, state) = test_router();
        // Level 4 = Hunt: rate 2, dwell 1000ms, channels 1-11
        let (status, _) = post_json(&router, "/api/rage", r#"{"level":4}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(s.attack_rate, 2, "rage preset should set rate immediately");
        assert_eq!(
            s.wifi_dwell_ms, 1000,
            "rage preset should set dwell immediately"
        );
        assert_eq!(
            s.wifi_channels.len(),
            11,
            "rage preset should set all 11 channels immediately"
        );
        assert!(
            !s.autohunt_enabled,
            "rage preset should disable autohunt immediately"
        );
    }

    #[tokio::test]
    async fn test_rage_level6_immediately_updates_rate_to_3() {
        let (router, state) = test_router();
        // Level 6 = FURY: rate 3, dwell 500ms
        let (status, _) = post_json(&router, "/api/rage", r#"{"level":6}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(
            s.attack_rate, 3,
            "FURY preset should set rate 3 immediately"
        );
        assert_eq!(s.wifi_dwell_ms, 500);
    }

    // === Settings panel tests (display invert, rotation, min_rssi, ap_ttl) ===

    #[tokio::test]
    async fn test_settings_display_invert_optimistic_update() {
        let (router, state) = test_router();
        let (status, _) = post_json(
            &router,
            "/api/settings",
            r#"{"name":"oxi","display_invert":false}"#,
        )
        .await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert!(
            !s.display_invert,
            "display_invert should update immediately"
        );
        assert!(s.pending_display_reinit, "reinit should be flagged");
    }

    #[tokio::test]
    async fn test_settings_display_invert_no_reinit_when_same() {
        let (router, state) = test_router();
        // Default is true, sending true again should NOT flag reinit
        let (status, _) = post_json(
            &router,
            "/api/settings",
            r#"{"name":"oxi","display_invert":true}"#,
        )
        .await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert!(s.display_invert);
        assert!(
            !s.pending_display_reinit,
            "reinit should NOT be flagged when value unchanged"
        );
    }

    #[tokio::test]
    async fn test_settings_display_rotation_optimistic_update() {
        let (router, state) = test_router();
        let (status, _) = post_json(
            &router,
            "/api/settings",
            r#"{"name":"oxi","display_rotation":0}"#,
        )
        .await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(s.display_rotation, 0, "rotation should update immediately");
        assert!(s.pending_display_reinit, "reinit should be flagged");
    }

    #[tokio::test]
    async fn test_settings_display_rotation_clamps_to_valid() {
        let (router, state) = test_router();
        // Anything non-180 clamps to 0
        let (status, _) = post_json(
            &router,
            "/api/settings",
            r#"{"name":"oxi","display_rotation":90}"#,
        )
        .await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(s.display_rotation, 0, "rotation 90 should clamp to 0");
    }

    #[tokio::test]
    async fn test_settings_min_rssi_optimistic_update() {
        let (router, state) = test_router();
        let (status, _) =
            post_json(&router, "/api/settings", r#"{"name":"oxi","min_rssi":-50}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(s.min_rssi, -50, "min_rssi should update immediately");
    }

    #[tokio::test]
    async fn test_settings_min_rssi_clamps_low() {
        let (router, state) = test_router();
        let (status, _) = post_json(
            &router,
            "/api/settings",
            r#"{"name":"oxi","min_rssi":-120}"#,
        )
        .await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(s.min_rssi, -100, "min_rssi below -100 should clamp to -100");
    }

    #[tokio::test]
    async fn test_settings_min_rssi_clamps_high() {
        let (router, state) = test_router();
        let (status, _) =
            post_json(&router, "/api/settings", r#"{"name":"oxi","min_rssi":-10}"#).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(s.min_rssi, -30, "min_rssi above -30 should clamp to -30");
    }

    #[tokio::test]
    async fn test_settings_ap_ttl_optimistic_update() {
        let (router, state) = test_router();
        let (status, _) = post_json(
            &router,
            "/api/settings",
            r#"{"name":"oxi","ap_ttl_secs":300}"#,
        )
        .await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(s.ap_ttl_secs, 300, "ap_ttl should update immediately");
    }

    #[tokio::test]
    async fn test_settings_ap_ttl_clamps_low() {
        let (router, state) = test_router();
        let (status, _) = post_json(
            &router,
            "/api/settings",
            r#"{"name":"oxi","ap_ttl_secs":5}"#,
        )
        .await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(s.ap_ttl_secs, 30, "ap_ttl below 30 should clamp to 30");
    }

    #[tokio::test]
    async fn test_settings_ap_ttl_clamps_high() {
        let (router, state) = test_router();
        let (status, _) = post_json(
            &router,
            "/api/settings",
            r#"{"name":"oxi","ap_ttl_secs":9999}"#,
        )
        .await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert_eq!(s.ap_ttl_secs, 600, "ap_ttl above 600 should clamp to 600");
    }

    #[tokio::test]
    async fn test_settings_all_four_fields_at_once() {
        let (router, state) = test_router();
        let (status, _) = post_json(
            &router,
            "/api/settings",
            r#"{"name":"oxi","display_invert":false,"display_rotation":0,"min_rssi":-60,"ap_ttl_secs":240}"#,
        ).await;
        assert_eq!(status, 200);
        let s = state.lock().unwrap();
        assert!(!s.display_invert);
        assert_eq!(s.display_rotation, 0);
        assert_eq!(s.min_rssi, -60);
        assert_eq!(s.ap_ttl_secs, 240);
        assert!(s.pending_display_reinit);
    }

    #[tokio::test]
    async fn test_settings_partial_update_preserves_others() {
        let (router, state) = test_router();
        // First set min_rssi
        post_json(&router, "/api/settings", r#"{"name":"oxi","min_rssi":-70}"#).await;
        // Then set ap_ttl only — min_rssi should remain
        post_json(
            &router,
            "/api/settings",
            r#"{"name":"oxi","ap_ttl_secs":200}"#,
        )
        .await;
        let s = state.lock().unwrap();
        assert_eq!(s.min_rssi, -70, "previous min_rssi should be preserved");
        assert_eq!(s.ap_ttl_secs, 200);
    }

    #[tokio::test]
    async fn test_status_includes_settings_fields() {
        let (router, state) = test_router();
        {
            let mut s = state.lock().unwrap();
            s.min_rssi = -55;
            s.ap_ttl_secs = 180;
            s.display_invert = false;
            s.display_rotation = 0;
        }
        let (status, body) = get(&router, "/api/status").await;
        assert_eq!(status, 200);
        let resp: StatusResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(resp.min_rssi, -55);
        assert_eq!(resp.ap_ttl_secs, 180);
        assert!(!resp.display_invert);
        assert_eq!(resp.display_rotation, 0);
    }

    // === Manual BT attack endpoint tests ===

    #[tokio::test]
    async fn test_bt_manual_attack_rejects_invalid_address() {
        let state = test_state();
        let body = BtManualAttackRequest {
            address: Some("invalid".into()),
            attack: "knob".into(),
        };
        let resp = bt_manual_attack_handler(State(state), Json(body)).await;
        assert!(!resp.ok);
    }

    #[tokio::test]
    async fn test_bt_manual_attack_accepts_valid_request() {
        let state = test_state();
        {
            let mut s = state.lock().unwrap();
            s.bt_rage_level = "Medium".into();
        }
        let body = BtManualAttackRequest {
            address: Some("AA:BB:CC:DD:EE:FF".into()),
            attack: "knob".into(),
        };
        let resp = bt_manual_attack_handler(State(state.clone()), Json(body)).await;
        assert!(resp.ok);
        let s = state.lock().unwrap();
        assert!(s.pending_bt_manual_attack.is_some());
    }

    #[tokio::test]
    async fn test_bt_manual_attack_rejects_non_manual() {
        let state = test_state();
        let body = BtManualAttackRequest {
            address: Some("AA:BB:CC:DD:EE:FF".into()),
            attack: "smp_downgrade".into(),
        };
        let resp = bt_manual_attack_handler(State(state), Json(body)).await;
        assert!(!resp.ok);
    }

    #[tokio::test]
    async fn test_bt_manual_attack_rejects_when_pending() {
        let state = test_state();
        {
            let mut s = state.lock().unwrap();
            s.bt_rage_level = "Medium".into();
            s.pending_bt_manual_attack = Some(BtManualAttackRequest {
                address: Some("11:22:33:44:55:66".into()),
                attack: "knob".into(),
            });
        }
        let body = BtManualAttackRequest {
            address: Some("AA:BB:CC:DD:EE:FF".into()),
            attack: "knob".into(),
        };
        let resp = bt_manual_attack_handler(State(state), Json(body)).await;
        assert!(!resp.ok);
        assert!(resp.message.contains("already pending"));
    }

    #[tokio::test]
    async fn test_bt_manual_vendor_no_address_required() {
        let state = test_state();
        let body = BtManualAttackRequest {
            address: None,
            attack: "vendor_cmd_unlock".into(),
        };
        let resp = bt_manual_attack_handler(State(state), Json(body)).await;
        assert!(resp.ok);
    }

    #[test]
    fn test_interact_cooldown_fields_default() {
        let ds = DaemonState::new("testbot");
        assert!(ds.interact_cooldowns.is_empty());
        assert!(ds.pending_mood_boost.is_none());
    }

    #[tokio::test]
    async fn test_interact_pet_boosts_mood() {
        let state = Arc::new(Mutex::new(DaemonState::new("testbot")));
        {
            let mut s = state.lock().unwrap();
            s.mood = 0.0;
        }
        let body = InteractRequest { action: "pet".into() };
        let resp = interact_handler(
            axum::extract::State(state.clone()),
            axum::Json(body),
        ).await;
        assert!(resp.0.ok);
        assert_eq!(resp.0.cooldown_secs, 60);
        let s = state.lock().unwrap();
        assert!(s.mood > 0.0, "mood should have increased");
        assert!(s.pending_mood_boost.is_some());
    }

    #[tokio::test]
    async fn test_interact_cooldown_rejects() {
        let state = Arc::new(Mutex::new(DaemonState::new("testbot")));
        // First press: succeeds
        let body = InteractRequest { action: "treat".into() };
        let resp = interact_handler(
            axum::extract::State(state.clone()),
            axum::Json(body),
        ).await;
        assert!(resp.0.ok);

        // Immediate second press: rejected
        let body2 = InteractRequest { action: "treat".into() };
        let resp2 = interact_handler(
            axum::extract::State(state.clone()),
            axum::Json(body2),
        ).await;
        assert!(!resp2.0.ok);
        assert!(resp2.0.cooldown_secs > 0);
    }

    #[tokio::test]
    async fn test_interact_unknown_action() {
        let state = Arc::new(Mutex::new(DaemonState::new("testbot")));
        let body = InteractRequest { action: "kick".into() };
        let resp = interact_handler(
            axum::extract::State(state.clone()),
            axum::Json(body),
        ).await;
        assert!(!resp.0.ok);
        assert_eq!(resp.0.message, "Unknown action");
    }

    #[tokio::test]
    async fn test_interact_soft_cap_at_high_mood() {
        let state = Arc::new(Mutex::new(DaemonState::new("testbot")));
        {
            let mut s = state.lock().unwrap();
            s.mood = 0.85; // above soft cap
        }
        let body = InteractRequest { action: "treat".into() };
        let resp = interact_handler(
            axum::extract::State(state.clone()),
            axum::Json(body),
        ).await;
        assert!(resp.0.ok);
        // Mood should barely change (above 0.8 cap)
        let s = state.lock().unwrap();
        assert!((s.mood - 0.85).abs() < 0.01, "mood {} should not increase much above cap", s.mood);
    }

    #[tokio::test]
    async fn test_interact_global_cooldown() {
        let state = Arc::new(Mutex::new(DaemonState::new("testbot")));
        // Pet succeeds
        let resp1 = interact_handler(
            axum::extract::State(state.clone()),
            axum::Json(InteractRequest { action: "pet".into() }),
        ).await;
        assert!(resp1.0.ok);

        // Treat rejected (global cooldown — any action blocks all)
        let resp2 = interact_handler(
            axum::extract::State(state.clone()),
            axum::Json(InteractRequest { action: "treat".into() }),
        ).await;
        assert!(!resp2.0.ok);

        // Pet also rejected
        let resp3 = interact_handler(
            axum::extract::State(state.clone()),
            axum::Json(InteractRequest { action: "pet".into() }),
        ).await;
        assert!(!resp3.0.ok);
    }
}
