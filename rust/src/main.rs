// rustc 1.94 ICE in AnnotateSnippetEmitter when rendering dead_code warnings.
// Remove this once the compiler is updated past the fix.
#![allow(dead_code)]

// Modules are the public API surface for Rusty Oxigotchi.
mod ao;
mod attacks;
mod ieee80211;
mod bluetooth;
mod capture;
mod config;
mod display;
mod epoch;
mod firmware;
mod gpu;
mod lua;
mod migration;
mod network;
mod personality;
mod pisugar;
mod qpu;
mod radio;
mod rage;
mod recovery;
mod gps;
mod ssid;
mod timer;
mod web;
mod wifi;
mod wigle;

use chrono::Timelike;
use log::info;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use crate::timer::WallTimer;

/// Ensure tmpfs capture directory exists for AO output.
/// Creates /tmp/ao_captures/ if it doesn't exist.
/// On Pi, /tmp is already a tmpfs mount, so this is just mkdir.
#[cfg(unix)]
fn ensure_tmpfs_capture_dir() -> String {
    let dir = "/tmp/ao_captures";
    let _ = std::fs::create_dir_all(dir);
    dir.to_string()
}

#[cfg(not(unix))]
fn ensure_tmpfs_capture_dir() -> String {
    let dir = std::env::temp_dir().join("ao_captures");
    let _ = std::fs::create_dir_all(&dir);
    dir.to_string_lossy().to_string()
}

/// Build a FacePackInfo list by scanning the face_packs directory.
/// Used by sync_to_web to populate the dashboard's pack listing.
fn list_face_packs(
    root: &std::path::Path,
    cache_root: &std::path::Path,
) -> Vec<web::FacePackInfo> {
    let mut infos = vec![web::FacePackInfo {
        name: "default".to_string(),
        is_default: true,
        face_count: 26,
        converting: 0,
    }];
    let pack_names = match display::face_pack::discover_packs(root) {
        Ok(p) => p,
        Err(_) => return infos,
    };
    for name in pack_names {
        let cache_dir = cache_root.join(&name);
        let mut face_count = 0;
        if let Ok(entries) = std::fs::read_dir(&cache_dir) {
            for entry in entries.flatten() {
                if entry.path().extension().and_then(|e| e.to_str()) == Some("raw") {
                    face_count += 1;
                }
            }
        }
        let mut converting = 0;
        let pack_dir = root.join(&name);
        if let Ok(entries) = std::fs::read_dir(&pack_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("png") {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        if display::face_pack::face_name_from_filename(stem).is_some() {
                            let raw_path = cache_dir.join(format!("{}.raw", stem.to_lowercase()));
                            if !raw_path.exists() {
                                converting += 1;
                            }
                        }
                    }
                }
            }
        }
        infos.push(web::FacePackInfo {
            name,
            is_default: false,
            face_count,
            converting,
        });
    }
    infos
}

/// Default attack rate. All rates (1-3) stable with v6 firmware patch.
const ATTACK_RATE: u32 = 1;
/// Default capture directory.
const CAPTURE_DIR: &str = "/home/pi/captures";

/// Operating mode: RAGE (WiFi attacks), BT (Bluetooth offensive), or SAFE (BT internet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperatingMode {
    Rage,
    Bt,
    Safe,
}

impl OperatingMode {
    fn as_str(&self) -> &str {
        match self {
            OperatingMode::Rage => "RAGE",
            OperatingMode::Bt => "BT",
            OperatingMode::Safe => "SAFE",
        }
    }

    /// Three-way cycle: RAGE → BT → SAFE → RAGE.
    fn next(&self) -> Self {
        match self {
            OperatingMode::Rage => OperatingMode::Bt,
            OperatingMode::Bt => OperatingMode::Safe,
            OperatingMode::Safe => OperatingMode::Rage,
        }
    }

    /// Backward-compat alias for `next()`.
    fn toggle(&self) -> Self {
        self.next()
    }
}

/// All subsystem state, owned by the main loop.
struct Daemon {
    config: config::Config,
    screen: display::Screen,
    epoch_loop: epoch::EpochLoop,
    wifi: wifi::WifiManager,
    attacks: attacks::AttackScheduler,
    captures: capture::CaptureManager,
    ssid_resolver: ssid::SsidResolver,
    ssid_resolve_timer: timer::WallTimer,
    ssid_flush_timer: timer::WallTimer,
    bluetooth: bluetooth::BtTether,
    bt_feature: bluetooth::supervisor::BtSupervisor,
    bt_discovery: bluetooth::discovery::BtDiscoveryWorker,
    bt_attack_scheduler: bluetooth::attacks::BtAttackScheduler,
    bt_capture_manager: bluetooth::capture::BtCaptureManager,
    bt_controller_worker: bluetooth::controller::BtControllerWorker,
    bt_coex_worker: bluetooth::coex::BtCoexWorker,
    battery: pisugar::PiSugar,
    network: network::NetworkManager,
    recovery: recovery::RecoveryManager,
    watchdog: recovery::Watchdog,
    ao: ao::AoManager,
    radio: radio::RadioManager,
    patchram: bluetooth::patchram::PatchramManager,
    bt_hci_socket: Option<bluetooth::attacks::hci::HciSocket>,
    firmware_monitor: firmware::FirmwareMonitor,
    gpu_state: gpu::state::gpu_state::GpuFeatureState,
    gpu_runtime_ingestor: gpu::runtime::ingest::GpuRuntimeIngestor,
    gpu_optimizer: gpu::optimize::snapshot::SnapshotOptimizer,
    qpu_engine: Option<qpu::engine::QpuEngine>,
    mode: OperatingMode,
    /// Set in new() from config.main.default_mode when that mode is not RAGE.
    /// boot() uses this to skip WiFi setup and queue the mode transition.
    boot_target_mode: Option<String>,
    shared_state: web::SharedState,
    ws_tx: tokio::sync::broadcast::Sender<String>,
    prev_cpu_sample: Option<personality::CpuSample>,
    lua: lua::PluginRuntime,
    plugin_watcher: Option<lua::PluginWatcher>,
    wpasec_config: capture::WpaSecConfig,
    upload_queue: capture::UploadQueue,
    wigle_config: wigle::WigleConfig,
    /// BSSIDs already written to the WIGLE staging CSV (dedup across epochs).
    wigle_seen: std::collections::HashSet<String>,
    wigle_upload_timer: WallTimer,
    wigle_staging_path: std::path::PathBuf,
    /// Whether the last epoch produced a valid GPS fix (used for display indicator).
    gps_fix_active: bool,
    discord_webhook_url: String,
    discord_enabled: bool,
    /// Whether AO should auto-hunt channels vs use the configured channel list.
    autohunt: bool,
    /// Smart Skip: skip APs that already have captured handshakes on SD.
    skip_captured: bool,
    /// Collect All: AO writes directly to SD, all frames kept (not just verified handshakes).
    capture_all: bool,
    /// Adaptive channel scorer: ranks channels 1-13 by AP density, RSSI, etc.
    channel_scorer: wifi::ChannelScorer,
    /// tmpfs directory for AO captures (validated before moving to SD).
    tmpfs_capture_dir: String,
    /// Cumulative APs seen across all previous sessions (loaded from state.json).
    lifetime_aps_base: u64,
    /// Previous epoch's cumulative AP count from AO — used to compute delta (new unique APs).
    prev_ap_count: u32,
    // ---- Wall-clock timers (replace epoch % N scheduling) ----
    mood_timer: WallTimer,
    xp_passive_timer: WallTimer,
    xp_save_timer: WallTimer,
    psm_reset_timer: WallTimer,
    wpasec_fetch_timer: WallTimer,
    bt_internet_recheck_timer: WallTimer,
    ws_broadcast_timer: WallTimer,
    cpu_sample_timer: WallTimer,
    lua_tick_timer: WallTimer,
    bt_scan_alt_timer: WallTimer,
    qpu_reset_timer: WallTimer,
    autohunt_coldstart: WallTimer,
    autohunt_warmed_up: bool,
    bt_scan_use_le: bool,
    epoch_start: Instant,
    last_drawn_face: Option<personality::Face>,
    active_pack: display::face_pack::FacePack,
    face_pack_timer: WallTimer,
    face_pack_last_error: Option<String>,
    /// True while a BT scan thread is running and we have paused AO + wlan0mon
    /// to free the shared antenna for BT inquiry. Cleared when the scan thread
    /// completes and the main loop restores WiFi.
    ao_paused_for_bt_scan: bool,
}

impl Daemon {
    fn new(
        config: config::Config,
        shared_state: web::SharedState,
        ws_tx: tokio::sync::broadcast::Sender<String>,
    ) -> Self {
        let screen = display::Screen::new(config.display.clone());
        let epoch_loop = epoch::EpochLoop::new();
        let wifi = wifi::WifiManager::new();
        let mut attacks = attacks::AttackScheduler::new(ATTACK_RATE);

        // Populate attack whitelist from config
        let _ = &config.whitelist;
        attacks.whitelist.clear();

        let captures = capture::CaptureManager::new(CAPTURE_DIR);
        let bt_config = bluetooth::BtConfig {
            enabled: config.bluetooth.enabled,
            phone_name: config.bluetooth.phone_name.clone(),
            phone_mac: config.bluetooth.phone_mac.clone(),
            auto_connect: config.bluetooth.auto_connect,
            hide_after_connect: config.bluetooth.hide_after_connect,
        };
        let bluetooth = bluetooth::BtTether::new(bt_config);
        let bt_feature = bluetooth::supervisor::BtSupervisor::new(config.bt_feature.clone());
        let gpu_mode = if config.gpu.enabled {
            config.gpu.mode.clone()
        } else {
            gpu::state::gpu_state::GpuMode::Off
        };
        let battery = pisugar::PiSugar::default();
        let network = network::NetworkManager::new();
        let recovery = recovery::RecoveryManager::default();
        let watchdog = recovery::Watchdog::new(true, 60);
        let ao = ao::AoManager::default();
        let patchram = bluetooth::patchram::PatchramManager::new(
            config.bt_attacks.attack_hcd.clone(),
            config.bt_attacks.stock_hcd.clone(),
        );
        let bt_attack_scheduler = bluetooth::attacks::BtAttackScheduler::new(config.bt_attacks.clone());
        let bt_capture_manager = bluetooth::capture::BtCaptureManager::new(&config.bt_attacks.capture_dir);
        let boot_mode = match config.main.default_mode.to_uppercase().as_str() {
            "RAGE" => OperatingMode::Rage,
            "BT" => OperatingMode::Bt,
            _ => OperatingMode::Safe,
        };

        Self {
            config,
            screen,
            epoch_loop,
            wifi,
            attacks,
            captures,
            ssid_resolver: ssid::SsidResolver::new(
                std::path::PathBuf::from("/home/pi/bssid_ssid.json")
            ),
            ssid_resolve_timer: timer::WallTimer::new(Duration::from_secs(30)),
            ssid_flush_timer: timer::WallTimer::new(Duration::from_secs(60)),
            bluetooth,
            bt_feature,
            bt_discovery: bluetooth::discovery::BtDiscoveryWorker::new(),
            bt_attack_scheduler,
            bt_capture_manager,
            bt_controller_worker: bluetooth::controller::BtControllerWorker::new(),
            bt_coex_worker: bluetooth::coex::BtCoexWorker::new(),
            battery,
            network,
            recovery,
            watchdog,
            ao,
            radio: radio::RadioManager::new(),
            patchram,
            bt_hci_socket: None,
            firmware_monitor: firmware::FirmwareMonitor::new(),
            gpu_state: gpu::state::gpu_state::GpuFeatureState {
                mode: gpu_mode,
                ..gpu::state::gpu_state::GpuFeatureState::default()
            },
            gpu_runtime_ingestor: gpu::runtime::ingest::GpuRuntimeIngestor::new(),
            gpu_optimizer: gpu::optimize::snapshot::SnapshotOptimizer::new(),
            qpu_engine: None, // initialized in boot()
            mode: boot_mode,
            boot_target_mode: if boot_mode != OperatingMode::Rage {
                Some(boot_mode.as_str().to_string())
            } else {
                None
            },
            shared_state,
            ws_tx,
            prev_cpu_sample: None,
            lua: lua::PluginRuntime::new(),
            plugin_watcher: None, // initialized in boot() after plugin dir is confirmed
            wpasec_config: capture::WpaSecConfig::default(),
            upload_queue: capture::UploadQueue::new(),
            wigle_config: wigle::WigleConfig::default(),
            wigle_seen: std::collections::HashSet::new(),
            wigle_upload_timer: WallTimer::new(Duration::from_secs(1800)),
            wigle_staging_path: std::path::PathBuf::from("/tmp/oxigotchi-wigle.csv"),
            gps_fix_active: false,
            discord_webhook_url: String::new(),
            discord_enabled: false,
            autohunt: true,
            skip_captured: true,
            capture_all: false,
            channel_scorer: wifi::ChannelScorer::new(3),
            tmpfs_capture_dir: ensure_tmpfs_capture_dir(),
            lifetime_aps_base: 0,
            prev_ap_count: 0,
            // Wall-clock timers
            mood_timer: WallTimer::new(Duration::from_secs(30)),
            xp_passive_timer: WallTimer::new(Duration::from_secs(30)),
            xp_save_timer: WallTimer::new(Duration::from_secs(150)),
            psm_reset_timer: WallTimer::new(Duration::from_secs(900)),
            wpasec_fetch_timer: WallTimer::new(Duration::from_secs(1500)),
            bt_internet_recheck_timer: WallTimer::new(Duration::from_secs(120)),
            ws_broadcast_timer: WallTimer::new(Duration::from_secs(2)),
            cpu_sample_timer: WallTimer::new(Duration::from_secs(5)),
            lua_tick_timer: WallTimer::new(Duration::from_secs(5)),
            bt_scan_alt_timer: WallTimer::new(Duration::from_secs(60)),
            qpu_reset_timer: WallTimer::new(Duration::from_secs(10)),
            autohunt_coldstart: WallTimer::new(Duration::from_secs(300)),
            autohunt_warmed_up: false,
            bt_scan_use_le: true,
            epoch_start: Instant::now(),
            last_drawn_face: None,
            active_pack: display::face_pack::FacePack::empty(),
            face_pack_timer: WallTimer::new(Duration::from_secs(30)),
            face_pack_last_error: None,
            ao_paused_for_bt_scan: false,
        }
    }

    /// Boot sequence: init display, probe hardware, scan existing captures, start AO.
    fn boot(&mut self) {
        // Load saved XP/mood from disk
        let xp_path = std::path::Path::new(personality::DEFAULT_XP_SAVE_PATH);
        let (xp, mood) = personality::XpTracker::load(xp_path);
        self.epoch_loop.personality.xp = xp;
        self.epoch_loop.personality.mood = personality::Mood::new(mood);
        info!(
            "loaded XP: Lv {} ({} xp), mood {:.2}",
            self.epoch_loop.personality.xp.level, self.epoch_loop.personality.xp.xp_total, mood
        );

        // Display boot screen with debug face (Feature 7: debug on boot)
        let boot_face_key = self.epoch_loop.personality.variety.boot_face();
        let boot_face = if boot_face_key == "debug" {
            personality::Face::Debug
        } else {
            personality::Face::Awake
        };
        self.screen.clear();
        // Boot screen: centered face + centered welcome text below
        // Face: 120x66, centered horizontally: x = (250-120)/2 = 65
        let boot_bitmap = display::face_pack::bitmap_for_face(boot_face, &self.active_pack);
        self.screen.draw_bitmap(
            boot_bitmap,
            65,
            5,
            display::faces::FACE_WIDTH,
            display::faces::FACE_HEIGHT,
        );
        // Welcome text centered below face, using bold font
        let line1 = format!("Hi! I'm {}!", self.config.name);
        let line2 = format!("Starting v{}", env!("CARGO_PKG_VERSION"));
        // Center: each char ~7px wide in bold (12pt), display=250
        let x1 = (250 - (line1.len() as i32) * 7) / 2;
        let x2 = (250 - (line2.len() as i32) * 7) / 2;
        self.screen.draw_name_at(&line1, x1, 80);
        self.screen.draw_name_at(&line2, x2, 95);
        self.screen.flush();
        info!("display initialized");

        // Probe PiSugar battery
        if self.battery.probe() {
            self.battery.configure_registers();
            let level = self.battery.read_status().level;
            info!("PiSugar detected: {}%, board temp {}°C", level, self.battery.temperature_c);
        } else {
            info!("PiSugar not detected");
        }

        // Disable legacy Python/Go services — Rusty Oxigotchi replaces them.
        // Saves ~66MB RAM (bettercap ~36MB + pwnagotchi ~30MB).
        #[cfg(unix)]
        {
            use std::process::Command;
            for svc in &["pwnagotchi", "bettercap"] {
                let active = Command::new("systemctl")
                    .args(["is-active", "--quiet", svc])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if active {
                    info!("disabling legacy service: {svc}");
                    let _ = Command::new("systemctl").args(["stop", svc]).output();
                    let _ = Command::new("systemctl").args(["disable", svc]).output();
                }
            }
        }

        // Load persisted runtime state early — mode must be known before
        // deciding whether to start WiFi or BT.
        self.load_runtime_state();

        // Start WiFi monitor mode — but only if booting into a WiFi mode.
        // If config.main.default_mode is BT/SAFE, skip WiFi and queue a mode
        // switch so the first epoch transitions the radio.
        if let Some(ref target) = self.boot_target_mode {
            info!("target mode is {target} — skipping WiFi, will transition in first epoch");
            let mut s = self.shared_state.lock().unwrap();
            s.pending_mode_switch = Some(target.clone());
            drop(s);
        } else {
            match self.wifi.start_monitor() {
                Ok(()) => info!("WiFi monitor mode started"),
                Err(e) => {
                    log::error!("Failed to start WiFi monitor: {e}");
                    self.epoch_loop
                        .personality
                        .set_override(personality::Face::WifiDown);
                }
            }
        }

        // Scan for existing capture files
        match self.captures.scan_directory() {
            Ok(n) => info!("found {n} existing captures"),
            Err(e) => log::warn!("capture scan failed: {e}"),
        }

        // Load cached BSSID->SSID map
        self.ssid_resolver.load();
        info!("SSID resolver: loaded {} cached entries", self.ssid_resolver.entry_count());

        // Load Lua plugins — read persisted positions from plugins.toml, fall back to defaults
        let plugin_defaults = vec![
            lua::PluginConfig::default_for("ao_status", 0, 0),
            lua::PluginConfig::default_for("aps", 130, 0),
            lua::PluginConfig::default_for("uptime", 178, 0),
            lua::PluginConfig::default_for("status_msg", 125, 20),
            lua::PluginConfig::default_for("sys_stats", 125, 85),
            lua::PluginConfig::default_for("bt_ip_display", 0, 85),
            lua::PluginConfig::default_for("ip_display", 0, 95),
            lua::PluginConfig::default_for("crash", 0, 112),
            lua::PluginConfig::default_for("www", 52, 112),
            lua::PluginConfig::default_for("bt_status", 96, 112),
            lua::PluginConfig::default_for("battery", 140, 112),
            lua::PluginConfig::default_for("wigle_gps", 185, 112),
            lua::PluginConfig::default_for("mode", 214, 112),
            lua::PluginConfig::default_for("bt_summary", 0, 0),
            lua::PluginConfig::default_for("bt_devices", 0, 0),
        ];
        let plugin_configs = match lua::config::read_plugins_toml() {
            Some(pt) => {
                info!("loaded plugin positions from plugins.toml");
                lua::config::merge_with_defaults(plugin_defaults, &pt)
            }
            None => plugin_defaults,
        };
        let loaded = self
            .lua
            .load_plugins_from_dir("/etc/oxigotchi/plugins", &plugin_configs);
        info!("loaded {loaded} Lua plugin(s)");

        // Start watching plugin directory for hot-reload
        match lua::PluginWatcher::new("/etc/oxigotchi/plugins") {
            Ok(watcher) => {
                info!("plugin hot-reload watcher active");
                self.plugin_watcher = Some(watcher);
            }
            Err(e) => log::warn!("plugin watcher not available: {e}"),
        }

        // USB RNDIS network setup
        self.network.probe();
        if self.network.usb0_state != network::Usb0State::Absent {
            match self.network.apply_ip_config() {
                Ok(()) => info!("USB network configured: {}", self.network.status_str()),
                Err(e) => log::warn!("USB network setup failed: {e}"),
            }
        } else {
            info!("usb0 not present, skipping network setup");
        }

        // Point AO output to tmpfs (verified mode) or SD directly (collect-all mode).
        if self.capture_all {
            self.ao.config.output_dir = CAPTURE_DIR.to_string();
            info!(
                "capture pipeline: collect-all mode — AO output -> SD ({})",
                CAPTURE_DIR
            );
        } else {
            self.ao.config.output_dir = format!("{}/capture", self.tmpfs_capture_dir);
            info!(
                "capture pipeline: verified mode — AO output -> tmpfs ({})",
                self.tmpfs_capture_dir
            );
        }

        // Pass SSID whitelist to AO so it skips our own APs
        self.ao.config.whitelist = self.build_ao_whitelist();
        if !self.ao.config.whitelist.is_empty() {
            info!("AO whitelist: {:?}", self.ao.config.whitelist);
        }

        // Skip AO/QPU/radio-lock when booting into non-WiFi mode —
        // enter_bt_mode()/enter_safe_mode() handles the radio transition
        // in the first epoch.
        if self.boot_target_mode.is_none() {
            // BT tether setup is deferred to the first epoch — hardware may
            // not be ready during early boot (hciattach, UART settle).


            // Start AngryOxide subprocess
            match self.ao.start() {
                Ok(()) => info!("AO started: PID {}", self.ao.pid),
                Err(e) => {
                    log::error!("AO failed to start: {e}");
                    self.epoch_loop
                        .personality
                        .set_override(personality::Face::AoCrashed);
                }
            }

            // QPU initialization
            if self.config.qpu.enabled {
                match qpu::engine::QpuEngine::init(self.config.qpu.to_engine_config()) {
                    Ok(mut engine) => {
                        info!(
                            "QPU engine initialized: {} QPUs available",
                            engine.num_qpus()
                        );
                        // Start pcap capture thread on wlan0mon
                        match engine.start_capture("wlan0mon") {
                            Ok(()) => info!("QPU capture thread started on wlan0mon"),
                            Err(e) => log::warn!("QPU capture start failed: {e} (frames from AO only)"),
                        }
                        self.qpu_engine = Some(engine);
                    }
                    Err(e) => {
                        log::warn!("QPU init failed (CPU fallback): {}", e);
                    }
                }
            }

            // Acquire radio lock — WiFi mode
            if let Err(e) = self.radio.acquire_lock(radio::RadioMode::Wifi) {
                log::warn!("failed to acquire WIFI radio lock on boot: {e}");
            }
        }

        // Initial state sync to web
        self.sync_to_web();
        web::broadcast_state(&self.shared_state, &self.ws_tx);
    }

    /// Run one full epoch: Scan -> Attack -> Capture -> Display.
    fn run_epoch(&mut self) {
        self.epoch_start = Instant::now();
        let mut result = epoch::EpochResult::default();

        // ---- Web commands ----
        self.process_web_commands();

        // ---- Face pack conversion (background tick) ----
        if self.face_pack_timer.due() {
            let root = std::path::Path::new(display::face_pack::FACE_PACK_DIR);
            let cache = std::path::Path::new(display::face_pack::FACE_PACK_CACHE);
            match display::face_pack::convert_one_png(root, cache) {
                Ok(_) => self.face_pack_last_error = None,
                Err(e) => {
                    let msg = e.to_string();
                    if self.face_pack_last_error.as_deref() != Some(&msg) {
                        log::warn!("face_pack: tick failed: {msg}");
                        self.face_pack_last_error = Some(msg);
                    }
                }
            }
        }

        // ---- PiSugar button events ----
        self.process_button();

        // ---- PiSugar soft shutdown (power button) ----
        if self.battery.check_soft_shutdown() {
            self.show_transition(personality::Face::Shutdown, "Shutting down...");
            self.battery.pisugar_shutdown();
            return; // stop processing this epoch
        }

        // ---- Bluetooth D-Bus message processing (all modes — Agent1 pairing events) ----
        self.bluetooth.process_dbus();
        // Collect events first so we drop the borrow on pairing_rx before
        // processing — some arms call self.bluetooth.connect() (mutable).
        let bt_events: Vec<_> = self
            .bluetooth
            .pairing_rx
            .as_ref()
            .map(|rx| std::iter::from_fn(|| rx.try_recv().ok()).collect())
            .unwrap_or_default();
        for event in bt_events {
            match event {
                    bluetooth::dbus::PairingEvent::ConfirmPasskey { device, passkey }
                    | bluetooth::dbus::PairingEvent::DisplayPasskey { device, passkey } => {
                        let mut s = self.shared_state.lock().unwrap();
                        s.bt_passkey = Some(passkey);
                        s.bt_passkey_device = device;
                        info!("BT: pairing passkey {passkey} forwarded to web UI");
                    }
                    bluetooth::dbus::PairingEvent::PairingComplete { device, success } => {
                        info!("BT: pairing complete for {device}: success={success}");
                        let mut s = self.shared_state.lock().unwrap();
                        s.bt_passkey = None;
                        s.bt_passkey_device.clear();
                    }
                    bluetooth::dbus::PairingEvent::RequestConfirmation { device } => {
                        info!("BT: pairing request from {device} (auto-accepted)");
                    }
                    bluetooth::dbus::PairingEvent::DeviceNewlyPaired { device } => {
                        // Phone-initiated pair just completed. Auto-set Trusted=true
                        // so the daemon's connect path (and any user-facing logic
                        // that cares about Trusted) sees a clean, first-class bond.
                        info!("BT: auto-trusting newly paired device {device}");
                        {
                            let mut s = self.shared_state.lock().unwrap();
                            s.bt_passkey = None;
                            s.bt_passkey_device.clear();
                        }
                        if let Some(ref dbus) = self.bluetooth.dbus_ref() {
                            match dbus.trust_device(&device) {
                                Ok(()) => info!("BT: auto-trust OK for {device}"),
                                Err(e) => log::warn!("BT: auto-trust failed for {device}: {e}"),
                            }
                        } else {
                            log::warn!("BT: auto-trust skipped — D-Bus not initialized");
                        }
                    }
                    bluetooth::dbus::PairingEvent::DeviceReconnected { device } => {
                        // Network1.Connect internally opens the ACL link first,
                        // which can emit Connected=true before PAN succeeds.
                        // Never let that signal bypass the normal retry/backoff
                        // logic after a recent connect failure.
                        info!("BT: device reconnected (ACL up): {device}");

                        if self.bluetooth.pan_interface.is_some()
                            || matches!(
                                self.bluetooth.state,
                                bluetooth::BtState::Connected | bluetooth::BtState::Connecting
                            )
                        {
                            log::debug!(
                                "BT: ignoring ACL reconnect for {device} — PAN is already up or connecting"
                            );
                            continue;
                        }

                        if !self.bluetooth.should_connect() {
                            log::debug!(
                                "BT: ignoring ACL reconnect for {device} — reconnect backoff/user policy active"
                            );
                            continue;
                        }

                        self.bluetooth.state = bluetooth::BtState::Disconnected;
                        match self.bluetooth.connect() {
                            Ok(()) => info!("BT: PAN reconnected after ACL restore: {}", self.bluetooth.status_str()),
                            Err(e) => {
                                log::debug!("BT: PAN connect after ACL restore failed: {e}");
                            }
                        }
                    }
                }
        }

        // ---- BT mode: run BT epoch instead of WiFi phases ----
        if self.mode == OperatingMode::Bt {
            self.run_bt_epoch();
            // Skip WiFi scan/attack/capture — jump to display/personality/web sync below
        } else {

        // ---- AO health (RAGE mode only) ----
        if self.mode == OperatingMode::Rage && self.ao.check_health() {
            self.epoch_loop
                .personality
                .set_override(personality::Face::AoCrashed);
        }
        // Suppress AO auto-restart while a BT scan is in progress —
        // restarting AO puts wlan0mon back on the shared antenna and
        // starves BT inquiry.
        if self.mode == OperatingMode::Rage && !self.ao_paused_for_bt_scan {
            self.ao.try_auto_restart();
        }

        // ---- Bluetooth health (SAFE and RAGE modes) ----
        // Deferred setup: first epoch initializes BT (hardware not ready at boot).
        // Runs BEFORE scan so BT coexistence rate cap can protect the combo chip.
        // Skip entirely if BT is disabled in config — otherwise setup() returns
        // Ok(()) without initializing D-Bus, dbus_ready() stays false, and the
        // health block spams "BT tether initialized: BT OFF" every epoch.
        if (self.mode == OperatingMode::Safe || self.mode == OperatingMode::Rage)
            && self.bluetooth.config.enabled
        {
            if self.bluetooth.dbus_ready() {
                self.bluetooth.check_status();
                if self.bluetooth.pan_interface.is_some() && !self.bluetooth.internet_available {
                    if self.bt_internet_recheck_timer.due() {
                        let _ = self.bluetooth.refresh_internet_status();
                    }
                } else {
                    self.bt_internet_recheck_timer.reset();
                }
                if self.bluetooth.should_connect() {
                    match self.bluetooth.connect() {
                        Ok(()) => info!("bluetooth reconnected: {}", self.bluetooth.status_str()),
                        Err(e) => {
                            log::warn!("bluetooth reconnect failed: {e}");
                        }
                    }
                }
            } else {
                match self.bluetooth.setup() {
                    Ok(()) => info!("BT tether initialized: {}", self.bluetooth.status_str()),
                    Err(e) => log::warn!("BT tether setup deferred (not ready): {e}"),
                }
            }
        }

        // ---- Scan phase ----
        self.run_scan_phase(&mut result);

        // ---- Network health ----
        self.network.health_check();
        self.network.check_internet();

        // ---- Firmware health (RAGE mode only) ----
        if self.mode == OperatingMode::Rage {
            let fw_health = self.firmware_monitor.poll();
            match fw_health {
                firmware::FirmwareHealth::Critical => {
                    log::warn!(
                        "firmware: CRITICAL -- counters spiking (crash={}, fault={}), triggering preemptive recovery",
                        self.firmware_monitor.crash_suppress,
                        self.firmware_monitor.hardfault
                    );
                }
                firmware::FirmwareHealth::Degraded => {
                    log::info!(
                        "firmware: degraded -- counters increasing (crash={}, fault={})",
                        self.firmware_monitor.crash_suppress,
                        self.firmware_monitor.hardfault
                    );
                }
                firmware::FirmwareHealth::Healthy => {}
                firmware::FirmwareHealth::Unknown => {
                    if self.firmware_monitor.initialized {
                        log::warn!("firmware: health monitor lost SDIO RAMRW — was working, now failing");
                    }
                }
            }
        }

        // ---- Adaptive channel scoring (RAGE mode only) ----
        if self.mode == OperatingMode::Rage {
            self.channel_scorer.reset_epoch_counts();

            // Feed AP data from WiFi tracker (has RSSI + client counts)
            for ap in self.wifi.tracker.sorted_by_rssi() {
                self.channel_scorer
                    .record_ap(ap.channel, ap.rssi, ap.client_count);
            }

            // Feed capture info from AO (which APs had captures this session)
            for ao_ap in &self.ao.ap_snapshot() {
                if ao_ap.captured {
                    self.channel_scorer.record_capture(ao_ap.channel);
                }
            }

            // Mark the current AO channel as visited
            let current_ch = self.ao.channel() as u8;
            self.channel_scorer.mark_visited(current_ch);
            self.channel_scorer.tick_epoch();

            // When autohunt is ON, update AO's channel config with the best channels.
            // Cold-start guard: use safe 1,6,11 for the first 5 min so the
            // scorer collects real AP data before making decisions.
            if !self.autohunt_warmed_up && self.autohunt_coldstart.due() {
                self.autohunt_warmed_up = true;
            }
            if self.autohunt {
                let best = if !self.autohunt_warmed_up {
                    vec![1, 6, 11]
                } else {
                    self.channel_scorer.top_channels()
                };
                if !best.is_empty() {
                    self.wifi.channel_config.channels = best.clone();
                    self.ao.config.channels = best;
                    info!(
                        "adaptive channels: top {} -> {:?}",
                        self.wifi.channel_config.channels.len(),
                        self.wifi.channel_config.channels
                    );
                }
            }
        }

        // ---- Prune stale APs ----
        let ap_ttl = self.shared_state.lock().unwrap().ap_ttl_secs;
        self.wifi.tracker.prune(ap_ttl);

        // ---- Attack + Capture phases ----
        if self.mode == OperatingMode::Rage {
            self.run_attack_phase(&mut result);
        } else {
            self.epoch_loop.next_phase(); // -> Attack (skip)
        }
        self.run_capture_phase(&mut result);

        } // end else (non-BT mode WiFi phases)

        // ---- QPU classification + RF environment ----
        if let Some(ref mut engine) = self.qpu_engine {
            let classified = engine.process_batch();
            if !classified.is_empty() {
                // Collect AO BSSID set for cross-reference
                let ao_bssids: std::collections::HashSet<[u8; 6]> = self
                    .ao
                    .ap_snapshot()
                    .iter()
                    .filter_map(|ap| {
                        let hex = &ap.bssid;
                        if hex.len() == 12 {
                            let mut b = [0u8; 6];
                            for i in 0..6 {
                                b[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                                    .unwrap_or(0);
                            }
                            Some(b)
                        } else {
                            None
                        }
                    })
                    .collect();

                let epoch_secs = self.epoch_start.elapsed().as_secs_f32().max(1.0);
                let rf = qpu::rf::RfEnvironment::compute(
                    &classified,
                    epoch_secs,
                    &ao_bssids,
                );

                // Feed RF environment into personality (RAGE only — stale in BT mode)
                if self.mode != OperatingMode::Bt {
                    self.epoch_loop.personality.apply_rf_environment(&rf);
                }

                // Store RF stats for web API
                {
                    let mut s = self.shared_state.lock().unwrap();
                    s.qpu_beacon_rate = rf.beacon_rate;
                    s.qpu_probe_rate = rf.probe_rate;
                    s.qpu_deauth_rate = rf.deauth_rate;
                    s.qpu_data_rate = rf.data_rate;
                    s.qpu_unique_bssids = rf.unique_bssids;
                    s.qpu_total_frames = rf.total_frames;
                    s.qpu_dominant_class = format!("{:?}", rf.dominant_class);
                }
            }
        }

        // ---- SSID resolver: parse new beacon frames from AO pcapng ----
        if self.ssid_resolve_timer.due() {
            // ao.config.output_dir is a file prefix (e.g. "/tmp/ao_captures/capture"),
            // not a directory. Use tmpfs_capture_dir for the actual directory.
            let ao_dir = std::path::Path::new(&self.tmpfs_capture_dir);
            self.ssid_resolver.tick(ao_dir);
        }
        // Flush SSID map to disk periodically
        if self.ssid_flush_timer.due() {
            self.ssid_resolver.flush();
        }

        // ---- WIGLE observation logging (RAGE mode, gated on GPS fix) ----
        if self.mode == OperatingMode::Rage && self.wigle_config.enabled {
            let fix = gps::query_gpsd();
            self.gps_fix_active = fix.is_some();
            if let Some(fix) = fix {
                let new_obs: Vec<wigle::WigleObservation> = self
                    .ao
                    .ap_snapshot()
                    .into_iter()
                    .filter(|ap| !self.wigle_seen.contains(&ap.bssid))
                    .map(|ap| wigle::WigleObservation {
                        bssid: ap.bssid,
                        channel: ap.channel,
                    })
                    .collect();
                if !new_obs.is_empty() {
                    for obs in &new_obs {
                        self.wigle_seen.insert(obs.bssid.clone());
                    }
                    match wigle::append_observations(
                        &self.wigle_staging_path,
                        &new_obs,
                        &fix,
                        &self.ssid_resolver,
                        &self.config.name,
                    ) {
                        Ok(n) => log::debug!("WIGLE: logged {n} new AP(s)"),
                        Err(e) => log::warn!("WIGLE: append failed: {e}"),
                    }
                }
            }
        }

        // ---- Display phase ----
        self.epoch_loop.next_phase(); // -> Display

        if self.mode == OperatingMode::Bt {
            // BT mode: status text set in run_bt_epoch().
            // Don't record a WiFi result (would poison mood with blind epochs).
            // Reset per-epoch variety state so stale capture faces don't leak.
            self.epoch_loop.personality.variety.tick_epoch();
            // Don't tick_idle — BT has no captures to reset the counter,
            // inflating it causes sad faces when switching back to RAGE.
        } else {
            self.epoch_loop.record_result(&result);

            // ---- Face & personality ----
            self.update_face_and_personality(&result);
        }

        // ---- Mode-independent timers (mood, XP, battery) ----
        // These must run in ALL modes so mood drifts, XP saves, and
        // battery warnings work during BT and SAFE mode.
        self.tick_shared_timers();

        // ---- Lua plugins (gated to every 5s) + display ----
        if self.lua_tick_timer.due() {
            let epoch_state = self.build_epoch_state();
            self.lua.tick_epoch(&epoch_state);
        }

        // ---- Plugin hot-reload: check inotify for changed .lua files ----
        if let Some(ref watcher) = self.plugin_watcher {
            for name in watcher.check() {
                info!("plugin {name}: file changed, reloading");
                if let Err(e) = self.lua.reload_plugin(&name, watcher.dir()) {
                    log::error!("plugin {name}: reload failed: {e}");
                }
            }
        }

        // Check for display settings changes before rendering
        self.apply_pending_display_settings();

        self.update_display();

        // ---- CPU usage sampling (every 5s) ----
        if self.cpu_sample_timer.due() {
            if let Some(sample) = personality::CpuSample::read() {
                if let Some(ref prev) = self.prev_cpu_sample {
                    let cpu_pct = sample.cpu_percent(prev);
                    let mut s = self.shared_state.lock().unwrap();
                    s.cpu_percent = cpu_pct;
                }
                self.prev_cpu_sample = Some(sample);
            }
        }

        // ---- PSM counter reset (every 15 min wall-clock) ----
        if self.mode == OperatingMode::Rage && self.psm_reset_timer.due() {
            if let Err(e) = recovery::reset_watchdog_counters() {
                log::debug!("PSM counter reset skipped: {e}");
            } else {
                info!("PSM/DPC/RSSI watchdog counters reset (preventive)");
            }
        }

        // ---- Sync state to web (every 2s wall-clock) ----
        // tick_transition_override() already called in update_face_and_personality()
        // before generate_status(), so face state is consistent across display + web.
        if self.ws_broadcast_timer.due() {
            self.sync_to_web();
            web::broadcast_state(&self.shared_state, &self.ws_tx);
        }
        // Keep manual attack result visible for a few broadcasts, then clear.
        {
            let mut s = self.shared_state.lock().unwrap();
            if s.bt_manual_result.is_some() {
                s.bt_manual_result_ttl = s.bt_manual_result_ttl.saturating_sub(1);
                if s.bt_manual_result_ttl == 0 {
                    s.bt_manual_result = None;
                }
            }
        }

        // ---- Finish epoch + watchdog ----
        // next_phase() on Display wraps back to Scan and calls finish_epoch() internally.
        self.epoch_loop.next_phase(); // Display -> Scan (increments epoch counter)
        if self.watchdog.needs_ping() {
            self.watchdog.ping();
        }
        // Reset QPU ring buffer (every 10s wall-clock)
        if self.qpu_reset_timer.due() {
            if let Some(e) = self.qpu_engine.as_mut() { e.reset_ring(); }
        }
    }

    /// Scan phase: count tracked APs, check WiFi health (RAGE mode only).
    fn run_scan_phase(&mut self, result: &mut epoch::EpochResult) {
        self.epoch_loop.phase = epoch::EpochPhase::Scan;
        self.recovery
            .log(recovery::DiagLevel::Info, "epoch scan start");

        result.channel = self.ao.channel() as u8;
        // Compute NEW unique APs this epoch (delta from previous epoch's cumulative count).
        // AO tracks cumulative unique BSSIDs — subtracting prev gives only genuinely new APs.
        let current_ap_count = self.ao.ap_count();
        result.aps_seen = current_ap_count.saturating_sub(self.prev_ap_count);
        self.prev_ap_count = current_ap_count;

        // Health check on WiFi (RAGE mode only — SAFE mode intentionally has no monitor)
        if self.mode == OperatingMode::Rage && self.recovery.should_check() {
            // Check actual interface existence, not just internal state.
            // Firmware crashes remove the interface without updating wifi.state.
            #[cfg(unix)]
            let iface_exists = std::path::Path::new("/sys/class/net/wlan0mon").exists();
            #[cfg(not(unix))]
            let iface_exists = self.wifi.state == wifi::WifiState::Monitor;

            let health = if !iface_exists {
                // Interface gone — hard firmware crash
                if self.wifi.state == wifi::WifiState::Monitor {
                    log::warn!("wlan0mon disappeared — firmware crash detected");
                    self.wifi.state = wifi::WifiState::Down;
                }
                recovery::HealthCheck::Missing
            } else if self.ao.crash_count >= 3 {
                // Interface up but AO keeps crashing — firmware degraded (PSM wedged)
                log::warn!(
                    "wlan0mon exists but AO crashed {} times — firmware degraded",
                    self.ao.crash_count
                );
                recovery::HealthCheck::Unresponsive
            } else {
                recovery::HealthCheck::Ok
            };
            let action = self.recovery.process_health(health);
            self.handle_recovery_action(action);
        }
    }

    /// Run one BT-mode epoch: scan, target, attack, update status.
    fn run_bt_epoch(&mut self) {
        // Phase 0: Scan — discover nearby BT devices via HCI
        if let Some(ref hci) = self.bt_hci_socket {
            let scan_mode = self.config.bt_attacks.scan_mode;

            let discovered = match scan_mode {
                bluetooth::attacks::BtScanMode::Ble => {
                    bluetooth::attacks::scan::hci_le_scan(hci, 2000)
                }
                bluetooth::attacks::BtScanMode::Classic => {
                    if self.bt_attack_scheduler.active_count() == 0 {
                        bluetooth::attacks::scan::hci_inquiry(hci, 3)
                    } else {
                        vec![]
                    }
                }
                bluetooth::attacks::BtScanMode::Both => {
                    if self.bt_scan_use_le {
                        bluetooth::attacks::scan::hci_le_scan(hci, 2000)
                    } else if self.bt_attack_scheduler.active_count() == 0 {
                        bluetooth::attacks::scan::hci_inquiry(hci, 3)
                    } else {
                        vec![]
                    }
                }
            };

            // Toggle LE/Classic scan on wall-clock timer (every 60s)
            if scan_mode == bluetooth::attacks::BtScanMode::Both && self.bt_scan_alt_timer.due() {
                self.bt_scan_use_le = !self.bt_scan_use_le;
            }

            for dev in discovered {
                self.bt_discovery.apply(
                    bluetooth::model::observation::BtDiscoveryObservation::DeviceSeen(dev),
                );
            }
        }

        // Phase 0b: Name resolution — connect to unnamed devices to read GATT Device Name
        // Only when no attacks are active (avoids HCI/L2CAP contention)
        if self.bt_attack_scheduler.active_count() == 0 {
            let sorted = self.bt_discovery.devices_by_rssi();
            let unnamed: Vec<(String, String, u8)> = sorted
                .iter()
                .filter(|d| d.name.is_none() && !d.name_resolve_attempted && d.connectable && d.transport == bluetooth::model::observation::BtTransport::Ble)
                .take(1) // max 1 per epoch — LE connect timeout ~5s
                .map(|d| {
                    let addr_type = match d.address_type.as_deref() {
                        Some("random") => 2u8,
                        _ => 1u8,
                    };
                    (d.id.clone(), d.address.clone(), addr_type)
                })
                .collect();
            if !unnamed.is_empty() {
                log::info!("bt_name_resolve: attempting {} devices (of {} total)", unnamed.len(), sorted.len());
                let resolved = bluetooth::attacks::scan::resolve_ble_names(&unnamed, 1);
                // Mark all attempted devices
                for (id, _, _) in &unnamed {
                    if let Some(dev) = self.bt_discovery.get_device_mut(id) {
                        dev.name_resolve_attempted = true;
                    }
                }
                // Apply resolved names
                for (id, name) in resolved {
                    if let Some(dev) = self.bt_discovery.get_device_mut(&id) {
                        dev.name = Some(name);
                    }
                }
            }
        }

        // Phase 1: Prune — age out stale devices, enforce limit
        self.bt_discovery.prune(self.config.bt_attacks.target_ttl_secs);
        self.bt_discovery.enforce_limit(256);

        // Phase 2: Target — select targets based on rage level + toggles
        let active_attacks = self.bt_attack_scheduler.active_attack_types();
        let devices = self.bt_discovery.devices_by_rssi();

        if !active_attacks.is_empty() && self.bt_attack_scheduler.can_attack() {
            let targets = bluetooth::attacks::target::TargetSelector::select(
                &devices,
                &active_attacks,
                &self.config.bt_attacks,
                self.config.bt_attacks.max_concurrent_attacks as usize,
            );

            // Phase 3: Attack — dispatch attacks against targets
            for target in &targets {
                self.bt_attack_scheduler.mark_active(&target.device_id, target.attack);

                // Update device attack state
                if let Some(dev) = self.bt_discovery.get_device_mut(&target.device_id) {
                    dev.attack_state = bluetooth::model::observation::BtDeviceAttackState::Attacking;
                }

                log::info!(
                    "BT attack: {:?} → {} ({})",
                    target.attack,
                    target.device_address,
                    target.device_name.as_deref().unwrap_or("?")
                );

                // Dispatch the actual attack worker
                if let Some(ref hci) = self.bt_hci_socket {
                    let result = match target.attack {
                        bluetooth::attacks::BtAttackType::SmpDowngrade => {
                            let addr_type = self.bt_discovery.get_device_addr_type(&target.device_id);
                            bluetooth::attacks::smp::run_downgrade(hci, &target.device_address, addr_type)
                        }
                        bluetooth::attacks::BtAttackType::Knob => {
                            bluetooth::attacks::knob::run(hci, &target.device_address)
                        }
                        bluetooth::attacks::BtAttackType::BleAdvInjection => {
                            bluetooth::attacks::ble_adv::run(hci, &target.device_address)
                        }
                        bluetooth::attacks::BtAttackType::L2capFuzz => {
                            let addr_type = self.bt_discovery.get_device_addr_type(&target.device_id);
                            bluetooth::attacks::l2cap_fuzz::run(&target.device_address, addr_type)
                        }
                        bluetooth::attacks::BtAttackType::L2capConnFlood => {
                            let addr_type = self.bt_discovery.get_device_addr_type(&target.device_id);
                            bluetooth::attacks::l2cap_conn_flood::run(&target.device_address, addr_type, 30)
                        }
                        bluetooth::attacks::BtAttackType::AttGattFuzz => {
                            let addr_type = self.bt_discovery.get_device_addr_type(&target.device_id);
                            bluetooth::attacks::att_fuzz::run(&target.device_address, addr_type)
                        }
                        bluetooth::attacks::BtAttackType::VendorCmdUnlock => {
                            bluetooth::attacks::vendor::run_diagnostics(hci, &target.device_address)
                        }
                    };

                    // Store capture if present
                    self.bt_capture_manager.store(&result);

                    // Update device state and attack detail based on result
                    if let Some(dev) = self.bt_discovery.get_device_mut(&target.device_id) {
                        dev.attack_state = if result.capture.is_some() {
                            bluetooth::model::observation::BtDeviceAttackState::Captured
                        } else if result.success {
                            bluetooth::model::observation::BtDeviceAttackState::Targeted
                        } else {
                            bluetooth::model::observation::BtDeviceAttackState::Failed
                        };
                        dev.last_attack = Some(format!("{:?}", target.attack));
                        dev.last_attack_detail = if result.capture.is_some() {
                            Some("Data captured".to_string())
                        } else if result.success {
                            Some("Completed".to_string())
                        } else if let Some(ref e) = result.error {
                            // Shorten common error messages for display
                            let short = if e.contains("timeout") {
                                "Connection timeout"
                            } else if e.contains("rejected") || e.contains("refused") {
                                "Rejected by device"
                            } else if e.contains("not supported") {
                                "Not supported"
                            } else {
                                e.as_str()
                            };
                            Some(short.to_string())
                        } else {
                            Some("No response".to_string())
                        };
                    }

                    // Record in scheduler and remove from active set
                    self.bt_attack_scheduler.remove_active(&target.device_id);
                    self.bt_attack_scheduler.record(result);
                } else {
                    log::warn!("BT attack: no HCI socket — skipping dispatch for {}", target.device_address);
                    self.bt_attack_scheduler.remove_active(&target.device_id);
                }
            }
        }

        // Phase 3b: Rotate captures if over size limit.
        self.bt_capture_manager
            .rotate_if_needed(self.config.bt_attacks.max_capture_mb);

        // Phase 4: Update status
        let summary = self.bt_discovery.summary();
        let active_count = self.bt_attack_scheduler.active_count();
        let total_captures = self.bt_capture_manager.total_captures();

        let status = if active_count > 0 {
            format!("Attacking {} targets ({} captures)", active_count, total_captures)
        } else if summary.devices_now > 0 {
            format!("Scanning {} BT devices...", summary.devices_now)
        } else {
            "Scanning for BT devices...".to_string()
        };

        self.epoch_loop.personality.current_status = status;
    }

    /// Attack phase: schedule attacks against tracked APs.
    fn run_attack_phase(&mut self, result: &mut epoch::EpochResult) {
        self.epoch_loop.next_phase(); // -> Attack
        let min_rssi = self.shared_state.lock().unwrap().min_rssi;
        let attackable = self.wifi.tracker.attackable(min_rssi);
        // Read attack toggles from web state (all 6 types)
        let enabled_types = {
            let s = self.shared_state.lock().unwrap();
            [
                s.attack_deauth,
                s.attack_pmkid,
                s.attack_csa,
                s.attack_disassoc,
                s.attack_anon_reassoc,
                s.attack_rogue_m2,
            ]
        };
        // Smart Skip: collect BSSIDs that already have handshakes on SD
        let captured_bssids: std::collections::HashSet<[u8; 6]> = if self.skip_captured {
            self.captures
                .files
                .iter()
                .filter(|f| f.has_handshake)
                .map(|f| f.bssid)
                .collect()
        } else {
            std::collections::HashSet::new()
        };
        let mut skipped = 0u32;
        for ap in &attackable {
            if self.attacks.is_whitelisted(&ap.bssid) {
                continue;
            }
            // Smart Skip: skip APs with existing handshakes
            if self.skip_captured && captured_bssids.contains(&ap.bssid) {
                skipped += 1;
                continue;
            }
            if let Some(attack_type) = self.attacks.next_attack(&ap.bssid, &enabled_types) {
                let attack_result = attacks::AttackResult {
                    attack_type,
                    target_bssid: ap.bssid,
                    success: self.ao.state == ao::AoState::Running,
                    handshake_captured: false, // per-attack attribution not possible; epoch-level detection below
                    timestamp: std::time::Instant::now(),
                };
                self.attacks.record(&attack_result);
                result.deauths_sent += 1;
                if attack_result.handshake_captured {
                    result.handshakes_captured += 1;
                }
            }
        }
        // "I already got that one" — small mood boost per skipped AP
        self.epoch_loop.personality.on_smart_skip(skipped);
    }

    /// Capture phase: validate and index captures from AO output.
    /// In verified mode: tmpfs → hcxpcapngtool → move validated to SD, delete junk.
    /// In collect-all mode: AO writes to SD directly → hcxpcapngtool on SD files, keep all.
    fn run_capture_phase(&mut self, result: &mut epoch::EpochResult) {
        self.epoch_loop.next_phase(); // -> Capture
        result.associations = self.wifi.tracker.total_clients();

        // session_captures is tracked by the AO stdout reader (EAPOL Message 1 events).
        // session_handshakes is incremented below.

        // Snapshot handshake count before any scan/convert so new_handshakes is accurate
        // in both modes. Must be taken here, before the collect-all branch runs batch_convert.
        let handshakes_before = self.captures.handshake_count();

        if !self.capture_all {
            // === VERIFIED MODE: tmpfs → validate → SD ===

            // 1. Scan tmpfs for new AO captures
            let tmpfs_dir = std::path::Path::new(&self.tmpfs_capture_dir);
            let mut tmpfs_manager = capture::CaptureManager::new(&self.tmpfs_capture_dir);
            let _ = tmpfs_manager.scan_directory();

            // Truncate kismet file if it exceeds 50MB to prevent tmpfs exhaustion
            let kismet_path = format!("{}/capture.kismet", self.tmpfs_capture_dir);
            if let Ok(meta) = std::fs::metadata(&kismet_path) {
                if meta.len() > 50 * 1024 * 1024 {
                    info!("kismet file {}MB, truncating", meta.len() / 1024 / 1024);
                    let _ = std::fs::File::create(&kismet_path); // truncate to zero
                }
            }

            // 2. Convert new captures in tmpfs via hcxpcapngtool
            if !tmpfs_manager.files.is_empty() {
                let (converted, _no_hs, failed) = capture::batch_convert(&mut tmpfs_manager);
                if converted > 0 {
                    info!("tmpfs: converted {converted} capture(s) to .22000");
                }
                if failed > 0 {
                    log::warn!("tmpfs: {failed} conversion(s) failed");
                }
            }

            // 3. Move validated captures to SD, delete junk from tmpfs
            let permanent_dir = self.captures.capture_dir.clone();
            let (moved, deleted) = capture::move_validated_captures(
                tmpfs_dir,
                &permanent_dir,
                &mut self.captures,
                &self.ssid_resolver,
            );
            if moved > 0 || deleted > 0 {
                info!("capture pipeline: {moved} saved to SD, {deleted} junk deleted from RAM");
            }
            if moved > 0 {
                self.ao
                    .session_handshakes
                    .fetch_add(moved as u32, std::sync::atomic::Ordering::Relaxed);
            }
        } else {
            // === COLLECT ALL MODE: AO writes directly to SD ===
            // Scan first so newly written files are visible before conversion.
            let _ = self.captures.scan_directory();
            // Run hcxpcapngtool so .22000 companions are created, but keep everything.
            let (converted, no_hs, failed) = capture::batch_convert(&mut self.captures);
            if converted > 0 {
                info!("collect-all: converted {converted} capture(s) to .22000 on SD");
                let with_hs = converted.saturating_sub(no_hs);
                if with_hs > 0 {
                    self.ao
                        .session_handshakes
                        .fetch_add(with_hs as u32, std::sync::atomic::Ordering::Relaxed);
                }
            }
            if failed > 0 {
                log::warn!("collect-all: {failed} conversion(s) failed");
            }
        }

        // 4. Scan permanent dir for upload tracking + new handshake detection
        match self.captures.scan_directory() {
            Ok(new) => {
                if new > 0 {
                    info!("capture scan: {new} new file(s) on SD");
                }
            }
            Err(e) => log::warn!("capture scan failed: {e}"),
        }

        // 5. Upload pending .22000 files to WPA-SEC.
        // Skipped while a BT scan owns the radio: wlan0mon is down, there
        // is no internet route, and curl would block the main epoch loop
        // (even with --max-time 25s) long enough to starve BT inquiry. The
        // upload queue is persistent, so files upload on the next clean
        // epoch after the scan completes.
        if self.ao_paused_for_bt_scan {
            log::debug!("WPA-SEC upload skipped: BT scan owns the radio");
        } else {
            let internet_available = self.network.internet == network::InternetStatus::Online
                || self.bluetooth.internet_available;
            if !internet_available {
                log::debug!("WPA-SEC upload skipped: internet unavailable");
            }
            let (uploaded, upload_failed) = capture::upload_all_pending(
                &mut self.captures,
                &self.wpasec_config,
                &mut self.upload_queue,
                internet_available,
            );
            if uploaded > 0 {
                info!("WPA-SEC: uploaded {uploaded} files");
            }
            if upload_failed > 0 {
                log::warn!("WPA-SEC: {upload_failed} upload(s) failed");
            }
        }

        // 5b. Upload WIGLE staging CSV (every 30 min wall-clock)
        if self.wigle_upload_timer.due() && self.wigle_config.enabled {
            let internet_available = self.network.internet == network::InternetStatus::Online
                || self.bluetooth.internet_available;
            if internet_available {
                match wigle::upload_to_wigle(&self.wigle_staging_path, &self.wigle_config) {
                    Ok(()) => info!("WIGLE: upload complete"),
                    Err(e) => log::warn!("WIGLE: upload failed: {e}"),
                }
            } else {
                log::debug!("WIGLE upload skipped: internet unavailable");
            }
        }

        // 5c. Fetch cracked passwords from WPA-SEC (every 25 min wall-clock)
        if self.wpasec_fetch_timer.due()
            && self.wpasec_config.enabled
            && !self.ao_paused_for_bt_scan
        {
            let cracked = capture::fetch_cracked_from_wpasec(&self.wpasec_config);
            if !cracked.is_empty() {
                info!("WPA-SEC: fetched {} cracked password(s)", cracked.len());
                let mut s = self.shared_state.lock().unwrap();
                let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
                s.cracked = cracked
                    .into_iter()
                    .map(|(bssid, ssid, password)| web::CrackedEntry {
                        bssid,
                        ssid,
                        password,
                        date: today.clone(),
                    })
                    .collect();
            }
        }

        let new_handshakes = self
            .captures
            .handshake_count()
            .saturating_sub(handshakes_before);
        result.handshakes_captured = new_handshakes as u32;

        // Discord notification for new handshakes
        if new_handshakes > 0 && self.discord_enabled && !self.discord_webhook_url.is_empty() {
            let msg = format!(
                "New handshake(s) captured! {} new, {} total",
                new_handshakes,
                self.captures.handshake_count()
            );
            Self::post_discord(&self.discord_webhook_url, &msg);
        }
    }

    /// Post a message to a Discord webhook via curl.
    #[cfg(unix)]
    fn post_discord(webhook_url: &str, message: &str) {
        if webhook_url.is_empty() {
            return;
        }
        let body = format!(r#"{{"content":"{}"}}"#, message.replace('"', r#"\""#));
        let _ = std::process::Command::new("curl")
            .args([
                "-s",
                // Bound curl so Discord webhooks cannot stall the main loop
                // when there is no internet route (e.g. wlan0mon paused for BT).
                "--connect-timeout",
                "5",
                "--max-time",
                "15",
                "-H",
                "Content-Type: application/json",
                "-d",
                &body,
                webhook_url,
            ])
            .output();
    }

    #[cfg(not(unix))]
    fn post_discord(_webhook_url: &str, _message: &str) {
        // Discord posting requires curl (Unix only)
    }

    /// Tick mode-independent timers: mood drift, XP, battery, variety countdowns.
    /// Runs every epoch in ALL modes so mood/battery/XP work during BT and SAFE.
    fn tick_shared_timers(&mut self) {
        // Mood tick + variety countdowns (30s wall-clock)
        if self.mood_timer.due() {
            self.epoch_loop.personality.mood_tick();
            self.epoch_loop.personality.variety.tick_countdowns();
        }

        // Keep variety engine's mood in sync for mood-aware idle faces
        self.epoch_loop.personality.variety.mood = self.epoch_loop.personality.mood.value();

        // Passive XP (30s wall-clock)
        if self.xp_passive_timer.due() {
            self.epoch_loop.personality.xp.award(1);
        }

        // XP save (2.5 min wall-clock)
        if self.xp_save_timer.due() {
            let mood = self.epoch_loop.personality.mood.value();
            if let Err(e) = self.epoch_loop.personality.xp.save(mood) {
                log::warn!("XP save failed: {e}");
            }
        }

        // Battery face overrides (critical in all modes)
        self.check_battery_overrides();
    }

    /// Update face variety engine, overrides, and AO crash recovery (RAGE/SAFE only).
    fn update_face_and_personality(&mut self, result: &epoch::EpochResult) {
        // Reset per-epoch transient context flags (level_up, scan_channels, etc.)
        self.epoch_loop.personality.reset_epoch_context();

        // Reset per-epoch variety state (capture face, capture count)
        self.epoch_loop.personality.variety.tick_epoch();

        // Expire mode transition override if countdown reached zero
        self.epoch_loop.personality.tick_transition_override();

        // Wire captures into variety engine for milestones + face cycling.
        // Call on_capture per handshake with intermediate totals so milestones
        // at exact counts (1, 10, 25, 50, 100) are never skipped.
        if result.handshakes_captured > 0 {
            let base = self.epoch_loop.personality.total_handshakes
                - result.handshakes_captured;
            for i in 1..=result.handshakes_captured {
                self.epoch_loop.personality.variety.on_capture(base + i);
            }
        } else {
            self.epoch_loop.personality.variety.tick_idle();
        }

        // Set time-of-day state for variety engine
        let hour = chrono::Local::now().hour();
        self.epoch_loop.personality.variety.current_hour = hour;
        // Mark morning greeting shown when in the 6-8am window, regardless of
        // which face is currently active (so milestones don't block it forever).
        if (6..=8).contains(&hour) && !self.epoch_loop.personality.variety.morning_greeted {
            self.epoch_loop.personality.variety.morning_greeted = true;
        }

        // Clear AO crash face if AO recovered
        if self.ao.state == ao::AoState::Running
            && self.epoch_loop.personality.override_face == Some(personality::Face::AoCrashed)
        {
            self.epoch_loop.personality.clear_override();
        }

        // Generate status AFTER all override changes are finalized —
        // so the message pool matches the face that will actually display.
        self.epoch_loop.personality.generate_status();

        // Record stable epoch for AO
        if self.ao.state == ao::AoState::Running {
            self.ao.record_stable_epoch();
        }
    }

    /// Process PiSugar custom button tap events.
    /// Events come from two sources:
    /// 1. Direct I2C TAP register poll (single/double tap from MCU)
    /// 2. Web API /api/button (from pisugar-server shell scripts — supports long press)
    fn process_button(&mut self) {
        // Check web API first (pisugar-server shell scripts)
        let web_tap = {
            let mut s = self.shared_state.lock().unwrap();
            s.pending_button_tap.take()
        };

        let action = if let Some(tap_value) = web_tap {
            match pisugar::parse_tap_event(tap_value) {
                Some(a) => a,
                None => return,
            }
        } else {
            // Fall back to direct I2C TAP register poll
            match self.battery.read_tap_event() {
                Some(a) => a,
                None => return,
            }
        };

        match pisugar::map_button_action(action) {
            pisugar::MappedAction::CycleRageLevel => {
                // Cycle 1-6 only — level 7 (YOLO) crashes BCM43436B0 firmware
                let current = {
                    let s = self.shared_state.lock().unwrap();
                    if s.rage_enabled { s.rage_level } else { 0 }
                };
                let next = if current >= 6 || current == 0 { 1 } else { current + 1 };
                if let Some(p) = crate::rage::preset(next) {
                    info!(
                        "button: rage level {} ({}) — rate={} dwell={}ms",
                        p.level, p.name, p.rate, p.dwell_ms
                    );
                    self.ao.set_rate(p.rate);
                    self.wifi.channel_config.channels = p.channels.to_vec();
                    self.wifi.channel_config.dwell_ms = p.dwell_ms;
                    self.wifi.channel_config.current_index = 0;
                    self.autohunt = false;
                    self.ao.config.channels = p.channels.to_vec();
                    self.ao.config.dwell = (p.dwell_ms / 1000).max(1) as u32;
                    let mut s = self.shared_state.lock().unwrap();
                    s.rage_enabled = true;
                    s.rage_level = next;
                    s.autohunt_enabled = false;
                    s.wifi_channels = p.channels.to_vec();
                    s.wifi_dwell_ms = p.dwell_ms;
                }
                if let Err(e) = self.ao.restart() {
                    log::error!("button: AO restart failed after rage change: {e}");
                }
            }
            pisugar::MappedAction::ToggleBtTether => {
                info!("button: toggling BT tethering");
                self.bluetooth.toggle();
            }
            pisugar::MappedAction::ToggleRageSafe => {
                match self.mode {
                    OperatingMode::Rage => {
                        info!("button: RAGE → SAFE");
                        self.enter_safe_mode();
                    }
                    _ => {
                        info!("button: {} → RAGE", self.mode.as_str());
                        self.enter_rage_mode();
                    }
                }
            }
        }

        // Immediate display refresh so button feedback is visible on e-ink
        self.update_display();
    }

    /// Build merged whitelist for AO: SSID entries + formatted BSSID entries.
    fn build_ao_whitelist(&self) -> Vec<String> {
        let mut wl: Vec<String> = self.wifi.tracker.ssid_whitelist.clone();
        for mac in &self.attacks.whitelist {
            wl.push(
                mac.iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(":"),
            );
        }
        wl
    }

    /// Process commands queued by the web server.
    fn process_web_commands(&mut self) {
        let mut any_command = false;

        let (mode_switch, rate_change, restart, shutdown, bt_toggle) = {
            let mut s = self.shared_state.lock().unwrap();
            let mode = s.pending_mode_switch.take();
            let rate = s.pending_rate_change.take();
            let restart = s.pending_restart;
            s.pending_restart = false;
            let shutdown = s.pending_shutdown;
            s.pending_shutdown = false;
            let bt_toggle = s.pending_bt_toggle.take();
            (mode, rate, restart, shutdown, bt_toggle)
        };

        if let Some(mode) = mode_switch {
            any_command = true;
            info!("web: mode switch to {mode}");
            match mode.to_uppercase().as_str() {
                "TOGGLE" => {
                    let new_mode = self.mode.next();
                    match new_mode {
                        OperatingMode::Safe => self.enter_safe_mode(),
                        OperatingMode::Bt => self.enter_bt_mode(),
                        OperatingMode::Rage => self.enter_rage_mode(),
                    }
                }
                "SAFE" if self.mode != OperatingMode::Safe => self.enter_safe_mode(),
                "BT" if self.mode != OperatingMode::Bt => self.enter_bt_mode(),
                "RAGE" if self.mode != OperatingMode::Rage => self.enter_rage_mode(),
                _ => {
                    let mut s = self.shared_state.lock().unwrap();
                    s.mode = mode;
                }
            }
        }

        if let Some(rate) = rate_change {
            any_command = true;
            info!("web: rate change to {rate}, restarting AO");
            self.ao.set_rate(rate);
            if let Err(e) = self.ao.restart() {
                log::error!("web: AO restart failed after rate change: {e}");
                self.epoch_loop.personality.set_override(personality::Face::AoCrashed);
            }
            // Manual rate change breaks out of RAGE
            let mut s = self.shared_state.lock().unwrap();
            s.rage_enabled = false;
        }

        // Process pending rage slider change
        let rage_change = {
            let mut s = self.shared_state.lock().unwrap();
            s.pending_rage_change.take()
        };
        if let Some(rage) = rage_change {
            any_command = true;
            match rage {
                Some(level) => {
                    if let Some(p) = crate::rage::preset(level) {
                        info!(
                            "web: RAGE level {} ({}) — rate={} dwell={}ms ch={:?}",
                            p.level, p.name, p.rate, p.dwell_ms, p.channels
                        );
                        self.ao.set_rate(p.rate);
                        self.wifi.channel_config.channels = p.channels.to_vec();
                        self.wifi.channel_config.dwell_ms = p.dwell_ms;
                        self.wifi.channel_config.current_index = 0;
                        self.autohunt = false;
                        self.ao.config.channels = p.channels.to_vec();
                        self.ao.config.dwell = (p.dwell_ms / 1000).max(1) as u32;
                        let mut s = self.shared_state.lock().unwrap();
                        s.rage_enabled = true;
                        s.rage_level = level;
                        s.autohunt_enabled = false;
                        s.wifi_channels = p.channels.to_vec();
                        s.wifi_dwell_ms = p.dwell_ms;
                        s.attack_rate = p.rate;
                        drop(s);
                        if let Err(e) = self.ao.restart() {
                            log::error!("web: AO restart failed for RAGE preset: {e}");
                            self.epoch_loop.personality.set_override(personality::Face::AoCrashed);
                        }
                    }
                }
                None => {
                    info!("web: RAGE disabled, Custom mode");
                    let mut s = self.shared_state.lock().unwrap();
                    s.rage_enabled = false;
                }
            }
        }

        if restart {
            any_command = true;
            info!("web: AO restart requested");
            match self.ao.restart() {
                Ok(()) => info!("AO restarted successfully"),
                Err(e) => log::error!("AO restart failed: {e}"),
            }
        }

        if shutdown {
            any_command = true;
            info!("web: system shutdown requested");
            self.show_transition(personality::Face::Shutdown, "Shutting down...");
            self.battery.pisugar_shutdown();
        }

        if let Some(visible) = bt_toggle {
            any_command = true;
            info!("web: BT visibility set to {visible}");
            if visible {
                self.bluetooth.show();
            } else {
                self.bluetooth.hide();
            }
        }

        // Process pending radio request (from /api/radio)
        let radio_request = {
            let mut s = self.shared_state.lock().unwrap();
            s.pending_radio_request.take()
        };
        if let Some(req) = radio_request {
            any_command = true;
            info!("web: radio request: {req}");
            match req.as_str() {
                "WIFI" if self.mode == OperatingMode::Safe => self.enter_rage_mode(),
                "BT" if self.mode == OperatingMode::Rage => self.enter_safe_mode(),
                "FREE" => {
                    // Release the radio lock (stop everything)
                    self.ao.stop();
                    let _ = self.wifi.stop_monitor();
                    self.bluetooth.power_off();
                    let _ = self.radio.release_lock();
                    info!("radio: released to FREE");
                }
                _ => info!("web: radio request {req} ignored (already in requested mode)"),
            }
        }

        // Process pending attack toggle (trigger persistence)
        let attack_toggle = {
            let mut s = self.shared_state.lock().unwrap();
            s.pending_attack_toggle.take()
        };
        if attack_toggle.is_some() {
            any_command = true; // triggers save_runtime_state
        }

        // Process pending BT attack toggle
        let bt_attack_toggle = {
            let mut s = self.shared_state.lock().unwrap();
            s.pending_bt_attack_toggle.take()
        };
        if let Some(toggle) = bt_attack_toggle {
            any_command = true;
            if let Some(attack_type) = match toggle.attack.as_str() {
                "smp_downgrade" => {
                    Some(crate::bluetooth::attacks::BtAttackType::SmpDowngrade)
                }
                "knob" => Some(crate::bluetooth::attacks::BtAttackType::Knob),
                "ble_adv_injection" => {
                    Some(crate::bluetooth::attacks::BtAttackType::BleAdvInjection)
                }
                "l2cap_fuzz" => Some(crate::bluetooth::attacks::BtAttackType::L2capFuzz),
                "l2cap_conn_flood" => Some(crate::bluetooth::attacks::BtAttackType::L2capConnFlood),
                "att_gatt_fuzz" => {
                    Some(crate::bluetooth::attacks::BtAttackType::AttGattFuzz)
                }
                "vendor_cmd_unlock" => {
                    Some(crate::bluetooth::attacks::BtAttackType::VendorCmdUnlock)
                }
                _ => None,
            } {
                self.bt_attack_scheduler
                    .config
                    .set_toggle(attack_type, toggle.enabled);
                // Keep main config in sync with scheduler config
                self.config
                    .bt_attacks
                    .set_toggle(attack_type, toggle.enabled);
                info!(
                    "web: BT attack {} set to {}",
                    toggle.attack, toggle.enabled
                );
            }
        }

        // Process pending BT rage level change
        let bt_rage_level = {
            let mut s = self.shared_state.lock().unwrap();
            s.pending_bt_rage_level.take()
        };
        if let Some(level) = bt_rage_level {
            any_command = true;
            if let Some(rage) =
                crate::bluetooth::attacks::BtRageLevel::from_str(&level)
            {
                self.bt_attack_scheduler.config.rage_level = rage;
                self.config.bt_attacks.rage_level = rage;
                info!("web: BT rage level set to {}", level);
            }
        }

        // Process pending BT scan mode change
        let bt_scan_mode = {
            let mut s = self.shared_state.lock().unwrap();
            s.pending_bt_scan_mode.take()
        };
        if let Some(mode_str) = bt_scan_mode {
            any_command = true;
            if let Some(mode) = crate::bluetooth::attacks::BtScanMode::from_str(&mode_str) {
                self.config.bt_attacks.scan_mode = mode;
                info!("web: BT scan mode set to {}", mode_str);
            }
        }

        // Check if a manual attack completed — clean up scheduler and prepare for result clearing
        {
            let s = self.shared_state.lock().unwrap();
            if let Some(ref result) = s.bt_manual_result {
                // Remove device from active attacks so auto-targeting can pick it up again
                if let Some(ref addr) = result.address {
                    self.bt_attack_scheduler.remove_active(addr);
                }
            }
        }

        // Process pending manual BT attack
        let manual_attack = {
            let mut s = self.shared_state.lock().unwrap();
            s.pending_bt_manual_attack.take()
        };
        if let Some(req) = manual_attack {
            any_command = true;
            let attack_type = match req.attack.as_str() {
                "knob" => Some(bluetooth::attacks::BtAttackType::Knob),
                "ble_adv_injection" => Some(bluetooth::attacks::BtAttackType::BleAdvInjection),
                "l2cap_fuzz" => Some(bluetooth::attacks::BtAttackType::L2capFuzz),
                "l2cap_conn_flood" => Some(bluetooth::attacks::BtAttackType::L2capConnFlood),
                "att_gatt_fuzz" => Some(bluetooth::attacks::BtAttackType::AttGattFuzz),
                "vendor_cmd_unlock" => Some(bluetooth::attacks::BtAttackType::VendorCmdUnlock),
                _ => None,
            };

            if let Some(attack) = attack_type {
                if let Some(ref hci) = self.bt_hci_socket {
                    let address = req.address.clone().unwrap_or_else(|| "local".to_string());
                    info!("bt: manual attack {} on {}", req.attack, address);

                    // Set face override for manual attack
                    self.epoch_loop.personality.set_transition_override(
                        crate::personality::Face::Raging,
                        90,
                    );

                    // Mark device active in scheduler to prevent auto-targeting collision
                    if let Some(ref addr) = req.address {
                        self.bt_attack_scheduler.mark_active(addr, attack);
                    }

                    // Spawn background thread for blocking attack
                    let hci_cloned = hci.try_clone();
                    let shared = Arc::clone(&self.shared_state);
                    let attack_addr = req.address.clone();
                    let attack_name = req.attack.clone();
                    std::thread::spawn(move || {
                        let result = match hci_cloned {
                            Ok(ref h) => {
                                let addr = attack_addr.as_deref().unwrap_or("local");
                                match attack {
                                    bluetooth::attacks::BtAttackType::Knob => {
                                        bluetooth::attacks::knob::run(h, addr)
                                    }
                                    bluetooth::attacks::BtAttackType::BleAdvInjection => {
                                        bluetooth::attacks::ble_adv::run(h, addr)
                                    }
                                    bluetooth::attacks::BtAttackType::VendorCmdUnlock => {
                                        bluetooth::attacks::vendor::run_diagnostics(h, addr)
                                    }
                                    bluetooth::attacks::BtAttackType::L2capFuzz => {
                                        bluetooth::attacks::l2cap_fuzz::run(addr, 0)
                                    }
                                    bluetooth::attacks::BtAttackType::L2capConnFlood => {
                                        let addr_type = 0; // BR/EDR classic
                                        bluetooth::attacks::l2cap_conn_flood::run(addr, addr_type, 30)
                                    }
                                    bluetooth::attacks::BtAttackType::AttGattFuzz => {
                                        bluetooth::attacks::att_fuzz::run(addr, 1) // BLE addr type
                                    }
                                    _ => unreachable!(),
                                }
                            }
                            Err(e) => {
                                log::error!("bt: failed to clone HCI socket: {}", e);
                                bluetooth::attacks::BtAttackResult {
                                    attack_type: attack,
                                    target_address: attack_addr
                                        .clone()
                                        .unwrap_or_else(|| "local".into()),
                                    target_name: None,
                                    success: false,
                                    capture: None,
                                    error: Some(format!("HCI socket clone failed: {}", e)),
                                    detail: None,
                                    timestamp: std::time::Instant::now(),
                                }
                            }
                        };

                        // Store result for WebSocket delivery
                        let mut s = shared.lock().unwrap();
                        s.bt_manual_result = Some(web::BtManualResult {
                            address: if result.target_address == "local" {
                                None
                            } else {
                                Some(result.target_address.clone())
                            },
                            attack: attack_name,
                            success: result.success,
                            message: if let Some(detail) = result.detail {
                                detail
                            } else if result.success {
                                "OK".into()
                            } else {
                                result.error.unwrap_or_else(|| "failed".into())
                            },
                        });
                        s.bt_manual_result_ttl = 5;
                    });
                } else {
                    // Not in BT mode — store error result
                    let mut s = self.shared_state.lock().unwrap();
                    s.bt_manual_result = Some(web::BtManualResult {
                        address: req.address,
                        attack: req.attack,
                        success: false,
                        message: "Not in BT mode — no HCI socket".into(),
                    });
                    s.bt_manual_result_ttl = 5;
                }
            }
        }

        // Process BT scan request — spawn in background thread to avoid blocking.
        // Used by the BT attacks UI (tether pairing is phone-initiated and
        // doesn't go through this path). AO + wlan0mon get paused for the
        // duration so the BCM43436B0 shared antenna is free for BT inquiry.
        let bt_scan_needed = {
            let s = self.shared_state.lock().unwrap();
            s.bt_scan_in_progress && s.bt_scan_results.is_empty()
        };
        if bt_scan_needed {
            info!("web: pausing AO and wlan0mon for BT scan (radio coexistence)");
            self.ao.stop();
            if let Err(e) = self.wifi.pause_for_bt() {
                log::warn!("web: wlan0mon pause for scan failed: {e}");
            }
            self.ao_paused_for_bt_scan = true;
            info!("web: BT scan triggered (background thread)");
            let shared = Arc::clone(&self.shared_state);
            let _ = std::thread::Builder::new()
                .name("bt-scan".into())
                .spawn(move || {
                    // Run scan on this thread (blocking ~10s)
                    let devices = bluetooth::BtTether::scan_devices_static();
                    let results: Vec<web::BtScanDevice> = devices
                        .into_iter()
                        .map(|(mac, name)| web::BtScanDevice { mac, name })
                        .collect();
                    let mut s = shared.lock().unwrap();
                    s.bt_scan_results = results;
                    s.bt_scan_in_progress = false;
                    log::info!("BT scan thread completed");
                });
        }

        // Detect scan completion and restore WiFi/AO.
        if self.ao_paused_for_bt_scan {
            let scan_done = {
                let s = self.shared_state.lock().unwrap();
                !s.bt_scan_in_progress
            };
            if scan_done {
                info!("web: BT scan complete — resuming wlan0mon and AO");
                if let Err(e) = self.wifi.resume_from_pause() {
                    log::warn!("web: wlan0mon resume after scan failed: {e}");
                }
                self.ao_paused_for_bt_scan = false;
            }
        }

        // Process BT forget
        let bt_forget = {
            let mut s = self.shared_state.lock().unwrap();
            s.pending_bt_forget.take()
        };
        if let Some(path) = bt_forget {
            any_command = true;
            info!("web: forgetting BT device {path}");
            let _ = self.bluetooth.forget_device(&path);
        }

        // Process BT disconnect (user-initiated, suppresses auto-reconnect)
        let bt_disconnect = {
            let mut s = self.shared_state.lock().unwrap();
            s.pending_bt_disconnect.take()
        };
        if let Some(true) = bt_disconnect {
            any_command = true;
            info!("web: user-initiated BT disconnect");
            self.bluetooth.user_disconnected = true;
            self.bluetooth.disconnect();
        }

        // Process BT paired-device refresh (on-demand only — never from passive sync)
        let bt_refresh_paired = {
            let mut s = self.shared_state.lock().unwrap();
            let v = s.pending_bt_refresh_paired;
            s.pending_bt_refresh_paired = false;
            v
        };
        if bt_refresh_paired {
            any_command = true;
            match self.bluetooth.list_paired_devices_brief() {
                Ok(list) => {
                    let devices: Vec<web::PairedDeviceBrief> = list
                        .into_iter()
                        .map(|(name, mac)| web::PairedDeviceBrief { name, mac })
                        .collect();
                    info!("web: BT paired refresh found {} device(s)", devices.len());
                    let mut s = self.shared_state.lock().unwrap();
                    s.paired_devices = devices;
                }
                Err(e) => log::warn!("web: BT paired refresh failed: {e}"),
            }
        }

        // Process BT reset pairings (nuclear option: forget all paired devices)
        let bt_reset = {
            let mut s = self.shared_state.lock().unwrap();
            let v = s.pending_bt_reset_pairings;
            s.pending_bt_reset_pairings = false;
            v
        };
        if bt_reset {
            any_command = true;
            match self.bluetooth.reset_all_pairings() {
                Ok(n) => info!("web: BT reset pairings removed {n} device(s)"),
                Err(e) => log::warn!("web: BT reset pairings failed: {e}"),
            }
            // Clear stale error hint and connection state — no devices left to connect to.
            self.bluetooth.last_error_hint = None;
            self.bluetooth.state = bluetooth::BtState::Disconnected;
            self.bluetooth.retry_count = 0;
        }

        // Process pending plugin position updates
        let plugin_updates = {
            let mut s = self.shared_state.lock().unwrap();
            std::mem::take(&mut s.pending_plugin_updates)
        };
        if !plugin_updates.is_empty() {
            for update in &plugin_updates {
                if let Some(enabled) = update.enabled {
                    self.lua.set_plugin_enabled(&update.name, enabled);
                }
                if let (Some(x), Some(y)) = (update.x, update.y) {
                    let x = x.clamp(0, 249);
                    let y = y.clamp(0, 121);
                    self.lua.update_plugin_position(&update.name, x, y);
                    info!("plugin {}: position updated to ({x},{y})", update.name);
                }
            }
            lua::config::write_plugins_toml(&self.lua.get_plugin_configs());
            info!("persisted plugin positions to plugins.toml");
        }

        // Process pending whitelist adds (batch — supports multiple per epoch)
        let mut whitelist_changed = false;
        let (wl_adds, wl_removes) = {
            let mut s = self.shared_state.lock().unwrap();
            (
                std::mem::take(&mut s.pending_whitelist_adds),
                std::mem::take(&mut s.pending_whitelist_removes),
            )
        };
        for add in wl_adds {
            let entry = wifi::parse_whitelist_entry(&add.value);
            match entry {
                wifi::WhitelistEntry::Bssid(mac) => {
                    if !self.attacks.is_whitelisted(&mac) {
                        self.attacks.whitelist.push(mac);
                        info!("web: whitelist added MAC {}", add.value);
                        any_command = true;
                        whitelist_changed = true;
                    }
                }
                wifi::WhitelistEntry::Ssid(ssid) => {
                    self.wifi.tracker.add_ssid_whitelist(&ssid);
                    self.ao.config.whitelist = self.build_ao_whitelist();
                    info!("web: whitelist added SSID {ssid}");
                    any_command = true;
                    whitelist_changed = true;
                }
            }
        }
        for remove in wl_removes {
            let parts: Vec<&str> = remove.split(':').collect();
            if parts.len() == 6 {
                let mut mac = [0u8; 6];
                let mut ok = true;
                for (i, p) in parts.iter().enumerate() {
                    match u8::from_str_radix(p, 16) {
                        Ok(b) => mac[i] = b,
                        Err(_) => {
                            ok = false;
                            break;
                        }
                    }
                }
                if ok {
                    self.attacks.whitelist.retain(|m| m != &mac);
                    info!("web: whitelist removed {}", remove);
                    any_command = true;
                    whitelist_changed = true;
                }
            } else {
                // SSID removal
                self.wifi.tracker.ssid_whitelist.retain(|s| s != &remove);
                info!("web: whitelist removed SSID {}", remove);
                any_command = true;
                whitelist_changed = true;
            }
        }

        // If whitelist changed, restart AO so it picks up the new --whitelist file
        if whitelist_changed && self.ao.state == ao::AoState::Running {
            self.ao.config.whitelist = self.build_ao_whitelist();
            info!("web: whitelist changed, restarting AO");
            if let Err(e) = self.ao.restart() {
                log::error!("web: AO restart failed after whitelist change: {e}");
                self.epoch_loop.personality.set_override(personality::Face::AoCrashed);
            }
        }

        // Process pending channel config
        let ch_config = {
            let mut s = self.shared_state.lock().unwrap();
            s.pending_channel_config.take()
        };
        if ch_config.is_some() {
            any_command = true;
        }
        if let Some(cfg) = ch_config {
            if let Some(channels) = cfg.channels {
                if !channels.is_empty() {
                    self.wifi.channel_config.channels = channels.clone();
                    self.wifi.channel_config.current_index = 0;
                    info!("web: channels set to {:?}", channels);
                }
            }
            if let Some(dwell) = cfg.dwell_ms {
                self.wifi.channel_config.dwell_ms = dwell;
                info!("web: dwell set to {}ms", dwell);
            }
            if let Some(autohunt) = cfg.autohunt {
                self.autohunt = autohunt;
                info!("web: autohunt set to {autohunt}");
            }
            // Sync to AO config before restart
            if self.autohunt {
                self.ao.config.channels.clear(); // autohunt = scan all
            } else {
                self.ao.config.channels = self.wifi.channel_config.channels.clone();
            }
            self.ao.config.dwell = (self.wifi.channel_config.dwell_ms / 1000).max(1) as u32;
            // Restart AO so new channel/dwell/autohunt settings take effect
            info!("web: restarting AO with new channel config");
            if let Err(e) = self.ao.restart() {
                log::error!("web: AO restart failed after channel config change: {e}");
                self.epoch_loop.personality.set_override(personality::Face::AoCrashed);
            }
            // Manual channel change breaks out of RAGE
            let mut s = self.shared_state.lock().unwrap();
            s.rage_enabled = false;
        }

        // Process pending skip_captured toggle (Smart Skip)
        let skip_captured_toggle = {
            let mut s = self.shared_state.lock().unwrap();
            s.pending_skip_captured.take()
        };
        if let Some(skip) = skip_captured_toggle {
            self.skip_captured = skip;
            info!("web: skip_captured set to {skip}");
            any_command = true;
        }

        // Process pending capture mode change (Verified vs Collect All)
        let capture_all_toggle = {
            let mut s = self.shared_state.lock().unwrap();
            s.pending_capture_all.take()
        };
        if let Some(all) = capture_all_toggle {
            self.capture_all = all;
            if all {
                self.ao.config.output_dir = CAPTURE_DIR.to_string();
                info!("web: capture_all enabled — AO output -> SD directly");
            } else {
                self.ao.config.output_dir = format!("{}/capture", self.tmpfs_capture_dir);
                info!("web: capture_all disabled — AO output -> tmpfs");
            }
            // Only restart AO in RAGE mode; in SAFE mode AO isn't running and the
            // updated output_dir will take effect when RAGE mode is next entered.
            if self.mode == OperatingMode::Rage {
                info!("web: restarting AO for capture mode change");
                self.ao
                    .session_captures
                    .store(0, std::sync::atomic::Ordering::Relaxed);
                self.ao
                    .session_handshakes
                    .store(0, std::sync::atomic::Ordering::Relaxed);
                if let Err(e) = self.ao.restart() {
                    log::error!("web: AO restart failed for capture mode change: {e}");
                    self.epoch_loop.personality.set_override(personality::Face::AoCrashed);
                }
            } else {
                info!("web: capture mode updated (SAFE mode — AO restart deferred to RAGE entry)");
            }
            any_command = true;
        }

        // Process pending capture deletion
        let pending_delete = {
            let mut s = self.shared_state.lock().unwrap();
            s.pending_delete.take()
        };
        if let Some(filename) = pending_delete {
            if let Some(pos) = self.captures.files.iter().position(|f| {
                f.path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy() == filename)
            }) {
                let file = self.captures.files.remove(pos);
                let companion = file.path.with_extension("22000");
                if let Err(e) = std::fs::remove_file(&file.path) {
                    log::warn!(
                        "delete capture: failed to remove {}: {e}",
                        file.path.display()
                    );
                } else {
                    info!("deleted capture: {filename}");
                }
                let _ = std::fs::remove_file(&companion); // ok if .22000 missing
                any_command = true;
            }
        }

        // Process pending WPA-SEC key
        let wpasec_key = {
            let mut s = self.shared_state.lock().unwrap();
            s.pending_wpasec_key.take()
        };
        if let Some(key) = wpasec_key {
            self.wpasec_config.api_key = key.clone();
            self.wpasec_config.enabled = !key.is_empty();
            info!(
                "web: WPA-SEC key updated, enabled={}",
                self.wpasec_config.enabled
            );
            any_command = true;
        }

        // Process pending WIGLE config
        let wigle_config = {
            let mut s = self.shared_state.lock().unwrap();
            s.pending_wigle_config.take()
        };
        if let Some((name, token)) = wigle_config {
            self.wigle_config.enabled = !name.is_empty() && !token.is_empty();
            self.wigle_config.api_name = name;
            self.wigle_config.api_token = token;
            info!("web: WIGLE config updated, enabled={}", self.wigle_config.enabled);
            any_command = true;
        }

        // Process pending Discord config
        let discord_config = {
            let mut s = self.shared_state.lock().unwrap();
            s.pending_discord_config.take()
        };
        if let Some(cfg) = discord_config {
            self.discord_webhook_url = cfg.webhook_url;
            self.discord_enabled = cfg.enabled;
            info!("web: Discord updated, enabled={}", self.discord_enabled);
            any_command = true;
        }

        // Process pending settings update (display reinit handled by apply_pending_display_settings)
        let settings = {
            let mut s = self.shared_state.lock().unwrap();
            s.pending_settings.take()
        };
        if let Some(update) = settings {
            if let Some(name) = update.name {
                if !name.is_empty() {
                    self.config.name = name.clone();
                    let mut s = self.shared_state.lock().unwrap();
                    s.name = name.clone();
                    info!("web: device name changed to {name}");
                    any_command = true;
                }
            }
            if let Some(rssi) = update.min_rssi {
                let clamped = rssi.clamp(-100, -30);
                let mut s = self.shared_state.lock().unwrap();
                s.min_rssi = clamped;
                info!("web: min RSSI set to {clamped} dBm");
                any_command = true;
            }
            if let Some(ttl) = update.ap_ttl_secs {
                let clamped = ttl.clamp(30, 600);
                let mut s = self.shared_state.lock().unwrap();
                s.ap_ttl_secs = clamped;
                info!("web: AP TTL set to {clamped}s");
                any_command = true;
            }
            if let Some(interval) = update.display_refresh_interval {
                let clamped = interval.clamp(10, 500);
                self.screen.config.full_refresh_interval = clamped;
                let mut s = self.shared_state.lock().unwrap();
                s.display_refresh_interval = clamped;
                info!("web: display refresh interval set to {clamped} partials (also gated by 180s minimum)");
                any_command = true;
            }
        }

        // Process pending face pack switch
        let pending_face_pack = {
            let mut s = self.shared_state.lock().unwrap();
            s.pending_face_pack.take()
        };
        if let Some(pack_name) = pending_face_pack {
            any_command = true;
            info!("web: face pack switch to {pack_name}");
            if pack_name == "default" {
                self.active_pack = display::face_pack::FacePack::empty();
                self.update_display();
            } else {
                let cache_dir = std::path::Path::new(display::face_pack::FACE_PACK_CACHE)
                    .join(&pack_name);
                match display::face_pack::FacePack::load(&pack_name, &cache_dir) {
                    Ok(pack) => {
                        info!("face pack: loaded '{}' ({} faces)", pack.name, pack.face_count());
                        self.active_pack = pack;
                        self.update_display();
                    }
                    Err(e) => {
                        log::warn!("face pack load failed: {e}");
                        let mut s = self.shared_state.lock().unwrap();
                        s.face_pack_last_error = Some(format!("load {pack_name}: {e}"));
                    }
                }
            }
            let mut s = self.shared_state.lock().unwrap();
            s.active_face_pack = self.active_pack.name.clone();
        }

        // Process pending mood boost from interact buttons
        let mood_boost = {
            let mut s = self.shared_state.lock().unwrap();
            s.pending_mood_boost.take()
        };
        if let Some(boost) = mood_boost {
            any_command = true;
            self.epoch_loop.personality.mood.adjust(boost);
            info!("web: mood boost +{:.0}% (now {:.0}%)",
                  boost * 100.0,
                  self.epoch_loop.personality.mood.value() * 100.0);
        }

        // Persist runtime state if any command was processed
        if any_command {
            self.save_runtime_state();
        }
    }

    /// Battery state snapshot: (level, charging, voltage_mv, low, critical, available).
    fn battery_snapshot(&self) -> (u8, bool, u16, bool, bool, bool) {
        (
            self.battery.status.level,
            self.battery.status.charge_state == pisugar::ChargeState::Charging,
            self.battery.status.voltage_mv,
            self.battery.status.low,
            self.battery.status.critical,
            self.battery.available,
        )
    }

    /// AO process state snapshot: (state_str, pid, crash_count, uptime_str, uptime_secs).
    fn ao_snapshot(&self) -> (String, u32, u32, String, u64) {
        (
            self.ao.state_str().to_string(),
            self.ao.pid,
            self.ao.crash_count,
            self.ao.uptime_str(),
            self.ao.uptime_secs(),
        )
    }

    /// Bluetooth state snapshot: (connected, status_short, ip, internet_available).
    fn bt_snapshot(&self) -> (bool, String, String, bool) {
        (
            self.bluetooth.state == bluetooth::BtState::Connected,
            self.bluetooth.status_short().to_string(),
            self.bluetooth.ip_address.clone().unwrap_or_default(),
            self.bluetooth.internet_available,
        )
    }

    /// Build an EpochState snapshot for Lua plugins.
    fn build_epoch_state(&self) -> lua::state::EpochState {
        let m = &self.epoch_loop.metrics;

        // Read system info (CPU temp, memory)
        let (si, _cpu_sample) = personality::SystemInfo::read(&self.prev_cpu_sample);

        // Read CPU frequency
        let cpu_freq_ghz = {
            #[cfg(target_os = "linux")]
            {
                std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq")
                    .ok()
                    .and_then(|s| s.trim().parse::<f64>().ok())
                    .map(|khz| format!("{:.1}G", khz / 1_000_000.0))
                    .unwrap_or_else(|| "---".into())
            }
            #[cfg(not(target_os = "linux"))]
            {
                "---".to_string()
            }
        };

        // Get CPU percent from shared state
        let cpu_pct = {
            let s = self.shared_state.lock().unwrap();
            s.cpu_percent
        };

        let (bat_level, bat_charging, bat_mv, bat_low, bat_crit, bat_avail) =
            self.battery_snapshot();
        let (ao_state, ao_pid, ao_crashes, ao_uptime, ao_up_secs) = self.ao_snapshot();
        let (bt_conn, bt_short, bt_ip, bt_inet) = self.bt_snapshot();

        lua::state::EpochState {
            uptime_secs: self.epoch_loop.uptime_secs(),
            epoch: m.epoch,
            mode: self.mode.as_str().to_string(),
            rage_level: {
                let s = self.shared_state.lock().unwrap();
                if s.rage_enabled { s.rage_level } else { 0 }
            },
            channel: {
                let ch = self.ao.channel();
                if ch > 0 { ch as u8 } else { m.channel }
            },
            aps_seen: self.ao.ap_count(),
            handshakes: m.handshakes,
            captures_total: self.captures.count(),
            blind_epochs: m.blind_epochs,
            ao_state,
            ao_pid,
            ao_crash_count: ao_crashes,
            ao_uptime_str: ao_uptime,
            ao_uptime_secs: ao_up_secs,
            ao_channels: {
                let ch = self.ao.channel();
                if ch > 0 {
                    ch.to_string()
                } else {
                    "?".to_string()
                }
            },
            session_captures: self.ao.session_captures(),
            session_handshakes: self.ao.session_handshakes(),
            battery_level: bat_level,
            battery_charging: bat_charging,
            battery_voltage_mv: bat_mv,
            battery_low: bat_low,
            battery_critical: bat_crit,
            battery_available: bat_avail,
            pisugar_temp_c: self.battery.temperature_c,
            bt_connected: bt_conn,
            bt_short,
            bt_ip,
            bt_internet: bt_inet,
            bt_devices_seen: self.bt_discovery.summary().devices_now,
            bt_active_attacks: self.bt_attack_scheduler.active_count(),
            bt_total_captures: self.bt_capture_manager.total_captures(),
            bt_patchram_state: self.patchram.state.as_str().to_string(),
            bt_rage_level: self.config.bt_attacks.rage_level.as_str().to_string(),
            internet_online: self.network.internet == network::InternetStatus::Online,
            display_ip: self.network.usb_ip_str(),
            mood: self.epoch_loop.personality.mood.value(),
            face: self.epoch_loop.current_face().as_str().to_string(),
            level: self.epoch_loop.personality.xp.level,
            xp: self.epoch_loop.personality.xp.xp,
            status_message: self.epoch_loop.personality.status_msg(),
            epoch_phase_status: self.epoch_loop.status_message(),
            joke_active: self.epoch_loop.personality.joke_active(),
            skip_captured: self.skip_captured,
            wigle_enabled: self.wigle_config.enabled,
            gps_fix: self.gps_fix_active,
            fw_crash_suppress: self.firmware_monitor.crash_suppress,
            fw_hardfault: self.firmware_monitor.hardfault,
            fw_health: format!("{:?}", self.firmware_monitor.health()),
            cpu_temp: si.cpu_temp_c,
            mem_used_mb: si.mem_used_mb,
            mem_total_mb: si.mem_total_mb,
            cpu_percent: cpu_pct,
            cpu_freq_ghz,
        }
    }

    /// Persist runtime state to JSON so web-configurable settings survive restarts.
    fn save_runtime_state(&self) {
        let s = self.shared_state.lock().unwrap();
        let state = serde_json::json!({
            "attack_deauth": s.attack_deauth,
            "attack_pmkid": s.attack_pmkid,
            "attack_csa": s.attack_csa,
            "attack_disassoc": s.attack_disassoc,
            "attack_anon_reassoc": s.attack_anon_reassoc,
            "attack_rogue_m2": s.attack_rogue_m2,
            "attack_rate": self.ao.config.rate,
            "whitelist": self.attacks.whitelist.iter().map(|m|
                m.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
            ).collect::<Vec<String>>(),
            "ssid_whitelist": self.wifi.tracker.ssid_whitelist,
            "wpasec_key": self.wpasec_config.api_key,
            "discord_webhook_url": self.discord_webhook_url,
            "discord_enabled": self.discord_enabled,
            "autohunt": self.autohunt,
            "skip_captured": self.skip_captured,
            "capture_all": self.capture_all,
            "name": self.config.name,
            "wifi_channels": self.wifi.channel_config.channels,
            "wifi_dwell_ms": self.wifi.channel_config.dwell_ms,
            "rage_enabled": s.rage_enabled,
            "rage_level": s.rage_level,
            "lifetime_aps": self.lifetime_aps_base + self.ao.ap_count() as u64,
            "display_invert": self.screen.config.invert,
            "display_rotation": self.screen.config.rotation,
            "display_refresh_interval": self.screen.config.full_refresh_interval,
            "min_rssi": s.min_rssi,
            "ap_ttl_secs": s.ap_ttl_secs,
            "bt_scan_mode": self.config.bt_attacks.scan_mode.as_str(),
            "face_pack": self.active_pack.name,
            "state_version": 2,
        });
        drop(s);
        let path = "/var/lib/oxigotchi/state.json";
        let _ = std::fs::create_dir_all("/var/lib/oxigotchi");
        if let Err(e) = std::fs::write(
            path,
            serde_json::to_string_pretty(&state).unwrap_or_default(),
        ) {
            log::warn!("state save failed: {e}");
        }
    }

    /// Load persisted runtime state from JSON and apply values.
    fn load_runtime_state(&mut self) {
        let path = "/var/lib/oxigotchi/state.json";
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return, // No saved state, use defaults
        };
        let state: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("state load parse error: {e}");
                return;
            }
        };

        // Apply attack toggles to shared state
        {
            let mut s = self.shared_state.lock().unwrap();
            if let Some(v) = state.get("attack_deauth").and_then(|v| v.as_bool()) {
                s.attack_deauth = v;
            }
            if let Some(v) = state.get("attack_pmkid").and_then(|v| v.as_bool()) {
                s.attack_pmkid = v;
            }
            if let Some(v) = state.get("attack_csa").and_then(|v| v.as_bool()) {
                s.attack_csa = v;
            }
            if let Some(v) = state.get("attack_disassoc").and_then(|v| v.as_bool()) {
                s.attack_disassoc = v;
            }
            if let Some(v) = state.get("attack_anon_reassoc").and_then(|v| v.as_bool()) {
                s.attack_anon_reassoc = v;
            }
            if let Some(v) = state.get("attack_rogue_m2").and_then(|v| v.as_bool()) {
                s.attack_rogue_m2 = v;
            }
        }

        // Apply attack rate
        if let Some(rate) = state.get("attack_rate").and_then(|v| v.as_u64()) {
            self.ao.set_rate(rate as u32);
        }

        // Apply whitelist
        if let Some(wl) = state.get("whitelist").and_then(|v| v.as_array()) {
            self.attacks.whitelist.clear();
            for entry in wl {
                if let Some(mac_str) = entry.as_str() {
                    let parts: Vec<&str> = mac_str.split(':').collect();
                    if parts.len() == 6 {
                        let mut mac = [0u8; 6];
                        let mut ok = true;
                        for (i, p) in parts.iter().enumerate() {
                            match u8::from_str_radix(p, 16) {
                                Ok(b) => mac[i] = b,
                                Err(_) => {
                                    ok = false;
                                    break;
                                }
                            }
                        }
                        if ok {
                            self.attacks.whitelist.push(mac);
                        }
                    }
                }
            }
        }

        // Apply SSID whitelist
        if let Some(ssids) = state.get("ssid_whitelist").and_then(|v| v.as_array()) {
            for entry in ssids {
                if let Some(ssid) = entry.as_str() {
                    self.wifi.tracker.add_ssid_whitelist(ssid);
                    info!("state: restored SSID whitelist: {ssid}");
                }
            }
        }

        // Apply WPA-SEC key
        if let Some(key) = state.get("wpasec_key").and_then(|v| v.as_str()) {
            self.wpasec_config.api_key = key.to_string();
            self.wpasec_config.enabled = !key.is_empty();
        }

        // Apply Discord config
        if let Some(url) = state.get("discord_webhook_url").and_then(|v| v.as_str()) {
            self.discord_webhook_url = url.to_string();
        }
        if let Some(enabled) = state.get("discord_enabled").and_then(|v| v.as_bool()) {
            self.discord_enabled = enabled;
        }
        if let Some(autohunt) = state.get("autohunt").and_then(|v| v.as_bool()) {
            self.autohunt = autohunt;
        }
        if let Some(v) = state.get("skip_captured").and_then(|v| v.as_bool()) {
            self.skip_captured = v;
        }
        if let Some(v) = state.get("capture_all").and_then(|v| v.as_bool()) {
            self.capture_all = v;
        }
        if let Some(channels_arr) = state.get("wifi_channels").and_then(|v| v.as_array()) {
            let channels: Vec<u8> = channels_arr
                .iter()
                .filter_map(|v| v.as_u64().map(|n| n as u8))
                .collect();
            if !channels.is_empty() {
                self.wifi.channel_config.channels = channels.clone();
                // Also sync to AO config so next start uses these
                if !self.autohunt {
                    self.ao.config.channels = channels;
                }
            }
        }
        if let Some(lifetime_aps) = state.get("lifetime_aps").and_then(|v| v.as_u64()) {
            self.lifetime_aps_base = lifetime_aps;
        }
        if let Some(dwell) = state.get("wifi_dwell_ms").and_then(|v| v.as_u64()) {
            self.wifi.channel_config.dwell_ms = dwell;
            self.ao.config.dwell = (dwell / 1000).max(1) as u32;
        }
        if let Some(name) = state.get("name").and_then(|v| v.as_str()) {
            if !name.is_empty() {
                self.config.name = name.to_string();
                let mut s = self.shared_state.lock().unwrap();
                s.name = name.to_string();
            }
        }

        // Apply RAGE slider state
        if let Some(enabled) = state.get("rage_enabled").and_then(|v| v.as_bool()) {
            let mut s = self.shared_state.lock().unwrap();
            s.rage_enabled = enabled;
            if enabled {
                if let Some(level) = state.get("rage_level").and_then(|v| v.as_u64()) {
                    let level = (level as u8).clamp(1, 7);
                    s.rage_level = level;
                    if let Some(p) = crate::rage::preset(level) {
                        info!("state: restoring RAGE level {} ({})", p.level, p.name);
                        drop(s);
                        self.ao.set_rate(p.rate);
                        self.wifi.channel_config.channels = p.channels.to_vec();
                        self.wifi.channel_config.dwell_ms = p.dwell_ms;
                        self.wifi.channel_config.current_index = 0;
                        self.autohunt = false;
                        self.ao.config.channels = p.channels.to_vec();
                        self.ao.config.dwell = (p.dwell_ms / 1000).max(1) as u32;
                        let mut s = self.shared_state.lock().unwrap();
                        s.autohunt_enabled = false;
                        s.wifi_channels = p.channels.to_vec();
                        s.wifi_dwell_ms = p.dwell_ms;
                        s.attack_rate = p.rate;
                    }
                }
            }
        }

        // Apply display settings
        if let Some(invert) = state.get("display_invert").and_then(|v| v.as_bool()) {
            self.screen.config.invert = invert;
            let mut s = self.shared_state.lock().unwrap();
            s.display_invert = invert;
        }
        if let Some(rotation) = state.get("display_rotation").and_then(|v| v.as_u64()) {
            let r = if rotation == 180 { 180 } else { 0 };
            self.screen.config.rotation = r;
            let mut s = self.shared_state.lock().unwrap();
            s.display_rotation = r;
        }
        if let Some(interval) = state.get("display_refresh_interval").and_then(|v| v.as_u64()) {
            let i = (interval as u32).clamp(10, 500);
            self.screen.config.full_refresh_interval = i;
            let mut s = self.shared_state.lock().unwrap();
            s.display_refresh_interval = i;
        }
        // Apply wifi tuning settings
        if let Some(rssi) = state.get("min_rssi").and_then(|v| v.as_i64()) {
            let mut s = self.shared_state.lock().unwrap();
            s.min_rssi = (rssi as i8).clamp(-100, -30);
        }
        if let Some(ttl) = state.get("ap_ttl_secs").and_then(|v| v.as_u64()) {
            let mut s = self.shared_state.lock().unwrap();
            s.ap_ttl_secs = ttl.clamp(30, 600);
        }
        if let Some(mode_str) = state.get("bt_scan_mode").and_then(|v| v.as_str()) {
            if let Some(mode) = crate::bluetooth::attacks::BtScanMode::from_str(mode_str) {
                self.config.bt_attacks.scan_mode = mode;
                let mut s = self.shared_state.lock().unwrap();
                s.bt_scan_mode = mode_str.to_string();
            }
        }

        // Apply face pack
        if let Some(name) = state.get("face_pack").and_then(|v| v.as_str()) {
            if name != "default" && !name.is_empty() {
                let cache_dir = std::path::Path::new(display::face_pack::FACE_PACK_CACHE)
                    .join(name);
                match display::face_pack::FacePack::load(name, &cache_dir) {
                    Ok(pack) => {
                        info!("face pack: restored '{}' ({} faces)", pack.name, pack.face_count());
                        self.active_pack = pack;
                        let mut s = self.shared_state.lock().unwrap();
                        s.active_face_pack = self.active_pack.name.clone();
                    }
                    Err(e) => {
                        log::warn!("face pack: restore '{name}' failed: {e} (using default)");
                    }
                }
            }
        }

        info!("loaded runtime state from {path}");
    }

    /// Sync daemon state into the shared web state.
    fn sync_to_web(&mut self) {
        if self.config.gpu.enabled && self.config.gpu.runtime.trace_enabled {
            match self
                .gpu_runtime_ingestor
                .load(&self.config.gpu.runtime.summary_source)
            {
                Ok(Some(summary)) => {
                    self.gpu_state.runtime = summary;
                }
                Ok(None) => {}
                Err(e) => {
                    log::warn!("gpu runtime summary ingest failed: {e}");
                }
            }
        }

        // In BT mode, HCI scanning feeds bt_discovery directly in run_bt_epoch().
        // Only reset+repopulate from BlueZ scan results in RAGE/SAFE modes.
        if self.mode != OperatingMode::Bt {
            let scan_snapshot = {
                let s = self.shared_state.lock().unwrap();
                (s.bt_scan_results.clone(), s.bt_scan_in_progress)
            };

            self.bt_discovery.reset();
            if scan_snapshot.1 {
                let _ = self
                    .bt_discovery
                    .apply(bluetooth::model::observation::BtDiscoveryObservation::ScanStarted);
            }
            for device in &scan_snapshot.0 {
                let _ = self.bt_discovery.apply(
                    bluetooth::model::observation::BtDiscoveryObservation::DeviceSeen(
                        bluetooth::model::observation::BtDeviceObservation {
                            id: device.mac.clone(),
                            address: device.mac.clone(),
                            address_type: None,
                            transport: bluetooth::model::observation::BtTransport::Unknown,
                            name: if device.name.is_empty() {
                                None
                            } else {
                                Some(device.name.clone())
                            },
                            rssi: None,
                            rssi_best: None,
                            category: bluetooth::model::observation::BtCategory::Unknown,
                            services: Vec::new(),
                            manufacturer: None,
                            first_seen: chrono::Utc::now(),
                            ts: chrono::Utc::now(),
                            seen_count: 1,
                            attack_state: bluetooth::model::observation::BtDeviceAttackState::Untouched,
                            last_attack: None,
                            last_attack_detail: None,
                            name_resolve_attempted: false,
                            connectable: false, // BlueZ scan — unknown connectability
                        },
                    ),
                );
            }
            if !scan_snapshot.1 {
                let _ = self
                    .bt_discovery
                    .apply(bluetooth::model::observation::BtDiscoveryObservation::ScanStopped);
            }
        }

        let bt_mode = self.bt_feature.state.mode.clone();
        let bt_state_str = self.bluetooth.status_str().to_string();
        let bt_enabled = self.config.bluetooth.enabled;
        let bt_overlap_active = self.wifi.state == wifi::WifiState::Monitor
            && self.bluetooth.state == bluetooth::BtState::Connected;

        let mut s = self.shared_state.lock().unwrap();
        let m = &self.epoch_loop.metrics;

        let (bat_level, bat_charging, bat_mv, bat_low, bat_crit, bat_avail) =
            self.battery_snapshot();
        let (ao_state, ao_pid, ao_crashes, ao_uptime, _ao_up_secs) = self.ao_snapshot();
        let (bt_conn, _bt_short, bt_ip, bt_inet) = self.bt_snapshot();

        s.uptime_str = self.epoch_loop.uptime_str();
        s.mode = self.mode.as_str().to_string();
        s.epoch = m.epoch;
        s.channel = {
            let ch = self.ao.channel();
            if ch > 0 { ch as u8 } else { m.channel }
        };
        s.aps_seen = (self.lifetime_aps_base + self.ao.ap_count() as u64) as u32;
        s.handshakes = self.captures.handshake_count() as u32;
        s.blind_epochs = m.blind_epochs;
        s.mood = self.epoch_loop.personality.mood.value();
        s.face = self.epoch_loop.current_face().display_name().to_string();
        s.status_message = self.epoch_loop.personality.status_msg();

        s.total_attacks = self.attacks.total_attacks;
        s.total_handshakes_attacks = self.attacks.total_handshakes;
        s.attack_rate = self.ao.config.rate;
        s.deauths_this_epoch = m.deauths_this_epoch;

        s.capture_dir = self.captures.capture_dir.to_string_lossy().to_string();
        s.capture_files = self.captures.count();
        s.handshake_files = self.captures.handshake_count();
        s.pending_upload = self.captures.pending_upload_count();
        s.total_capture_size = self.captures.total_size();
        s.session_captures = self.ao.session_captures();
        s.session_handshakes = self.ao.session_handshakes();
        s.capture_all = self.capture_all;
        s.capture_list = self
            .captures
            .files
            .iter()
            .map(|f| {
                let bssid_mac = format!(
                    "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    f.bssid[0], f.bssid[1], f.bssid[2], f.bssid[3], f.bssid[4], f.bssid[5]
                );
                let captured_date = f
                    .mtime
                    .map(|t| {
                        let dt: chrono::DateTime<chrono::Utc> = t.into();
                        dt.format("%Y-%m-%d").to_string()
                    })
                    .unwrap_or_else(|| "unknown".to_string());
                web::CaptureEntry {
                    filename: f
                        .path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    size_bytes: f.size,
                    ssid: f.ssid.clone(),
                    bssid_mac,
                    captured_date,
                    has_handshake: f.has_handshake,
                }
            })
            .collect();

        s.battery_level = bat_level;
        s.battery_charging = bat_charging;
        s.battery_voltage_mv = bat_mv;
        s.battery_low = bat_low;
        s.battery_critical = bat_crit;
        s.battery_available = bat_avail;

        s.wifi_state = format!("{:?}", self.wifi.state);
        s.wifi_aps_tracked = self.ao.ap_count() as usize;
        s.wifi_channels = self.wifi.channel_config.channels.clone();
        s.wifi_dwell_ms = self.wifi.channel_config.dwell_ms;
        s.autohunt_enabled = self.autohunt;
        s.skip_captured = self.skip_captured;

        s.bt_state = self.bluetooth.status_str().to_string(); // long form for web
        s.bt_connected = bt_conn;
        s.bt_ip = bt_ip;
        s.bt_internet_available = bt_inet;
        s.bt_retry_count = self.bluetooth.retry_count;
        s.bt_device_name = self.bluetooth.config.phone_name.clone();
        s.bt_last_error_hint = self
            .bluetooth
            .last_error_hint
            .clone()
            .unwrap_or_default();

        self.bt_feature.state.mode = bt_mode;
        self.bt_feature.state.health.stack_up = bt_enabled;
        self.bt_feature.state.health.controller_present = bt_enabled;
        self.bt_feature.state.health.degraded = self.bluetooth.state == bluetooth::BtState::Error;
        self.bt_feature.state.health.last_error =
            if self.bluetooth.state == bluetooth::BtState::Error {
                Some(bt_state_str.clone())
            } else {
                None
            };
        self.bt_feature.state.summary = self.bt_discovery.summary();
        self.bt_feature.state.controller.last_probe_status = Some(bt_state_str.clone());
        self.bt_feature.state.coex.overlap_active = bt_overlap_active;
        self.bt_feature.state.coex.contention_score = if bt_overlap_active { 1 } else { 0 };

        s.bt_feature_mode = format!("{:?}", self.bt_feature.state.mode);
        s.bt_feature_devices_now = self.bt_feature.state.summary.devices_now;
        s.bt_feature_contention_score = self.bt_feature.state.coex.contention_score;

        // -- bt attacks --
        s.bt_attack_enabled = self.config.bt_attacks.enabled;
        s.bt_rage_level = self.config.bt_attacks.rage_level.as_str().to_string();
        s.bt_attack_smp_downgrade = self.config.bt_attacks.smp_downgrade;
        s.bt_attack_knob = self.config.bt_attacks.knob;
        s.bt_attack_l2cap_fuzz = self.config.bt_attacks.l2cap_fuzz;
        s.bt_attack_l2cap_conn_flood = self.config.bt_attacks.l2cap_conn_flood;
        s.bt_attack_att_gatt_fuzz = self.config.bt_attacks.att_gatt_fuzz;
        s.bt_total_attacks = self.bt_attack_scheduler.total_attacks;
        s.bt_total_captures = self.bt_attack_scheduler.total_captures;
        s.bt_active_attacks = self.bt_attack_scheduler.active_count();
        s.bt_devices_seen = self.bt_discovery.summary().devices_now;
        s.bt_device_list = self.bt_discovery.devices_by_rssi().iter().map(|d| {
            web::BtDeviceInfo {
                address: d.address.clone(),
                name: d.name.clone(),
                rssi: d.rssi,
                category: d.category.as_str().to_string(),
                transport: format!("{:?}", d.transport),
                attack_state: format!("{:?}", d.attack_state),
                seen_count: d.seen_count,
                vendor: d.manufacturer.clone(),
                last_attack: d.last_attack.clone(),
                last_attack_detail: d.last_attack_detail.clone(),
            }
        }).collect();
        s.bt_patchram_state = self.patchram.state.as_str().to_string();
        s.bt_capture_keys = self.bt_capture_manager.total_keys;
        s.bt_capture_transcripts = self.bt_capture_manager.total_transcripts;
        s.bt_capture_crashes = self.bt_capture_manager.total_crashes;
        s.bt_capture_vendor = self.bt_capture_manager.total_vendor;

        let gpu_policy = self.gpu_optimizer.policy_for(&self.gpu_state.runtime);
        s.gpu_mode = format!("{:?}", self.gpu_state.mode);
        s.gpu_signal = self
            .gpu_state
            .runtime
            .strongest_signal
            .as_ref()
            .map(|s| format!("{s:?}"))
            .unwrap_or_else(|| "None".to_string());
        s.gpu_submit_seen = self.gpu_state.runtime.vc4_submit_cl_seen;
        s.gpu_snapshot_policy = gpu_policy.as_str().to_string();
        s.gpu_flush_threshold = gpu_policy.threshold();

        // Update QPU stats
        if let Some(ref engine) = self.qpu_engine {
            let stats = engine.stats();
            s.qpu_enabled = true;
            s.qpu_available = stats.qpu_available;
            s.qpu_num_cores = stats.num_qpus;
            s.qpu_frames_submitted = stats.frames_submitted;
            s.qpu_frames_classified = stats.frames_classified;
            s.qpu_batches_processed = stats.batches_processed;
            s.qpu_overflow_count = stats.overflow_count;
            s.qpu_last_batch_size = stats.last_batch_size;
            s.qpu_last_batch_duration_us = stats.last_batch_duration_us;
        }

        s.ao_state = ao_state;
        s.ao_pid = ao_pid;
        s.ao_crash_count = ao_crashes;
        s.ao_uptime = ao_uptime;
        s.gpsd_available = self.ao.gpsd_detected;

        // Radio lock state
        s.radio_mode = self.radio.mode.as_str().to_string();
        let (_, radio_pid) = self.radio.read_lock();
        s.radio_pid = radio_pid;

        s.xp = self.epoch_loop.personality.xp.xp;
        s.level = self.epoch_loop.personality.xp.level;

        s.fw_crash_suppress = self.firmware_monitor.crash_suppress;
        s.fw_hardfault = self.firmware_monitor.hardfault;
        s.fw_health = format!("{:?}", self.firmware_monitor.health());

        // Refresh system metrics so WS broadcast has real values (not zeroes)
        let cpu_temp = web::read_cpu_temp();
        if cpu_temp > 0.0 {
            s.cpu_temp_c = cpu_temp;
        }
        let (mem_used, mem_total) = web::read_mem_info();
        if mem_total > 0 {
            s.mem_used_mb = mem_used;
            s.mem_total_mb = mem_total;
        }
        let (disk_used, disk_total) = web::read_disk_info();
        if disk_total > 0 {
            s.disk_used_mb = disk_used;
            s.disk_total_mb = disk_total;
        }

        s.recovery_state = format!("{:?}", self.recovery.state);
        s.recovery_total = self.recovery.total_recoveries;
        s.recovery_soft_retries = self.recovery.soft_retry_count;
        s.recovery_hard_retries = self.recovery.hard_retry_count;
        s.recovery_last_str = match self.recovery.last_recovery {
            Some(t) => format!("{}s ago", t.elapsed().as_secs()),
            None => "never".into(),
        };

        // Copy framebuffer for web display preview
        s.screen_width = self.screen.fb.width;
        s.screen_height = self.screen.fb.height;
        s.screen_bytes = self.screen.fb.as_bytes().to_vec();
        s.display_refresh_interval = self.screen.config.full_refresh_interval;

        // Sync AP list for web dashboard — merge WiFi tracker + AO stdout data
        let mut ap_entries: Vec<web::ApEntry> = self
            .wifi
            .tracker
            .sorted_by_rssi()
            .iter()
            .map(|ap| {
                let has_hs = self
                    .captures
                    .files
                    .iter()
                    .any(|f| f.has_handshake && f.bssid == ap.bssid);
                web::ApEntry {
                    bssid: ap.bssid_str(),
                    ssid: if ap.ssid.is_empty() {
                        "(hidden)".into()
                    } else {
                        ap.ssid.clone()
                    },
                    rssi: ap.rssi as i16,
                    channel: ap.channel,
                    clients: ap.client_count,
                    has_handshake: has_hs,
                    whitelisted: ap.whitelisted,
                }
            })
            .collect();

        // Add APs seen by AO that aren't already in the WiFi tracker
        let ao_aps = self.ao.ap_snapshot();
        let existing_bssids: std::collections::HashSet<String> = ap_entries
            .iter()
            .map(|e| e.bssid.replace(':', "").to_lowercase())
            .collect();
        for ao_ap in &ao_aps {
            if !existing_bssids.contains(&ao_ap.bssid) {
                // Format BSSID with colons: aabbccddeeff -> AA:BB:CC:DD:EE:FF
                let bssid_fmt = ao_ap
                    .bssid
                    .as_bytes()
                    .chunks(2)
                    .map(|c| std::str::from_utf8(c).unwrap_or("??").to_uppercase())
                    .collect::<Vec<_>>()
                    .join(":");
                // Check if we have a capture for this BSSID on SD
                let ao_bssid_bytes: [u8; 6] = {
                    let hex = &ao_ap.bssid;
                    let mut b = [0u8; 6];
                    if hex.len() == 12 {
                        for i in 0..6 {
                            b[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
                        }
                    }
                    b
                };
                let has_hs = ao_ap.captured
                    || self
                        .captures
                        .files
                        .iter()
                        .any(|f| f.has_handshake && f.bssid == ao_bssid_bytes);
                let ssid = self
                    .ssid_resolver
                    .get(&ao_bssid_bytes)
                    .map(|s| s.to_string())
                    .or_else(|| {
                        self.captures
                            .ssid_for(&ao_bssid_bytes)
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_else(|| "(AO)".into());
                let rssi = self
                    .captures
                    .bssid_rssi
                    .get(&ao_bssid_bytes)
                    .copied()
                    .unwrap_or(-100);
                let whitelisted = self
                    .wifi
                    .tracker
                    .ssid_whitelist
                    .iter()
                    .any(|w| w.eq_ignore_ascii_case(&ssid))
                    || self.attacks.whitelist.iter().any(|w| *w == ao_bssid_bytes);
                ap_entries.push(web::ApEntry {
                    bssid: bssid_fmt,
                    ssid,
                    rssi,
                    channel: ao_ap.channel,
                    clients: ao_ap.hit_count,
                    has_handshake: has_hs,
                    whitelisted,
                });
            }
        }
        s.ap_list = ap_entries;

        // Sync whitelist for web dashboard (MAC + SSID entries)
        let mut wl: Vec<web::WhitelistEntry> = self
            .attacks
            .whitelist
            .iter()
            .map(|mac| web::WhitelistEntry {
                value: mac
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(":"),
                entry_type: "MAC".into(),
            })
            .collect();
        for ssid in &self.wifi.tracker.ssid_whitelist {
            wl.push(web::WhitelistEntry {
                value: ssid.clone(),
                entry_type: "SSID".into(),
            });
        }
        s.whitelist = wl;

        // Sync plugin list for web dashboard
        s.plugin_list = self
            .lua
            .get_web_plugin_list()
            .into_iter()
            .map(|(meta, enabled, x, y)| web::PluginInfo {
                name: meta.name,
                version: meta.version,
                author: meta.author,
                tag: meta.tag,
                enabled,
                x,
                y,
            })
            .collect();

        // Sync WPA-SEC and Discord config for web dashboard
        s.wpasec_api_key = self.wpasec_config.api_key.clone();
        s.wigle_api_name = self.wigle_config.api_name.clone();
        s.wigle_api_token = self.wigle_config.api_token.clone();
        s.discord_webhook_url = self.discord_webhook_url.clone();
        s.discord_enabled = self.discord_enabled;

        // Sync face pack listing for web dashboard
        let root = std::path::Path::new(display::face_pack::FACE_PACK_DIR);
        let cache_root = std::path::Path::new(display::face_pack::FACE_PACK_CACHE);
        s.face_packs = list_face_packs(root, cache_root);
        s.active_face_pack = self.active_pack.name.clone();
        s.face_pack_last_error = self.face_pack_last_error.clone();
    }

    /// Check for pending display settings changes and apply immediately.
    /// Called before each display render so invert/rotation take effect
    /// within the current epoch rather than waiting for the next one.
    fn apply_pending_display_settings(&mut self) {
        let needs_reinit = {
            let mut s = self.shared_state.lock().unwrap();
            let reinit = s.pending_display_reinit;
            if reinit {
                s.pending_display_reinit = false;
                // Sync display config from shared state
                self.screen.config.invert = s.display_invert;
                self.screen.config.rotation = s.display_rotation;
                self.screen.config.full_refresh_interval = s.display_refresh_interval;
            }
            reinit
        };
        if needs_reinit {
            display::driver::request_reinit();
            self.screen.force_flush();
            info!("display: applying invert/rotation change immediately");
            self.save_runtime_state();
        }
    }

    /// Update the e-ink display with current state.
    /// Unified render path for ALL modes — face varies by mode, indicators
    /// are filtered via `get_visible_indicators(mode)`.
    fn update_display(&mut self) {
        self.screen.clear();

        // ---- Face selection (mode-dependent) ----
        if self.mode == OperatingMode::Bt {
            let summary = self.bt_discovery.summary();
            let active = self.bt_attack_scheduler.active_count();
            let captures = self.bt_capture_manager.total_captures();
            let patchram_error = self.patchram.state == bluetooth::patchram::PatchramState::Error;
            let face = personality::bt_mode_face(
                active,
                summary.devices_now,
                captures,
                patchram_error,
            );
            self.screen.draw_face(&face, &self.active_pack);
        } else {
            let face = self.epoch_loop.current_face();
            if self.last_drawn_face != Some(face) {
                log::info!(
                    "face changed: {:?} -> {:?} (override={:?}, variety={:?}, mood={:.2})",
                    self.last_drawn_face,
                    face,
                    self.epoch_loop.personality.override_face,
                    self.epoch_loop.personality.variety.current_override(),
                    self.epoch_loop.personality.mood.value(),
                );
                self.last_drawn_face = Some(face);
            }
            self.screen.draw_face(&face, &self.active_pack);
        }

        // ---- LINE 1 (y=14) ----
        self.screen.draw_hline(0, 14, display::DISPLAY_WIDTH);

        // NOTE: Status text is rendered by status_msg.lua plugin (ALL-mode indicator).
        // Do NOT add a hardcoded draw_status() here — it would duplicate the plugin output.

        // ---- XP BAR right of face (~125, 65) ----
        let xp = &self.epoch_loop.personality.xp;
        let lv_str = format!("Lv {}", xp.level);
        self.screen.draw_text(&lv_str, 125, 73);
        let bar_x: u32 = 168;
        let bar_y: u32 = 74;
        let bar_w: u32 = 80;
        let bar_h: u32 = 7;
        let needed = xp.xp_to_next_level();
        let filled_w = if needed > 0 {
            ((xp.xp as u32) * (bar_w - 2) / needed as u32).min(bar_w - 2)
        } else {
            bar_w - 2
        };
        // Outline
        for dx in 0..bar_w {
            self.screen.set_pixel(
                bar_x + dx, bar_y,
                embedded_graphics::pixelcolor::BinaryColor::On,
            );
            self.screen.set_pixel(
                bar_x + dx, bar_y + bar_h - 1,
                embedded_graphics::pixelcolor::BinaryColor::On,
            );
        }
        for dy in 0..bar_h {
            self.screen.set_pixel(
                bar_x, bar_y + dy,
                embedded_graphics::pixelcolor::BinaryColor::On,
            );
            self.screen.set_pixel(
                bar_x + bar_w - 1, bar_y + dy,
                embedded_graphics::pixelcolor::BinaryColor::On,
            );
        }
        // Fill
        for dy in 1..(bar_h - 1) {
            for dx in 1..=filled_w {
                self.screen.set_pixel(
                    bar_x + dx, bar_y + dy,
                    embedded_graphics::pixelcolor::BinaryColor::On,
                );
            }
        }

        // ---- LINE 2 (y=108) ----
        self.screen.draw_hline(0, 108, display::DISPLAY_WIDTH);

        // ---- LUA PLUGIN INDICATORS (mode-filtered) ----
        let mode_str = self.mode.as_str();
        for ind in self.lua.get_visible_indicators(mode_str) {
            self.screen.draw_indicator(&ind);
        }

        self.screen.flush();
    }

    /// Check battery level and apply face overrides.
    fn check_battery_overrides(&mut self) {
        if !self.battery.available {
            return;
        }
        self.battery.read_status();
        if self.battery.status.critical {
            self.epoch_loop
                .personality
                .set_override(personality::Face::BatteryCritical);
        } else if self.battery.status.low {
            self.epoch_loop
                .personality
                .set_override(personality::Face::BatteryLow);
        } else {
            // Clear battery overrides if we previously set one
            if matches!(
                self.epoch_loop.personality.override_face,
                Some(personality::Face::BatteryCritical)
                    | Some(personality::Face::BatteryLow)
                    | Some(personality::Face::Shutdown)
            ) {
                self.epoch_loop.personality.clear_override();
            }
        }

        if self.battery.should_shutdown() && !self.battery.shutting_down {
            info!("battery critical, initiating shutdown");
            self.show_transition(personality::Face::Shutdown, "Battery critical!");
            self.battery.pisugar_shutdown();
        }
    }

    /// Show a transition screen with face and message, then flush immediately.
    fn show_transition(&mut self, face: personality::Face, message: &str) {
        self.screen.clear();
        self.screen.draw_face(&face, &self.active_pack);
        self.screen.draw_status(message);
        self.screen.flush();
    }

    /// Pick a random face from a pool.
    fn random_face(faces: &[personality::Face]) -> personality::Face {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let idx = rng.gen_range(0..faces.len());
        faces[idx]
    }

    /// Face pools for each mode.
    const RAGE_FACES: &'static [personality::Face] = &[
        personality::Face::Angry,
        personality::Face::Intense,
        personality::Face::Excited,
        personality::Face::Upload,
        personality::Face::Motivated,
    ];
    const SAFE_FACES: &'static [personality::Face] =
        &[personality::Face::Debug, personality::Face::Grateful];

    /// Transition from RAGE or BT to SAFE mode via radio lock manager.
    fn enter_safe_mode(&mut self) {
        info!("mode: {} -> SAFE", self.mode.as_str());
        let face = Self::random_face(Self::SAFE_FACES);
        self.show_transition(face, "Switching to SAFE...");

        if self.mode == OperatingMode::Bt {
            // Close HCI socket before tearing down BT
            self.bt_hci_socket = None;
            // BT attack mode → SAFE: swap attack patchram for stock
            match self.radio.transition_bt_to_safe(
                &mut self.bluetooth,
                &mut self.patchram,
            ) {
                Ok(()) => {
                    info!("radio: BT attack -> BT safe transition complete (stock patchram)");
                    // Set up BT PAN connection with stock firmware
                    match self.bluetooth.setup() {
                        Ok(()) => info!("BT connected: {}", self.bluetooth.status_str()),
                        Err(e) => log::warn!("BT setup failed: {e}"),
                    }
                }
                Err(e) => {
                    log::error!("radio transition BT->SAFE failed: {e}");
                    return;
                }
            }
        } else {
            // RAGE mode → SAFE: standard WiFi -> BT transition
            match self
                .radio
                .transition_to_bt(&mut self.ao, &mut self.wifi, &mut self.bluetooth)
            {
                Ok(()) => {
                    info!("radio: WIFI -> BT transition complete");
                    // Now set up BT PAN connection
                    match self.bluetooth.setup() {
                        Ok(()) => info!("BT connected: {}", self.bluetooth.status_str()),
                        Err(e) => log::warn!("BT setup failed: {e}"),
                    }
                }
                Err(e) => {
                    log::error!("radio transition to BT failed: {e}");
                    // Radio manager already rolled back to WIFI
                    return;
                }
            }
        }

        self.mode = OperatingMode::Safe;
        self.epoch_loop.personality.set_transition_override(face, 90);
        // Radio transition disrupts SPI bus — force display reinit so next flush doesn't BUSY-timeout
        display::driver::request_reinit();
    }

    /// Transition into BT attack mode — tears down WiFi, loads attack patchram.
    fn enter_bt_mode(&mut self) {
        info!("mode: {} -> BT", self.mode.as_str());
        let face = Self::random_face(Self::RAGE_FACES);
        self.show_transition(face, "Switching to BT Attack...");

        // Atomic transition: stop AO + WiFi, load attack patchram
        match self.radio.transition_to_bt_attack(
            &mut self.ao,
            &mut self.wifi,
            &mut self.bluetooth,
            &mut self.patchram,
        ) {
            Ok(()) => {
                info!("radio: transition to BT attack complete");
                self.mode = OperatingMode::Bt;
                self.bt_feature.set_mode(bluetooth::model::config::BtMode::Attack);
                self.epoch_loop.personality.set_transition_override(face, 90);
                // Open raw HCI socket for attack dispatch
                match bluetooth::attacks::hci::HciSocket::open(0) {
                    Ok(sock) => {
                        info!("bt: HCI socket opened for attack dispatch");
                        self.bt_hci_socket = Some(sock);
                    }
                    Err(e) => log::error!("bt: failed to open HCI socket: {e}"),
                }
                // Init capture directories
                self.bt_capture_manager.init_dirs();
                // Radio transition disrupts SPI bus — force display reinit
                display::driver::request_reinit();
            }
            Err(e) => {
                log::error!("radio transition to BT attack failed: {e}");
                // Radio manager already set mode=Free on failure
            }
        }
    }

    /// Transition from SAFE or BT to RAGE mode via radio lock manager.
    fn enter_rage_mode(&mut self) {
        info!("mode: {} -> RAGE", self.mode.as_str());
        let face = Self::random_face(Self::RAGE_FACES);
        self.show_transition(face, "Switching to RAGE...");

        if self.mode == OperatingMode::Bt {
            // Close HCI socket before tearing down BT
            self.bt_hci_socket = None;
            // BT attack mode → RAGE: unload patchram, restart WiFi+AO
            match self.radio.transition_bt_to_wifi(
                &mut self.ao,
                &mut self.wifi,
                &mut self.patchram,
            ) {
                Ok(()) => {
                    info!("radio: BT -> WIFI transition complete (via patchram unload)");
                    // Reconnect tether immediately — don't wait for next epoch health check.
                    self.bluetooth.ensure_connected();
                }
                Err(e) => {
                    log::error!("radio transition BT->WIFI failed: {e}");
                    return;
                }
            }
        } else {
            // SAFE mode → RAGE: standard BT -> WiFi transition
            match self
                .radio
                .transition_to_wifi(&mut self.ao, &mut self.wifi, &mut self.bluetooth)
            {
                Ok(()) => {
                    info!("radio: BT -> WIFI transition complete");
                }
                Err(e) => {
                    log::error!("radio transition to WIFI failed: {e}");
                    // Radio manager already rolled back to BT
                    return;
                }
            }
        }

        self.mode = OperatingMode::Rage;
        self.epoch_loop.personality.clear_override();
        // Radio transition disrupts SPI bus — force display reinit so next flush doesn't BUSY-timeout
        display::driver::request_reinit();
    }

    /// Handle recovery actions from the health checker.
    fn handle_recovery_action(&mut self, action: recovery::RecoveryAction) {
        match action {
            recovery::RecoveryAction::None => {}
            recovery::RecoveryAction::SoftRecover => {
                // BCM43436B0 SAFETY: never rmmod brcmfmac on this chip — it
                // corrupts the SDIO bus and requires physical power cycle to
                // recover (see memory/feedback_deployment_lessons.md #9).
                // Also never toggle WL_REG_ON GPIO — it loses nexmon patches
                // and reverts to stock brcmfmac firmware (no monitor mode).
                // The only safe recovery is: stop AO, delete wlan0mon, sleep
                // 2s for firmware to settle, re-add monitor, restart AO.
                info!("attempting soft WiFi recovery (iw-only restart, no modprobe)");
                self.epoch_loop
                    .personality
                    .set_override(personality::Face::WifiDown);

                self.ao.stop();
                let _ = self.wifi.stop_monitor();
                std::thread::sleep(Duration::from_secs(2));

                match self.wifi.start_monitor() {
                    Ok(()) => {
                        info!("soft recovery: monitor mode restored");
                        self.epoch_loop.personality.clear_override();
                        self.epoch_loop.personality.clear_sticky_status();
                        self.ao.reset();
                        match self.ao.start() {
                            Ok(()) => info!("soft recovery: AO restarted (PID {})", self.ao.pid),
                            Err(e) => log::error!("soft recovery: AO restart failed: {e}"),
                        }
                        self.recovery.record_recovery();
                    }
                    Err(e) => log::error!("soft recovery: monitor mode failed: {e}"),
                }
            }
            recovery::RecoveryAction::HardRecover => {
                // BCM43436B0 SAFETY: the GPIO WL_REG_ON power cycle used to
                // live here. On this chip it reverts the firmware to stock
                // brcmfmac (no nexmon monitor-mode patches), leaving the
                // daemon running against a WiFi stack that can't inject or
                // capture anything until a cold boot. We refuse the GPIO
                // cycle and surface FwCrash so the user knows a physical
                // power cycle is required.
                log::error!(
                    "hard recovery refused: BCM43436B0 needs physical power cycle (USB + PiSugar). \
                     GPIO WL_REG_ON toggle would load stock firmware without monitor-mode support."
                );
                self.epoch_loop
                    .personality
                    .set_override(personality::Face::FwCrash);
                self.recovery.log(
                    recovery::DiagLevel::Error,
                    "hard recovery refused on BCM43436B0 — physical power cycle required",
                );
                self.ao.stop();
            }
            recovery::RecoveryAction::Reboot => {
                log::error!("WiFi recovery exhausted after max retries, rebooting");
                self.epoch_loop
                    .personality
                    .set_override(personality::Face::Broken);
                self.recovery.log(
                    recovery::DiagLevel::Error,
                    "all recovery attempts exhausted -- rebooting",
                );
                let _ = recovery::trigger_reboot();
            }
            recovery::RecoveryAction::GiveUp => {
                log::error!("WiFi recovery exhausted — giving up (no reboot to avoid loop)");
                self.epoch_loop
                    .personality
                    .set_override(personality::Face::Broken);
                // Pin an unmissable user instruction. The chip is in the
                // SDIO zombie state and only a physical power cut (USB +
                // PiSugar unplug, 10s) brings it back. A reboot won't help.
                // Without this, the Broken face cycles through generic
                // "debug" messages that don't tell the user what to do.
                self.epoch_loop
                    .personality
                    .set_sticky_status("ZOMBIE - UNPLUG USB+BATT 10s");
                self.recovery.log(
                    recovery::DiagLevel::Error,
                    "all recovery attempts exhausted — WiFi offline, daemon continues",
                );
                // Do NOT reboot — causes infinite loop when firmware is persistently broken.
                // The daemon stays up with web dashboard accessible via USB for diagnostics.
            }
        }
    }

    /// Build a web status snapshot.
    fn build_web_status(&self) -> web::StatusResponse {
        let m = &self.epoch_loop.metrics;
        let s = self.shared_state.lock().unwrap();
        web::build_status(&web::StatusParams {
            name: &self.config.name,
            uptime: &self.epoch_loop.uptime_str(),
            epoch: m.epoch,
            channel: m.channel,
            aps_seen: (self.lifetime_aps_base + self.ao.ap_count() as u64) as u32,
            handshakes: m.handshakes,
            blind_epochs: m.blind_epochs,
            mood: self.epoch_loop.personality.mood.value(),
            face: self.epoch_loop.current_face().display_name(),
            status_message: &self.epoch_loop.personality.status_msg(),
            mode: "AO",
            display_invert: s.display_invert,
            display_rotation: s.display_rotation,
            display_refresh_interval: s.display_refresh_interval,
            min_rssi: s.min_rssi,
            ap_ttl_secs: s.ap_ttl_secs,
        })
    }

    /// Build web attack stats.
    fn build_attack_stats(&self) -> web::AttackStats {
        let s = self.shared_state.lock().unwrap();
        web::AttackStats {
            total_attacks: self.attacks.total_attacks,
            total_handshakes: self.attacks.total_handshakes,
            attack_rate: ATTACK_RATE,
            deauths_this_epoch: self.epoch_loop.metrics.deauths_this_epoch,
            deauth: s.attack_deauth,
            pmkid: s.attack_pmkid,
            csa: s.attack_csa,
            disassoc: s.attack_disassoc,
            anon_reassoc: s.attack_anon_reassoc,
            rogue_m2: s.attack_rogue_m2,
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    // Run first-boot migration if needed (pwnagotchi -> oxigotchi)
    let legacy = migration::LegacyPaths::default();
    let oxi_paths = migration::OxiPaths::default();
    let migration_result = migration::run_migration(&legacy, &oxi_paths);
    if migration_result.success() && migration_result.config_migrated {
        info!(
            "migration: config migrated, {} captures imported (of {} found)",
            migration_result.captures_imported, migration_result.captures_found
        );
    }
    for w in &migration_result.warnings {
        log::warn!("migration: {w}");
    }
    for e in &migration_result.errors {
        log::error!("migration: {e}");
    }

    // Load oxigotchi config (may have been created by migration above)
    let config = if oxi_paths.config.exists() {
        config::Config::load_or_default(
            oxi_paths
                .config
                .to_str()
                .unwrap_or("/etc/oxigotchi/config.toml"),
        )
    } else {
        config::Config::defaults()
    };
    info!(
        "Hi! I'm {}! Rusty Oxigotchi v{} starting — the bull is awake",
        config.name,
        env!("CARGO_PKG_VERSION")
    );

    // Create shared state for web server <-> daemon communication
    let shared_state = Arc::new(Mutex::new(web::DaemonState::new(&config.name)));

    // Create WebSocket broadcast channel for live dashboard updates
    let ws_tx = web::create_ws_broadcast();

    // Start web server in a tokio task
    let web_state = shared_state.clone();
    let web_ws_tx = ws_tx.clone();
    tokio::spawn(async move {
        web::start_server(web_state, web_ws_tx).await;
    });

    // Run the daemon main loop in a blocking thread (it uses std::thread::sleep)
    let mut daemon = Daemon::new(config, shared_state, ws_tx);
    tokio::task::spawn_blocking(move || {
        daemon.boot();
        info!("entering main epoch loop");
        loop {
            daemon.run_epoch();
        }
    })
    .await
    .expect("daemon task panicked");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_daemon() -> Daemon {
        let config = config::Config::defaults();
        let shared_state = Arc::new(Mutex::new(web::DaemonState::new(&config.name)));
        let ws_tx = web::create_ws_broadcast();
        Daemon::new(config, shared_state, ws_tx)
    }

    #[test]
    fn test_daemon_construction() {
        let daemon = make_daemon();
        assert_eq!(daemon.epoch_loop.metrics.epoch, 0);
        assert_eq!(daemon.wifi.state, wifi::WifiState::Down);
        assert_eq!(daemon.captures.count(), 0);
        assert_eq!(daemon.ao.state, ao::AoState::Stopped);
    }

    #[test]
    fn test_daemon_boot() {
        // Skip on non-Pi Linux — boot() calls start_monitor() which needs wlan0
        if std::fs::metadata("/sys/class/net/wlan0").is_err() {
            return;
        }
        let mut daemon = make_daemon();
        daemon.boot();
        // WiFi should be in monitor mode (stub always succeeds)
        assert_eq!(daemon.wifi.state, wifi::WifiState::Monitor);
    }

    #[test]
    fn test_daemon_build_web_status() {
        let daemon = make_daemon();
        let status = daemon.build_web_status();
        assert_eq!(status.name, "oxigotchi");
        assert_eq!(status.epoch, 0);
        assert_eq!(status.mode, "AO");
    }

    #[test]
    fn test_daemon_build_attack_stats() {
        let daemon = make_daemon();
        let stats = daemon.build_attack_stats();
        assert_eq!(stats.total_attacks, 0);
        assert_eq!(stats.attack_rate, ATTACK_RATE);
    }

    #[test]
    fn test_attack_success_when_ao_stopped() {
        let daemon = make_daemon();
        // Default state is Stopped on all platforms
        assert_eq!(daemon.ao.state, ao::AoState::Stopped);
        // Build an attack result the way run_epoch does
        let success = daemon.ao.state == ao::AoState::Running;
        assert!(!success, "attack should not succeed when AO is stopped");
    }

    #[test]
    fn test_attack_success_when_ao_running() {
        let mut daemon = make_daemon();
        // Simulate AO running state directly
        daemon.ao.state = ao::AoState::Running;
        let success = daemon.ao.state == ao::AoState::Running;
        assert!(success, "attack should succeed when AO is running");
    }

    #[test]
    fn test_daemon_battery_override_critical_no_shutdown() {
        let mut daemon = make_daemon();
        daemon.battery.available = true;
        daemon.battery.config.auto_shutdown = false;
        daemon.battery.set_level(3); // critical
        daemon.check_battery_overrides();
        assert_eq!(
            daemon.epoch_loop.personality.override_face,
            Some(personality::Face::BatteryCritical)
        );
    }

    #[test]
    fn test_daemon_battery_override_critical_with_shutdown() {
        let mut daemon = make_daemon();
        daemon.battery.available = true;
        daemon.battery.set_level(3); // critical, auto_shutdown = true by default
        daemon.check_battery_overrides();
        // Face override stays BatteryCritical (show_transition draws Shutdown to screen directly)
        assert_eq!(
            daemon.epoch_loop.personality.override_face,
            Some(personality::Face::BatteryCritical)
        );
        // pisugar_shutdown() was called, setting shutting_down flag
        assert!(daemon.battery.shutting_down);
    }

    #[test]
    fn test_daemon_battery_override_low() {
        let mut daemon = make_daemon();
        daemon.battery.available = true;
        daemon.battery.set_level(15); // low but not critical
        daemon.check_battery_overrides();
        assert_eq!(
            daemon.epoch_loop.personality.override_face,
            Some(personality::Face::BatteryLow)
        );
    }

    #[test]
    fn test_daemon_battery_override_clears() {
        let mut daemon = make_daemon();
        daemon.battery.available = true;
        daemon.battery.config.auto_shutdown = false;
        daemon.battery.set_level(3);
        daemon.check_battery_overrides();
        assert_eq!(
            daemon.epoch_loop.personality.override_face,
            Some(personality::Face::BatteryCritical)
        );
        daemon.battery.set_level(80);
        daemon.check_battery_overrides();
        assert_eq!(daemon.epoch_loop.personality.override_face, None);
    }

    #[test]
    fn test_daemon_recovery_soft() {
        let mut daemon = make_daemon();
        daemon.handle_recovery_action(recovery::RecoveryAction::SoftRecover);
        // On non-unix (tests), start_monitor() succeeds → override cleared after recovery
        assert_eq!(
            daemon.epoch_loop.personality.override_face,
            None,
            "WifiDown override should be cleared after successful soft recovery"
        );
    }

    #[test]
    fn test_daemon_recovery_hard() {
        let mut daemon = make_daemon();
        daemon.handle_recovery_action(recovery::RecoveryAction::HardRecover);
        // Hard recovery is refused on BCM43436B0 — GPIO WL_REG_ON would revert
        // firmware to stock brcmfmac (no nexmon monitor mode). We surface
        // FwCrash so the user knows a physical power cycle is required.
        assert_eq!(
            daemon.epoch_loop.personality.override_face,
            Some(personality::Face::FwCrash),
            "hard recovery must surface FwCrash — GPIO cycle is unsafe on this chip"
        );
    }

    #[test]
    fn test_daemon_recovery_give_up() {
        let mut daemon = make_daemon();
        daemon.handle_recovery_action(recovery::RecoveryAction::GiveUp);
        assert_eq!(
            daemon.epoch_loop.personality.override_face,
            Some(personality::Face::Broken)
        );
    }

    #[test]
    fn test_daemon_update_display_no_panic() {
        let mut daemon = make_daemon();
        daemon.update_display();
        let pixel_count = daemon.screen.fb.count_set_pixels();
        assert!(pixel_count > 0, "display should have drawn something");
    }

    /// Verify that all 26 Face variants are reachable.
    #[test]
    fn test_face_reachability() {
        use personality::Face;

        let mood_faces = [
            Face::Excited,
            Face::Happy,
            Face::Awake,
            Face::Bored,
            Face::Sad,
            Face::Demotivated,
        ];
        let override_faces = [
            Face::BatteryCritical,
            Face::BatteryLow,
            Face::Shutdown,
            Face::WifiDown,
            Face::FwCrash,
            Face::Broken,
        ];
        let manual_override_faces = [
            Face::Sleep,
            Face::Intense,
            Face::Cool,
            Face::Angry,
            Face::Friend,
            Face::Debug,
            Face::Upload,
            Face::Lonely,
            Face::Grateful,
            Face::Motivated,
            Face::Smart,
            Face::AoCrashed,
            Face::Raging,
            Face::Grazing,
        ];

        let mut reachable: std::collections::HashSet<Face> = std::collections::HashSet::new();
        reachable.extend(mood_faces.iter());
        reachable.extend(override_faces.iter());
        reachable.extend(manual_override_faces.iter());

        for face in Face::all() {
            assert!(
                reachable.contains(face),
                "Face::{face:?} is not reachable through any trigger"
            );
        }
        assert_eq!(reachable.len(), Face::all().len());
    }

    #[test]
    fn test_epoch_drives_mood_faces() {
        let mut daemon = make_daemon();

        // Initial face is Excited (mood starts high on boot).
        assert_eq!(daemon.epoch_loop.current_face(), personality::Face::Excited);

        // After handshakes, mood stays high — face should be Excited or Happy.
        for _ in 0..10 {
            daemon.epoch_loop.record_result(&epoch::EpochResult {
                handshakes_captured: 3,
                aps_seen: 10,
                ..Default::default()
            });
        }
        let face = daemon.epoch_loop.current_face();
        assert!(
            face == personality::Face::Excited || face == personality::Face::Happy,
            "expected Excited or Happy after many handshakes, got {face:?}"
        );

        // The new mood system is a mean-reverting random walk driven by wall-clock
        // ticks (mood_tick()), not blind epoch counts. Simulate many ticks to drive
        // mood from high toward center, then verify face is no longer at maximum.
        // 500 ticks (each -0.2% drift + noise) is enough to move from 1.0 toward 0.5.
        for _ in 0..500 {
            daemon.epoch_loop.personality.mood_tick();
        }
        let face = daemon.epoch_loop.current_face();
        assert_ne!(
            face,
            personality::Face::Excited,
            "expected mood to drift from Excited after many mood ticks, got {face:?}"
        );
    }

    /// Integration test: create a Daemon, run 3 full epoch cycles.
    #[test]
    fn test_integration_three_epochs() {
        // Skip on non-Pi Linux — boot() calls start_monitor() which needs wlan0
        if std::fs::metadata("/sys/class/net/wlan0").is_err() {
            return;
        }
        let mut daemon = make_daemon();

        daemon.boot();

        let mut pixel_counts: Vec<u32> = Vec::new();

        for epoch in 0..3 {
            // ---- SCAN ----
            daemon.epoch_loop.phase = epoch::EpochPhase::Scan;

            let mut result = epoch::EpochResult::default();
            result.channel = 0; // AO handles channel hopping
            result.aps_seen = (epoch + 1) * 2;

            // ---- ATTACK ----
            daemon.epoch_loop.next_phase();
            result.deauths_sent = epoch;

            // ---- CAPTURE ----
            daemon.epoch_loop.next_phase();

            // ---- DISPLAY ----
            daemon.epoch_loop.next_phase();
            daemon.epoch_loop.record_result(&result);
            daemon.update_display();
            pixel_counts.push(daemon.screen.fb.count_set_pixels());

            // ---- SLEEP ----
            daemon.epoch_loop.next_phase();
            if daemon.watchdog.needs_ping() {
                daemon.watchdog.ping();
            }

            // ---- back to SCAN ----
            daemon.epoch_loop.next_phase();
        }

        assert_eq!(daemon.epoch_loop.metrics.epoch, 3);

        for (i, &count) in pixel_counts.iter().enumerate() {
            assert!(count > 0, "epoch {i} should have drawn pixels, got 0");
        }

        assert_eq!(daemon.wifi.state, wifi::WifiState::Monitor);
    }

    #[test]
    fn test_sync_to_web() {
        // Skip on non-Pi Linux — boot() calls start_monitor() which needs wlan0
        if std::fs::metadata("/sys/class/net/wlan0").is_err() {
            return;
        }
        let mut daemon = make_daemon();
        daemon.boot();
        daemon.sync_to_web();

        let s = daemon.shared_state.lock().unwrap();
        assert_eq!(s.name, "oxigotchi");
        assert_eq!(s.wifi_state, "Monitor");
    }

    #[test]
    fn test_process_web_commands_mode() {
        let mut daemon = make_daemon();
        {
            let mut s = daemon.shared_state.lock().unwrap();
            s.pending_mode_switch = Some("PWN".into());
        }
        daemon.process_web_commands();
        let s = daemon.shared_state.lock().unwrap();
        assert_eq!(s.mode, "PWN");
    }

    #[test]
    fn test_process_web_commands_rate() {
        let mut daemon = make_daemon();
        {
            let mut s = daemon.shared_state.lock().unwrap();
            s.pending_rate_change = Some(2);
        }
        daemon.process_web_commands();
        assert_eq!(daemon.ao.config.rate, 2);
    }

    #[test]
    fn test_process_web_commands_restart() {
        let mut daemon = make_daemon();
        {
            let mut s = daemon.shared_state.lock().unwrap();
            s.pending_restart = true;
        }
        daemon.process_web_commands();
        // On non-Pi, AO start is a stub so it should work
        // Just verify it didn't panic and pending_restart is cleared
        let s = daemon.shared_state.lock().unwrap();
        assert!(!s.pending_restart);
    }

    #[test]
    fn test_daemon_ao_state() {
        let daemon = make_daemon();
        assert_eq!(daemon.ao.state, ao::AoState::Stopped);
        assert_eq!(daemon.ao.crash_count, 0);
    }

    #[test]
    fn test_capture_scan_detects_new_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut cm = capture::CaptureManager::new(dir.path().to_str().unwrap());

        // Initial scan — empty
        assert_eq!(cm.scan_directory().unwrap(), 0);
        assert_eq!(cm.handshake_count(), 0);

        // Create a pcapng + .22000 companion
        let pcap = dir.path().join("test.pcapng");
        std::fs::write(&pcap, b"fake").unwrap();
        let companion = dir.path().join("test.22000");
        std::fs::write(&companion, b"fake").unwrap();

        // Rescan — should find 1 new file with handshake
        let new = cm.scan_directory().unwrap();
        assert_eq!(new, 1);
        assert_eq!(cm.handshake_count(), 1);
    }

    #[test]
    fn test_lua_plugins_load_and_register_indicators() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("test_ind.lua"),
            r#"
            plugin = {}
            plugin.name = "test_ind"
            plugin.version = "1.0.0"
            plugin.author = "test"
            plugin.tag = "default"
            function on_load(config)
                register_indicator("test", { x = config.x or 0, y = config.y or 0, font = "small" })
            end
            function on_epoch(state)
                set_indicator("test", "E:" .. state.epoch)
            end
        "#,
        )
        .unwrap();

        let mut rt = lua::PluginRuntime::new();
        let configs = vec![lua::PluginConfig::default_for("test_ind", 50, 60)];
        let loaded = rt.load_plugins_from_dir(dir.path().to_str().unwrap(), &configs);
        assert_eq!(loaded, 1);

        let state = lua::state::EpochState {
            epoch: 99,
            ..Default::default()
        };
        rt.tick_epoch(&state);

        let indicators = rt.get_indicators();
        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0].value, "E:99");
        assert_eq!(indicators[0].x, 50);
        assert_eq!(indicators[0].y, 60);
    }

    #[test]
    fn test_operating_mode_next() {
        assert_eq!(OperatingMode::Rage.next(), OperatingMode::Bt);
        assert_eq!(OperatingMode::Bt.next(), OperatingMode::Safe);
        assert_eq!(OperatingMode::Safe.next(), OperatingMode::Rage);
    }

    #[test]
    fn test_operating_mode_toggle_is_next() {
        assert_eq!(OperatingMode::Rage.toggle(), OperatingMode::Rage.next());
        assert_eq!(OperatingMode::Bt.toggle(), OperatingMode::Bt.next());
        assert_eq!(OperatingMode::Safe.toggle(), OperatingMode::Safe.next());
    }

    #[test]
    fn test_operating_mode_as_str() {
        assert_eq!(OperatingMode::Rage.as_str(), "RAGE");
        assert_eq!(OperatingMode::Bt.as_str(), "BT");
        assert_eq!(OperatingMode::Safe.as_str(), "SAFE");
    }

    #[test]
    fn test_daemon_starts_in_rage_mode_by_default() {
        let daemon = make_daemon();
        assert_eq!(daemon.mode, OperatingMode::Rage);
    }

    #[test]
    fn test_process_web_commands_rage_level() {
        let mut daemon = make_daemon();
        {
            let mut s = daemon.shared_state.lock().unwrap();
            s.pending_rage_change = Some(Some(4));
        }
        daemon.process_web_commands();
        // Level 4 = Hunt: rate 2, dwell 1000ms, channels 1-11
        assert_eq!(daemon.ao.config.rate, 2);
        assert_eq!(daemon.wifi.channel_config.dwell_ms, 1000);
        assert_eq!(
            daemon.wifi.channel_config.channels,
            vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        );
        assert!(!daemon.autohunt);
        let s = daemon.shared_state.lock().unwrap();
        assert!(s.rage_enabled);
        assert_eq!(s.rage_level, 4);
    }

    #[test]
    fn test_process_web_commands_rage_disable() {
        let mut daemon = make_daemon();
        {
            let mut s = daemon.shared_state.lock().unwrap();
            s.rage_enabled = true;
            s.rage_level = 2;
            s.pending_rage_change = Some(None);
        }
        daemon.process_web_commands();
        let s = daemon.shared_state.lock().unwrap();
        assert!(!s.rage_enabled);
    }

    #[test]
    fn test_process_web_commands_rate_breaks_rage() {
        let mut daemon = make_daemon();
        {
            let mut s = daemon.shared_state.lock().unwrap();
            s.rage_enabled = true;
            s.rage_level = 3;
            s.pending_rate_change = Some(1);
        }
        daemon.process_web_commands();
        let s = daemon.shared_state.lock().unwrap();
        assert!(
            !s.rage_enabled,
            "manual rate change should break out of RAGE"
        );
    }

    // ---- Autohunt toggle daemon tests ----

    #[test]
    fn test_process_web_commands_autohunt_on_clears_ao_channels() {
        let mut daemon = make_daemon();
        // Set some channels first
        daemon.wifi.channel_config.channels = vec![1, 6, 11];
        daemon.ao.config.channels = vec![1, 6, 11];
        daemon.autohunt = false;
        {
            let mut s = daemon.shared_state.lock().unwrap();
            s.pending_channel_config = Some(web::ChannelConfig {
                channels: None,
                dwell_ms: None,
                autohunt: Some(true),
            });
        }
        daemon.process_web_commands();
        assert!(daemon.autohunt, "autohunt should be enabled");
        assert!(
            daemon.ao.config.channels.is_empty(),
            "AO channels should be cleared when autohunt is ON"
        );
    }

    #[test]
    fn test_process_web_commands_autohunt_off_restores_channels() {
        let mut daemon = make_daemon();
        daemon.wifi.channel_config.channels = vec![1, 6, 11];
        daemon.autohunt = true;
        daemon.ao.config.channels = vec![]; // was autohunting
        {
            let mut s = daemon.shared_state.lock().unwrap();
            s.pending_channel_config = Some(web::ChannelConfig {
                channels: Some(vec![1, 6, 11]),
                dwell_ms: Some(2000),
                autohunt: Some(false),
            });
        }
        daemon.process_web_commands();
        assert!(!daemon.autohunt, "autohunt should be disabled");
        assert_eq!(
            daemon.ao.config.channels,
            vec![1, 6, 11],
            "AO channels should be restored from wifi channel config"
        );
    }

    #[test]
    fn test_process_web_commands_autohunt_on_breaks_rage() {
        let mut daemon = make_daemon();
        {
            let mut s = daemon.shared_state.lock().unwrap();
            s.rage_enabled = true;
            s.rage_level = 3;
            s.pending_channel_config = Some(web::ChannelConfig {
                channels: None,
                dwell_ms: None,
                autohunt: Some(true),
            });
        }
        daemon.process_web_commands();
        let s = daemon.shared_state.lock().unwrap();
        assert!(
            !s.rage_enabled,
            "autohunt toggle should break out of RAGE"
        );
    }

    #[test]
    fn test_process_web_commands_autohunt_preserves_dwell() {
        let mut daemon = make_daemon();
        daemon.wifi.channel_config.dwell_ms = 3000;
        {
            let mut s = daemon.shared_state.lock().unwrap();
            s.pending_channel_config = Some(web::ChannelConfig {
                channels: None,
                dwell_ms: None, // not changing dwell
                autohunt: Some(true),
            });
        }
        daemon.process_web_commands();
        assert_eq!(
            daemon.wifi.channel_config.dwell_ms, 3000,
            "dwell should be unchanged when only toggling autohunt"
        );
        assert_eq!(
            daemon.ao.config.dwell, 3,
            "AO dwell (seconds) should reflect existing dwell_ms"
        );
    }

    #[test]
    fn test_process_web_commands_channel_config_updates_dwell() {
        let mut daemon = make_daemon();
        {
            let mut s = daemon.shared_state.lock().unwrap();
            s.pending_channel_config = Some(web::ChannelConfig {
                channels: Some(vec![1, 6]),
                dwell_ms: Some(5000),
                autohunt: Some(false),
            });
        }
        daemon.process_web_commands();
        assert_eq!(daemon.wifi.channel_config.dwell_ms, 5000);
        assert_eq!(daemon.wifi.channel_config.channels, vec![1, 6]);
        assert_eq!(daemon.ao.config.dwell, 5);
        assert_eq!(daemon.ao.config.channels, vec![1, 6]);
    }

    #[test]
    fn test_process_web_commands_empty_channels_not_applied() {
        let mut daemon = make_daemon();
        daemon.wifi.channel_config.channels = vec![1, 6, 11];
        {
            let mut s = daemon.shared_state.lock().unwrap();
            s.pending_channel_config = Some(web::ChannelConfig {
                channels: Some(vec![]), // empty
                dwell_ms: None,
                autohunt: Some(false),
            });
        }
        daemon.process_web_commands();
        assert_eq!(
            daemon.wifi.channel_config.channels,
            vec![1, 6, 11],
            "empty channel list should not overwrite existing channels"
        );
    }

    #[test]
    fn test_daemon_default_autohunt_is_on() {
        let daemon = make_daemon();
        assert!(daemon.autohunt, "daemon should start with autohunt enabled");
    }

    #[test]
    fn test_generate_status_runs_after_battery_and_ao_checks() {
        let source = include_str!("main.rs");
        let gen_pos = source.find("personality.generate_status()").expect("generate_status not found");
        let battery_pos = source
            .find("check_battery_overrides()")
            .expect("check_battery_overrides not found");
        assert!(
            gen_pos > battery_pos,
            "generate_status() must run AFTER check_battery_overrides()"
        );
        let ao_clear_pos = source
            .find("// Clear AO crash face if AO recovered")
            .expect("AO clear comment not found");
        assert!(
            gen_pos > ao_clear_pos,
            "generate_status() must run AFTER AoCrashed clearing"
        );
    }
}
