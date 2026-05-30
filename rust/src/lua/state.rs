//! EpochState: daemon state snapshot passed to Lua plugins each epoch.

use mlua::prelude::*;

/// Flat snapshot of daemon state for Lua plugins.
#[derive(Debug, Clone, Default)]
pub struct EpochState {
    // timing
    pub uptime_secs: u64,
    pub epoch: u64,
    pub mode: String,
    pub rage_level: u8, // 0 = Custom/off, 1-3 = active RAGE level

    // wifi / AO
    pub channel: u8,
    pub aps_seen: u32,
    pub handshakes: u32,
    pub captures_total: usize,
    pub blind_epochs: u32,
    pub ao_state: String,
    pub ao_pid: u32,
    pub ao_crash_count: u32,
    pub ao_uptime_str: String,
    pub ao_uptime_secs: u64,
    pub ao_channels: String,
    /// Session capture count: pcapng files created by AO in tmpfs this session.
    pub session_captures: u32,
    /// Session handshake count: validated captures moved to SD this session.
    pub session_handshakes: u32,

    // battery
    pub battery_level: u8,
    pub battery_charging: bool,
    pub battery_voltage_mv: u16,
    pub battery_low: bool,
    pub battery_critical: bool,
    pub battery_available: bool,
    pub pisugar_temp_c: i8,

    // bluetooth
    pub bt_connected: bool,
    pub bt_short: String,
    pub bt_ip: String,
    pub bt_internet: bool,

    // bluetooth attack/discovery stats (for BT-mode indicators)
    pub bt_devices_seen: u32,
    pub bt_active_attacks: u32,
    pub bt_total_captures: u32,
    pub bt_patchram_state: String,
    pub bt_rage_level: String,

    // network
    pub internet_online: bool,
    pub display_ip: String,

    // personality
    pub mood: f32,
    pub face: String,
    pub level: u32,
    pub xp: u64,
    pub status_message: String,
    pub epoch_phase_status: String,
    pub joke_active: bool,

    // firmware
    pub fw_crash_suppress: u32,
    pub fw_hardfault: u32,
    pub fw_health: String,

    // smart skip
    pub skip_captured: bool,

    // wigle / gps
    pub wigle_enabled: bool,
    pub gps_fix: bool,

    // system
    pub cpu_temp: f32,
    pub mem_used_mb: u32,
    pub mem_total_mb: u32,
    pub cpu_percent: f32,
    pub cpu_freq_ghz: String,
}

impl EpochState {
    /// Convert to a Lua table.
    pub fn to_lua_table(&self, lua: &Lua) -> LuaResult<LuaTable> {
        let t = lua.create_table()?;

        t.set("uptime_secs", self.uptime_secs)?;
        t.set("epoch", self.epoch)?;
        t.set("mode", self.mode.as_str())?;
        t.set("rage_level", self.rage_level)?;

        t.set("channel", self.channel)?;
        t.set("aps_seen", self.aps_seen)?;
        t.set("handshakes", self.handshakes)?;
        t.set("captures_total", self.captures_total as u64)?;
        t.set("blind_epochs", self.blind_epochs)?;
        t.set("ao_state", self.ao_state.as_str())?;
        t.set("ao_pid", self.ao_pid)?;
        t.set("ao_crash_count", self.ao_crash_count)?;
        t.set("ao_uptime_str", self.ao_uptime_str.as_str())?;
        t.set("ao_uptime_secs", self.ao_uptime_secs)?;
        t.set("ao_channels", self.ao_channels.as_str())?;
        t.set("session_captures", self.session_captures)?;
        t.set("session_handshakes", self.session_handshakes)?;

        t.set("battery_level", self.battery_level)?;
        t.set("battery_charging", self.battery_charging)?;
        t.set("battery_voltage_mv", self.battery_voltage_mv)?;
        t.set("battery_low", self.battery_low)?;
        t.set("battery_critical", self.battery_critical)?;
        t.set("battery_available", self.battery_available)?;
        t.set("pisugar_temp_c", self.pisugar_temp_c)?;

        t.set("bt_connected", self.bt_connected)?;
        t.set("bt_short", self.bt_short.as_str())?;
        t.set("bt_ip", self.bt_ip.as_str())?;
        t.set("bt_internet", self.bt_internet)?;
        t.set("bt_devices_seen", self.bt_devices_seen)?;
        t.set("bt_active_attacks", self.bt_active_attacks)?;
        t.set("bt_total_captures", self.bt_total_captures)?;
        t.set("bt_patchram_state", self.bt_patchram_state.clone())?;
        t.set("bt_rage_level", self.bt_rage_level.clone())?;

        t.set("internet_online", self.internet_online)?;
        t.set("display_ip", self.display_ip.as_str())?;

        t.set("mood", self.mood)?;
        t.set("face", self.face.as_str())?;
        t.set("level", self.level)?;
        t.set("xp", self.xp)?;
        t.set("status_message", self.status_message.as_str())?;
        t.set("epoch_phase_status", self.epoch_phase_status.as_str())?;
        t.set("joke_active", self.joke_active)?;

        t.set("fw_crash_suppress", self.fw_crash_suppress)?;
        t.set("fw_hardfault", self.fw_hardfault)?;
        t.set("fw_health", self.fw_health.as_str())?;

        t.set("skip_captured", self.skip_captured)?;

        t.set("wigle_enabled", self.wigle_enabled)?;
        t.set("gps_fix", self.gps_fix)?;

        t.set("cpu_temp", self.cpu_temp)?;
        t.set("mem_used_mb", self.mem_used_mb)?;
        t.set("mem_total_mb", self.mem_total_mb)?;
        t.set("cpu_percent", self.cpu_percent)?;
        t.set("cpu_freq_ghz", self.cpu_freq_ghz.as_str())?;

        Ok(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_state_default() {
        let s = EpochState::default();
        assert_eq!(s.uptime_secs, 0);
        assert_eq!(s.epoch, 0);
        assert_eq!(s.ao_state, "");
    }

    #[test]
    fn test_epoch_state_to_lua_table() {
        let lua = Lua::new();
        let s = EpochState {
            uptime_secs: 7200,
            epoch: 42,
            aps_seen: 15,
            handshakes: 3,
            battery_level: 85,
            bt_connected: true,
            mood: 0.75,
            level: 3,
            xp: 450,
            cpu_temp: 45.2,
            ..Default::default()
        };
        let table = s.to_lua_table(&lua).unwrap();
        assert_eq!(table.get::<u64>("uptime_secs").unwrap(), 7200);
        assert_eq!(table.get::<u64>("epoch").unwrap(), 42);
        assert_eq!(table.get::<u32>("aps_seen").unwrap(), 15);
        assert_eq!(table.get::<u8>("battery_level").unwrap(), 85);
        assert!(table.get::<bool>("bt_connected").unwrap());
        assert_eq!(table.get::<u32>("level").unwrap(), 3);
    }

    #[test]
    fn test_epoch_state_mode_field() {
        let lua = Lua::new();
        let s = EpochState {
            mode: "RAGE".into(),
            ..Default::default()
        };
        let table = s.to_lua_table(&lua).unwrap();
        assert_eq!(table.get::<String>("mode").unwrap(), "RAGE");
    }

    #[test]
    fn test_epoch_state_bt_fields_in_lua_table() {
        let lua = Lua::new();
        let mut state = EpochState::default();
        state.bt_devices_seen = 5;
        state.bt_active_attacks = 2;
        state.bt_total_captures = 10;
        state.bt_patchram_state = "attack".to_string();

        let table = state.to_lua_table(&lua).unwrap();
        assert_eq!(table.get::<u32>("bt_devices_seen").unwrap(), 5);
        assert_eq!(table.get::<u32>("bt_active_attacks").unwrap(), 2);
        assert_eq!(table.get::<u32>("bt_total_captures").unwrap(), 10);
        assert_eq!(table.get::<String>("bt_patchram_state").unwrap(), "attack");
    }
}
