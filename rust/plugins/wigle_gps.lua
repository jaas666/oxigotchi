-- wigle_gps.lua: GPS fix status indicator, shown only when WIGLE is enabled.
-- "GPS+" = WIGLE active and fix acquired
-- "GPS-" = WIGLE active but no fix (gpsd missing or waiting)
-- ""     = WIGLE disabled (nothing drawn)
plugin = {}
plugin.name    = "wigle_gps"
plugin.version = "1.0.0"
plugin.author  = "oxigotchi"
plugin.tag     = "default"

function on_load(config)
    register_indicator("wigle_gps", {
        x     = config.x,
        y     = config.y,
        font  = "small",
        modes = {"RAGE"},
    })
end

function on_epoch(state)
    if not state.wigle_enabled then
        set_indicator("wigle_gps", "")
        return
    end
    if state.gps_fix then
        set_indicator("wigle_gps", "GPS+")
    else
        set_indicator("wigle_gps", "GPS-")
    end
end
