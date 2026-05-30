"""
Oxigotchi v3.0 Integration Tests
Run against a live Pi at 10.0.0.2 via USB RNDIS.

Usage:
    pytest tests/test_v3_integration.py -v
    pytest tests/test_v3_integration.py -v -k "TestWebAPI"

Requires: Pi running rusty-oxigotchi, reachable at 10.0.0.2.
"""
import json
import subprocess
import pytest
import urllib.request
import urllib.error

PI_HOST = "10.0.0.2"
PI_USER = "pi"
API_BASE = f"http://{PI_HOST}:8080"
SSH_OPTS = ["-o", "LogLevel=ERROR", "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=no"]


def ssh_cmd(cmd, timeout=10):
    """Run a command on the Pi via SSH. Returns (stdout, returncode)."""
    result = subprocess.run(
        ["ssh"] + SSH_OPTS + [f"{PI_USER}@{PI_HOST}", cmd],
        capture_output=True, text=True, timeout=timeout
    )
    return result.stdout.strip(), result.returncode


def api_get(path, timeout=5):
    """GET an API endpoint, return parsed JSON."""
    url = f"{API_BASE}{path}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def api_post(path, data=None, timeout=5):
    """POST to an API endpoint."""
    url = f"{API_BASE}{path}"
    body = json.dumps(data).encode() if data else b""
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


@pytest.fixture(scope="session", autouse=True)
def require_pi():
    """Skip entire test session if Pi is unreachable."""
    try:
        ssh_cmd("echo ok", timeout=5)
    except Exception:
        pytest.skip("Pi not reachable at 10.0.0.2")


# ── System Health ──────────────────────────────────────────────────────

class TestSystemHealth:
    def test_ssh_connectivity(self):
        out, rc = ssh_cmd("hostname")
        assert rc == 0
        assert "oxigotchi" in out

    def test_daemon_running(self):
        out, rc = ssh_cmd("systemctl is-active rusty-oxigotchi")
        assert out == "active"

    def test_wlan0mon_exists(self):
        out, rc = ssh_cmd("ip link show wlan0mon")
        assert rc == 0
        assert "wlan0mon" in out

    def test_memory_reasonable(self):
        out, _ = ssh_cmd("free -m | awk '/Mem:/ {print $3}'")
        used_mb = int(out)
        assert used_mb < 400, f"Memory usage too high: {used_mb}MB"

    def test_disk_not_full(self):
        out, _ = ssh_cmd("df / --output=pcent | tail -1")
        pct = int(out.strip().rstrip('%'))
        assert pct < 90, f"Disk {pct}% full"

    def test_no_unexpected_failed_services(self):
        out, _ = ssh_cmd(
            "systemctl --failed --no-legend "
            "| grep -v pwnagotchi | grep -v bettercap | wc -l"
        )
        count = int(out)
        assert count <= 3, f"{count} unexpected failed services"


# ── Binary ─────────────────────────────────────────────────────────────

class TestBinary:
    def test_binary_exists(self):
        _, rc = ssh_cmd("test -x /usr/local/bin/rusty-oxigotchi")
        assert rc == 0

    def test_binary_running(self):
        out, rc = ssh_cmd("pgrep -f rusty-oxigotchi")
        assert rc == 0
        assert int(out.split('\n')[0]) > 0

    def test_angryoxide_running(self):
        out, rc = ssh_cmd("pgrep -x angryoxide")
        assert rc == 0


# ── Web API ────────────────────────────────────────────────────────────

class TestWebAPI:
    def test_dashboard_loads(self):
        req = urllib.request.Request(f"{API_BASE}/")
        with urllib.request.urlopen(req, timeout=5) as resp:
            html = resp.read().decode()
            assert "oxigotchi" in html.lower()
            assert resp.status == 200

    def test_api_state_returns_json(self):
        state = api_get("/api/status")
        assert "epoch" in state
        assert "mode" in state

    def test_api_status_has_required_fields(self):
        state = api_get("/api/status")
        required = [
            "epoch", "mode", "channel", "aps_seen", "handshakes",
            "mood", "face", "name", "version", "uptime",
        ]
        for field in required:
            assert field in state, f"Missing field: {field}"

    def test_api_status_types(self):
        state = api_get("/api/status")
        assert isinstance(state["epoch"], int)
        assert isinstance(state["mood"], (int, float))
        assert isinstance(state["mode"], str)
        assert isinstance(state["name"], str)


# ── Plugins ────────────────────────────────────────────────────────────

EXPECTED_PLUGINS = [
    "ao_status", "aps", "battery", "bt_status", "crash",
    "ip_display", "mode", "status_msg", "sys_stats", "uptime", "wigle_gps", "www",
]


class TestPlugins:
    def test_all_plugin_files_present(self):
        out, _ = ssh_cmd("ls /etc/oxigotchi/plugins/*.lua")
        for name in EXPECTED_PLUGINS:
            assert f"{name}.lua" in out, f"Missing plugin file: {name}"

    def test_plugins_loaded_in_logs(self):
        out, _ = ssh_cmd(
            "journalctl -u rusty-oxigotchi --no-pager -n 200 "
            "| grep 'loaded v'"
        )
        for name in EXPECTED_PLUGINS:
            assert name in out, f"Plugin not loaded: {name}"


# ── Services ───────────────────────────────────────────────────────────

EXPECTED_ACTIVE = [
    "rusty-oxigotchi",
    "emergency-ssh",
    "wlan-keepalive",
]


class TestServices:
    @pytest.mark.parametrize("service", EXPECTED_ACTIVE)
    def test_service_active(self, service):
        out, rc = ssh_cmd(f"systemctl is-active {service}")
        assert out == "active", f"{service} not active: {out}"

    def test_legacy_services_disabled(self):
        """bettercap and pwngrid should be disabled in v3."""
        for svc in ["bettercap", "pwngrid-peer"]:
            out, _ = ssh_cmd(f"systemctl is-enabled {svc} 2>/dev/null || echo disabled")
            assert "disabled" in out or "masked" in out, f"{svc} still enabled"


# ── Config ─────────────────────────────────────────────────────────────

class TestConfig:
    def test_config_exists(self):
        _, rc = ssh_cmd("test -f /etc/oxigotchi/config.toml")
        assert rc == 0

    def test_state_json_valid(self):
        out, rc = ssh_cmd("cat /var/lib/oxigotchi/state.json")
        assert rc == 0
        state = json.loads(out)
        assert isinstance(state, dict)

    def test_bt_keepalive_shell_removed(self):
        """bt-keepalive.sh shell relic must NOT be on the image — v3.3.1
        moved BT tether reconnect into the Rust daemon. Any leftover script
        indicates an incomplete upgrade and will race with the daemon."""
        _, rc = ssh_cmd("test -e /usr/local/bin/bt-keepalive.sh")
        assert rc != 0, "bt-keepalive.sh still present; must be removed in v3.3.1"

    def test_xp_stats_valid(self):
        out, rc = ssh_cmd("cat /home/pi/exp_stats.json")
        if rc == 0:
            xp = json.loads(out)
            assert "level" in xp
            assert "xp" in xp


# ── Firmware ───────────────────────────────────────────────────────────

class TestFirmware:
    def test_patched_firmware_deployed(self):
        """Active firmware should differ from stock."""
        out, _ = ssh_cmd(
            "md5sum /lib/firmware/brcm/brcmfmac43436-sdio.bin "
            "/lib/firmware/brcm/brcmfmac43436-sdio.bin.orig 2>/dev/null"
        )
        lines = out.strip().split('\n')
        if len(lines) >= 2:
            assert lines[0].split()[0] != lines[1].split()[0], \
                "Firmware matches stock — patches not applied!"

    def test_firmware_size_reasonable(self):
        out, _ = ssh_cmd(
            "stat -c %s /lib/firmware/brcm/brcmfmac43436-sdio.bin"
        )
        size = int(out)
        assert 400000 < size < 500000, f"Unexpected firmware size: {size}"
