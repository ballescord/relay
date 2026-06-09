"""
PC Power Panel — self-hosted web panel to wake / reboot / shut down machines.

Managed entirely from the browser:
  * step-by-step wizard (OS -> distro -> connection -> details)
  * each field has a one-line "how to find this" helper command
  * the final screen shows numbered, copyable setup steps to run on the target
  * power actions are OS-aware (Linux: systemctl, Windows: shutdown)
"""

import hmac
import os
import re
import socket
import subprocess
from urllib.parse import quote, urlparse

import yaml
from flask import Flask, Response, redirect, render_template_string, request

# --- Input validation (block shell/SSH-argument injection via config fields) --
RE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
RE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$")   # IPv4 / hostname, no leading '-'
RE_USER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
RE_MAC = re.compile(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$")


def parse_ssh_target(value):
    """Validate a 'user@host' SSH target. Returns the clean string or None.
    Rejects anything that could be parsed by ssh as an option (leading '-',
    shell metacharacters, etc.)."""
    s = (value or "").strip()
    if "@" not in s:
        return None
    user, host = s.rsplit("@", 1)
    if RE_USER.match(user) and RE_HOST.match(host):
        return user + "@" + host
    return None


def clean_mac(value):
    """Return the MAC if it is a valid hex MAC, else None."""
    s = (value or "").strip()
    return s if RE_MAC.match(s) else None

CONFIG_PATH = os.environ.get("CONFIG_PATH", "/config/config.yaml")
SSH_KEY = os.environ.get("SSH_KEY", "/config/id_ed25519")
SSH_PUB = SSH_KEY + ".pub"

SSH_OPTS = [
    "-i", SSH_KEY, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5",
]

DISTROS = {
    "ubuntu": "Ubuntu / Debian / Mint",
    "arch": "Arch / Manjaro",
    "fedora": "Fedora / RHEL",
    "other": "Other Linux",
}
PKG_INSTALL = {
    "ubuntu": "sudo apt-get update && sudo apt-get install -y ethtool",
    "arch": "sudo pacman -S --noconfirm ethtool",
    "fedora": "sudo dnf install -y ethtool",
    "other": "# install 'ethtool' with your package manager",
}

app = Flask(__name__)


# --------------------------------------------------------------------------- #
# Config + key helpers
# --------------------------------------------------------------------------- #
def ensure_key():
    if os.path.exists(SSH_KEY):
        return
    try:
        os.makedirs(os.path.dirname(SSH_KEY) or ".", exist_ok=True)
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "pc-power-panel", "-f", SSH_KEY],
            check=True, capture_output=True,
        )
    except Exception:  # noqa: BLE001
        pass


def get_pubkey():
    try:
        with open(SSH_PUB) as f:
            return f.read().strip()
    except OSError:
        return ""


def load_config():
    try:
        with open(CONFIG_PATH) as f:
            cfg = yaml.safe_load(f) or {}
    except FileNotFoundError:
        cfg = {}
    cfg.setdefault("auth", {})
    cfg.setdefault("wol_broadcasts", ["255.255.255.255", "192.168.1.255"])
    cfg.setdefault("devices", [])
    cfg.setdefault("relays", [])
    return cfg


def save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_PATH) or ".", exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        yaml.safe_dump(cfg, f, sort_keys=False, allow_unicode=True)


def find_device(cfg, dev_id):
    return next((d for d in cfg["devices"] if d.get("id") == dev_id), None)


def find_relay(cfg, relay_id):
    return next((r for r in cfg.get("relays", []) if r.get("id") == relay_id), None)


def directed_broadcast(host):
    """Best-effort /24 directed broadcast from an IPv4 (192.168.1.50 -> 192.168.1.255)."""
    parts = (host or "").split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(parts[:3] + ["255"])
    return None


ensure_key()


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
@app.before_request
def _guard():
    if request.path == "/healthz":
        return
    # CSRF: block cross-origin state-changing requests. Browsers auto-send
    # Basic-Auth creds, so a malicious page could otherwise POST /shutdown.
    # Browsers send Origin on POST; non-browser tools (curl) send neither and pass.
    if request.method == "POST":
        origin = request.headers.get("Origin") or request.headers.get("Referer")
        if origin and urlparse(origin).netloc != request.host:
            return Response("Cross-origin request blocked (CSRF).", 403)
    # Optional Basic Auth (strongly recommended — see the warning banner)
    a = load_config().get("auth") or {}
    user, pw = a.get("user") or "", a.get("password") or ""
    if not user and not pw:
        return
    cred = request.authorization
    if (not cred
            or not hmac.compare_digest(cred.username or "", user)
            or not hmac.compare_digest(cred.password or "", pw)):
        return Response("Authentication required.", 401,
                        {"WWW-Authenticate": 'Basic realm="PC Power Panel"'})


# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #
def wake_on_lan(mac, broadcasts, extra_targets=None):
    mac = mac.replace(":", "").replace("-", "")
    packet = bytes.fromhex("FF" * 6 + mac * 16)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    # Broadcasts cover the local LAN; extra_targets (e.g. the device's own IP)
    # are a best-effort try for directed packets / subnet-router setups.
    for addr in list(broadcasts) + list(extra_targets or []):
        for port in (9, 7):
            try:
                s.sendto(packet, (addr, port))
            except OSError:
                pass
    s.close()


def remote_command(device, action):
    osname = device.get("os")
    if osname == "windows":
        return "shutdown /r /t 0" if action == "reboot" else "shutdown /s /t 0"
    if osname == "mac":
        return "sudo shutdown -r now" if action == "reboot" else "sudo shutdown -h now"
    return f"sudo systemctl {'reboot' if action == 'reboot' else 'poweroff'}"


def relay_wake_shell(relay_os, mac, targets):
    """A self-contained command to run ON the relay that emits the WoL magic
    packet on its local LAN. No package install needed: python3 on unix,
    PowerShell on Windows."""
    machex = mac.replace(":", "").replace("-", "").lower()
    addr_list = ",".join("'%s'" % a for a in targets)
    if relay_os == "windows":
        return (
            'powershell -NoProfile -Command "'
            "$mac='" + machex + "';"
            "$m=[byte[]](0..5|%{[Convert]::ToByte($mac.Substring($_*2,2),16)});"
            "$p=[byte[]]@(255,255,255,255,255,255)+($m*16);"
            "$u=New-Object System.Net.Sockets.UdpClient;$u.EnableBroadcast=$true;"
            "@(" + addr_list + ")|%{$u.Send($p,$p.Length,$_,9)|Out-Null}"
            '"'
        )
    # linux / raspberry pi / mac — zero-dependency python3
    return (
        'python3 -c "import socket;'
        "p=bytes.fromhex('ff'*6+'" + machex + "'*16);"
        "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
        "s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1);"
        "[s.sendto(p,(a,9)) for a in [" + addr_list + "]]\""
    )


def run_power(device, action, relay=None):
    # Re-validate before exec — guards against hand-edited config (SSH arg injection).
    if not parse_ssh_target(device.get("ssh")):
        return "❌ invalid SSH target in config."
    base = ["ssh"] + SSH_OPTS
    if relay and relay.get("ssh"):
        if not parse_ssh_target(relay["ssh"]):
            return "❌ invalid relay SSH target in config."
        base += ["-J", relay["ssh"]]   # ProxyJump through the site's relay
    cmd = base + [device["ssh"], remote_command(device, action)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
        if r.returncode == 0:
            return f"✅ '{action}' sent."
        err = (r.stderr or r.stdout or "").strip().splitlines()
        return f"❌ {err[-1] if err else 'exit ' + str(r.returncode)}"
    except subprocess.TimeoutExpired:
        return f"✅ '{action}' sent (connection dropped — expected)."
    except FileNotFoundError:
        return "❌ ssh not found in the image."
    except Exception as e:  # noqa: BLE001
        return f"❌ {e}"


# --------------------------------------------------------------------------- #
# Per-field "how do I find this?" helper command (Step 4)
# --------------------------------------------------------------------------- #
def field_helpers(data):
    osname = data.get("os")
    win = osname == "windows"
    mac_os = osname == "mac"
    if data.get("conn") == "tailscale":
        host = "tailscale ip -4"
    elif win:
        host = "ipconfig | findstr IPv4"
    elif mac_os:
        host = "ipconfig getifaddr en0"
    else:
        host = "hostname -I | awk '{print $1}'"
    user = "echo %USERNAME%" if win else "whoami"
    if win:
        mac = "getmac /v /fo list"
    elif mac_os:
        mac = "ifconfig en0 | awk '/ether/{print $2}'"
    else:
        mac = "cat /sys/class/net/$(ip route get 1.1.1.1 | awk '{print $5; exit}')/address"
    return host, user, mac


# --------------------------------------------------------------------------- #
# Numbered, copyable setup steps shown on the final screen
# --------------------------------------------------------------------------- #
def setup_steps(data, pubkey):
    osname = data.get("os")
    remote = data.get("conn") == "tailscale"
    via_relay = data.get("conn") == "relay"
    wol = bool(data.get("wol"))
    steps = []

    # This PC is reached through a site relay — make sure that relay is ready.
    if via_relay:
        steps.append({
            "title": "Make sure this site's relay is set up",
            "desc": "Wake packets and SSH (reboot/shutdown) for this PC go through the relay you picked. "
                    "Set it up once via Settings → Relays → 'setup steps' (install Tailscale + authorize "
                    "the panel's key). The PC itself does NOT need Tailscale.",
            "cmd": ""})

    # FIRST (only when the user wants to turn the PC on while it's off): the
    # firmware/BIOS prep that has to be done before anything else. Not needed
    # for Shutdown / Reboot.
    if wol:
        if osname == "windows":
            bios_desc = (
                "Reboot into BIOS/UEFI and turn ON 'Wake on LAN' (also called 'Power On By PCIe' / "
                "'Resume by PME'); disable 'ErP' / 'Deep Sleep' so the network card keeps power when off. "
                "Then in Windows: Device Manager → your wired adapter → Power Management → tick "
                "'Wake on Magic Packet', and turn OFF Fast Startup.")
        elif osname == "mac":
            bios_desc = (
                "Macs have no BIOS: turn on 'Wake for network access' in System Settings → "
                "Energy Saver / Battery (the WoL step below sets this for you). Note: waking a Mac "
                "that is fully shut down is limited — it works reliably from sleep.")
        else:
            bios_desc = (
                "Reboot into BIOS/UEFI and turn ON 'Wake on LAN' (also called 'Power On By PCIe' / "
                "'Resume by PME'); disable 'ErP' / 'Deep Sleep' so the network card keeps power when off.")
        steps.append({
            "title": "⚠️ FIRST — enable Wake-on-LAN in BIOS/firmware",
            "desc": bios_desc + "  This is only required to turn the PC ON while it is off, and needs "
                    "wired Ethernet. You do NOT need this step for Shutdown or Reboot.",
            "cmd": ""})

    # Remote (non-LAN) control rides over Tailscale — it must be present on both ends.
    if remote:
        steps.append({
            "title": "Install Tailscale (required for remote management)",
            "desc": "Remote control reaches this PC over Tailscale, so it must be installed and logged in "
                    "on BOTH the panel's host and this target. Get it from https://tailscale.com/download, "
                    "run 'tailscale up', then use its 100.x tailnet IP. (Wake-on-LAN does NOT work remotely — "
                    "only on the same local network.)",
            "cmd": ""})

    if osname == "windows":
        # Single line that runs from an elevated cmd OR PowerShell. The
        # administrators_authorized_keys path is global, so it works for ANY
        # admin username (no need to know the username).
        akp = "$env:ProgramData\\ssh\\administrators_authorized_keys"
        ps = (
            "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0; "
            "Start-Service sshd; Set-Service sshd -StartupType Automatic; "
            "Add-Content -Path " + akp + " -Value '" + pubkey + "'; "
            "icacls " + akp + " /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'"
        )
        one_line = 'powershell -NoProfile -ExecutionPolicy Bypass -Command "' + ps + '"'
        steps += [
            {"title": "Open Command Prompt (or PowerShell) as Administrator",
             "desc": "Click Start, type cmd, right-click and choose 'Run as administrator'. "
                     "Either cmd or PowerShell is fine for the next step.",
             "cmd": ""},
            {"title": "Enable SSH and authorize this panel",
             "desc": "Paste this ONE line and press Enter. Installs OpenSSH Server and adds the "
                     "panel's key automatically — works for any username (it runs PowerShell for you).",
             "cmd": one_line},
        ]
        return steps

    if osname == "mac":
        key_line = ("mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '" + pubkey
                    + "' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys")
        sudo_line = ('echo "$USER ALL=(ALL) NOPASSWD: /sbin/shutdown" | sudo tee '
                     "/etc/sudoers.d/pc-power-panel && sudo chmod 440 /etc/sudoers.d/pc-power-panel")
        steps += [
            {"title": "Enable Remote Login (SSH)",
             "desc": "Lets the panel sign in. Same as System Settings → General → Sharing → Remote Login.",
             "cmd": "sudo systemsetup -setremotelogin on"},
            {"title": "Authorize this panel's SSH key",
             "desc": "Adds the panel's key to your account.", "cmd": key_line},
            {"title": "Allow passwordless reboot / shutdown",
             "desc": "Auto-detects your username ($USER), so it works for anyone.", "cmd": sudo_line},
        ]
        if wol:
            steps.append({
                "title": "Turn on Wake for network access",
                "desc": "Enables waking over the network (works best from sleep). Requires wired Ethernet.",
                "cmd": "sudo systemsetup -setwakeonnetworkaccess on"})
        return steps

    # Linux — one command per step (pasting can't merge lines); $USER is detected
    # automatically, so it works whatever the username is.
    key_line = ("mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '" + pubkey
                + "' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys")
    sudo_line = ('echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl reboot, '
                 '/usr/bin/systemctl poweroff" | sudo tee /etc/sudoers.d/pc-power-panel '
                 "&& sudo chmod 440 /etc/sudoers.d/pc-power-panel")
    steps += [
        {"title": "Authorize this panel's SSH key",
         "desc": "Lets the panel securely sign in to this machine.", "cmd": key_line},
        {"title": "Allow passwordless reboot / shutdown",
         "desc": "Auto-detects your username ($USER), so it works for anyone.", "cmd": sudo_line},
    ]
    if wol:
        pkg = PKG_INSTALL.get(data.get("distro"), PKG_INSTALL["other"])
        wol_line = (
            "IFACE=$(ip route show default | awk '{print $5; exit}'); " + pkg
            + '; sudo ethtool -s "$IFACE" wol g; '
            "printf '[Unit]\\nDescription=Enable WoL\\nAfter=network-online.target\\n"
            "[Service]\\nType=oneshot\\nExecStart=/usr/sbin/ethtool -s %s wol g\\n"
            "[Install]\\nWantedBy=multi-user.target\\n' \"$IFACE\" | "
            "sudo tee /etc/systemd/system/wol-enable.service >/dev/null; "
            "sudo systemctl enable --now wol-enable.service")
        steps.append({
            "title": "Turn on Wake-on-LAN (kept after reboots)",
            "desc": "Keeps the NIC ready to wake after every boot. Requires wired Ethernet.",
            "cmd": wol_line})
    return steps


# --------------------------------------------------------------------------- #
# Relay (per-site agent) setup steps
# --------------------------------------------------------------------------- #
def relay_setup_steps(relay, pubkey):
    osname = relay.get("os", "linux")
    steps = [{
        "title": "Put this device on the SAME LAN as the PCs — and keep it always on",
        "desc": "Wired Ethernet recommended. It must share the local network (same router/subnet, "
                "no client/AP isolation) with the machines you want to wake. No port-forwarding needed.",
        "cmd": ""}]

    key_line = ("mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '" + pubkey
                + "' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys")

    if osname == "windows":
        akp = "$env:ProgramData\\ssh\\administrators_authorized_keys"
        ps = (
            "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0; "
            "Start-Service sshd; Set-Service sshd -StartupType Automatic; "
            "Add-Content -Path " + akp + " -Value '" + pubkey + "'; "
            "icacls " + akp + " /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'"
        )
        one_line = 'powershell -NoProfile -ExecutionPolicy Bypass -Command "' + ps + '"'
        steps += [
            {"title": "Install Tailscale & sign in",
             "desc": "Download from https://tailscale.com/download/windows, install, sign in — it joins "
                     "your tailnet. Use its 100.x IP as this relay's SSH host.",
             "cmd": "tailscale up"},
            {"title": "Enable SSH and authorize this panel",
             "desc": "Run in an Administrator Command Prompt or PowerShell. Wake uses built-in PowerShell.",
             "cmd": one_line},
        ]
    elif osname == "mac":
        steps += [
            {"title": "Install Tailscale & sign in",
             "desc": "Get the macOS app from https://tailscale.com/download, sign in. Use its 100.x IP "
                     "as this relay's SSH host.",
             "cmd": "sudo tailscale up"},
            {"title": "Enable Remote Login (SSH)",
             "desc": "Or System Settings → General → Sharing → Remote Login.",
             "cmd": "sudo systemsetup -setremotelogin on"},
            {"title": "Authorize this panel's SSH key",
             "desc": "Lets the panel sign in to send wake packets and proxy SSH. Wake uses python3.",
             "cmd": key_line},
        ]
    else:  # linux / raspberry pi
        steps += [
            {"title": "Install Tailscale & sign in",
             "desc": "Joins this Pi/PC to your tailnet. Use its 100.x IP as this relay's SSH host.",
             "cmd": "curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up"},
            {"title": "Authorize this panel's SSH key",
             "desc": "Lets the panel sign in to send wake packets and proxy SSH to this site's PCs.",
             "cmd": key_line},
            {"title": "Make sure Python 3 is present (sends the magic packet)",
             "desc": "Raspberry Pi OS / most Linux already have it.",
             "cmd": "python3 --version || sudo apt-get install -y python3"},
        ]

    steps.append({
        "title": "For each PC at this site",
        "desc": "Enable Wake-on-LAN in its BIOS (wired Ethernet) and authorize this panel's SSH key. "
                "Use the device wizard → connection 'Remote site (via relay)' to get the exact per-PC steps.",
        "cmd": ""})
    return steps


# --------------------------------------------------------------------------- #
# Templates
# --------------------------------------------------------------------------- #
STYLE = """
<style>
 :root{color-scheme:dark;} *{box-sizing:border-box;}
 body{font-family:system-ui,Arial,sans-serif;background:#111;color:#eee;padding:24px;max-width:760px;margin:auto;}
 a{color:#7db3ff;text-decoration:none;} h1{margin:0;} h2{margin:0 0 6px;}
 .top{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;}
 .grid{display:flex;gap:18px;flex-wrap:wrap;}
 .card{background:#1e1e1e;padding:20px;border-radius:14px;box-shadow:0 2px 8px #0006;margin-bottom:18px;}
 .dev{width:320px;} .sub{color:#8a8a8a;font-size:13px;margin-bottom:8px;word-break:break-all;}
 form.inline{margin-top:10px;}
 button{padding:13px 16px;font-size:15px;cursor:pointer;border:0;border-radius:10px;color:#fff;background:#3a6df0;}
 button.full{width:100%;}
 .wake{background:#2d7d46;}.reboot{background:#b8860b;}.shutdown{background:#9b2226;}.del{background:#444;padding:6px 12px;}
 button:hover{filter:brightness(1.12);}
 .msg{background:#1f3a5f;color:#cfe3ff;padding:12px 16px;border-radius:10px;margin-bottom:20px;}
 .empty{color:#888;}
 label{display:block;margin:12px 0 4px;color:#bbb;font-size:14px;}
 input,select{width:100%;padding:11px;border-radius:8px;border:1px solid #333;background:#161616;color:#eee;}
 .row{display:flex;gap:14px;flex-wrap:wrap;}.row>div{flex:1;min-width:150px;}
 pre{background:#000;padding:14px;border-radius:10px;overflow:auto;font-size:12.5px;border:1px solid #222;white-space:pre-wrap;margin:8px 0 6px;}
 .pill{font-size:11px;padding:2px 9px;border-radius:20px;background:#333;color:#bbb;}
 .choice{display:flex;gap:14px;flex-wrap:wrap;}
 .choice button{flex:1;min-width:130px;padding:22px;font-size:17px;background:#262626;border:1px solid #333;}
 .choice button:hover{border-color:#3a6df0;}
 .step{color:#888;font-size:13px;margin-bottom:6px;}
 .note{background:#2a2410;border:1px solid #5a4a12;color:#e9d8a6;padding:10px 14px;border-radius:8px;font-size:13px;margin:10px 0;}
 .hint{font-size:12.5px;color:#9aaab0;margin:6px 0 10px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
 .hint code{background:#000;border:1px solid #233;padding:6px 10px;border-radius:6px;color:#9fe;}
 .copy{background:#333;padding:6px 12px;font-size:12px;border-radius:6px;}
 .stepbox{display:flex;gap:14px;border-top:1px solid #2a2a2a;padding:16px 0;}
 .num{width:30px;height:30px;border-radius:50%;background:#3a6df0;color:#fff;display:flex;
      align-items:center;justify-content:center;font-weight:bold;flex-shrink:0;}
</style>
<script>
function cp(b){var c=b.previousElementSibling,t=c.innerText;
 if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t);}
 else{var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();
      try{document.execCommand('copy');}catch(e){}document.body.removeChild(a);}
 var o=b.textContent;b.textContent='✓ Copied';setTimeout(function(){b.textContent=o;},1200);}
</script>
"""


def page(body, title="PC Power Panel"):
    return ("<!doctype html><html><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<title>{title}</title>{STYLE}</head><body>{body}</body></html>")


PANEL = """
<div class="top"><h1>⚡ PC Power Panel</h1><a class="pill" href="/settings">⚙ Settings</a></div>
{% if noauth %}<div class="msg" style="background:#5a1a1a;color:#ffd9d9">⚠️ No password set — anyone who can reach this panel can power and access your machines. Set one in <a href="/settings" style="color:#fff;text-decoration:underline">Settings → Panel password</a>, and keep the panel on a trusted network (LAN / Tailscale).</div>{% endif %}
{% if msg %}<div class="msg">{{ msg }}</div>{% endif %}
<div class="grid">
{% for d in devices %}
 <div class="card dev"><h2>{{ d.name or d.id }}</h2>
  <div class="sub">{{ d.os|default('linux') }} · {{ d.ssh }}{% if d.mac %} · {{ d.mac }}{% endif %}</div>
  {% if d.mac %}<form class="inline" action="/wake/{{ d.id }}" method="post"><button class="wake full">Wake / Aç</button></form>{% endif %}
  {% if d.ssh %}<form class="inline" action="/reboot/{{ d.id }}" method="post"><button class="reboot full">Reboot</button></form>
  <form class="inline" action="/shutdown/{{ d.id }}" method="post"><button class="shutdown full">Shutdown</button></form>{% endif %}
 </div>
{% else %}<p class="empty">No devices yet. <a href="/wizard">➕ Add your first device</a>.</p>{% endfor %}
</div>
"""

SETTINGS = """
<div class="top"><h1>⚙ Settings</h1><a class="pill" href="/">← Panel</a></div>
{% if noauth %}<div class="msg" style="background:#5a1a1a;color:#ffd9d9">⚠️ No password set — set one below. Anyone who can reach this panel can otherwise power and access your machines.</div>{% endif %}
{% if msg %}<div class="msg">{{ msg }}</div>{% endif %}
<div class="card"><h2>Panel password</h2>
 <p class="sub">Recommended — anyone who reaches this panel can power your machines.</p>
 <form action="/settings/password" method="post"><div class="row">
   <div><label>Username</label><input name="user" value="{{ auth.user or '' }}"></div>
   <div><label>Password</label><input name="password" type="password" value="{{ auth.password or '' }}"></div>
 </div><br><button>Save</button></form>
</div>
<div class="card"><h2>Devices</h2>
 <p><a href="/wizard"><button>➕ Add a device (wizard)</button></a></p>
 {% for d in devices %}
  <div style="border-top:1px solid #2a2a2a;padding:12px 0">
   <b>{{ d.name or d.id }}</b> <span class="pill">{{ d.os|default('linux') }}</span>
   <span class="pill">{{ d.ssh }}</span>{% if d.wol %}<span class="pill">WoL</span>{% endif %}
   <form action="/settings/delete/{{ d.id }}" method="post" style="display:inline;float:right">
     <button class="del">Delete</button></form>
  </div>
 {% else %}<p class="empty">No devices yet.</p>{% endfor %}
</div>
<div class="card"><h2>🛰️ Relays / Sites</h2>
 <p class="sub">An always-on device (Raspberry Pi, mini-PC, NAS, any OS) on a remote LAN, joined to your
  tailnet. It wakes that site's PCs and proxies SSH to them — so the PCs themselves don't need Tailscale.</p>
 <form action="/settings/relay/add" method="post">
  <div class="row">
   <div><label>Name</label><input name="name" placeholder="Office Pi"></div>
   <div><label>Short id</label><input name="id" placeholder="office" required></div>
  </div>
  <div class="row">
   <div><label>Relay OS</label><select name="os">
     <option value="linux">Linux / Raspberry Pi</option>
     <option value="windows">Windows</option>
     <option value="mac">macOS</option></select></div>
   <div><label>SSH (user@tailscale-ip)</label><input name="ssh" placeholder="pi@100.x.x.x" required></div>
  </div>
  <br><button>➕ Add relay</button>
 </form>
 {% for r in relays %}
  <div style="border-top:1px solid #2a2a2a;padding:12px 0">
   <b>{{ r.name or r.id }}</b> <span class="pill">{{ r.os|default('linux') }}</span>
   <span class="pill">{{ r.ssh }}</span> <a class="pill" href="/relay/{{ r.id }}">📋 setup steps</a>
   <form action="/settings/relay/delete/{{ r.id }}" method="post" style="display:inline;float:right">
     <button class="del">Delete</button></form>
  </div>
 {% else %}<p class="empty">No relays yet — add one to control PCs at a remote site.</p>{% endfor %}
</div>
<div class="card"><h2>SSH public key</h2>
 <p class="sub">The panel signs in to your machines with this key.</p>
 <pre>{{ pubkey or 'not generated yet' }}</pre>
</div>
"""

WIZARD = """
<div class="top"><h1>➕ Add a device</h1><a class="pill" href="/settings">✕ Cancel</a></div>

{% if step == 'os' %}
 <div class="card"><div class="step">Step 1 of 4</div><h2>What is the target computer?</h2>
  <form method="post" action="/wizard" class="choice">
   <input type="hidden" name="step" value="conn"><input type="hidden" name="os" value="windows">
   <button>🪟 Windows</button></form>
  <form method="post" action="/wizard" class="choice" style="margin-top:14px">
   <input type="hidden" name="step" value="distro"><input type="hidden" name="os" value="linux">
   <button>🐧 Linux</button></form>
  <form method="post" action="/wizard" class="choice" style="margin-top:14px">
   <input type="hidden" name="step" value="conn"><input type="hidden" name="os" value="mac">
   <button>🍎 macOS</button></form>
 </div>

{% elif step == 'distro' %}
 <div class="card"><div class="step">Step 2 of 4 · Linux</div><h2>Which distribution?</h2>
  <p class="sub">Package manager &amp; paths differ a little per distro.</p>
  <div class="choice">
  {% for key,label in distros.items() %}
   <form method="post" action="/wizard">{{ hidden(d) }}
    <input type="hidden" name="step" value="conn"><input type="hidden" name="distro" value="{{ key }}">
    <button>{{ label }}</button></form>
  {% endfor %}</div>
 </div>

{% elif step == 'conn' %}
 <div class="card"><div class="step">Step 3 of 4</div><h2>How do you reach this computer?</h2>
  <div class="choice">
   <form method="post" action="/wizard">{{ hidden(d) }}
    <input type="hidden" name="step" value="details"><input type="hidden" name="conn" value="lan">
    <button>🏠 Same local network</button></form>
   <form method="post" action="/wizard">{{ hidden(d) }}
    <input type="hidden" name="step" value="details"><input type="hidden" name="conn" value="tailscale">
    <button>🌐 Remote (Tailscale on the PC)</button></form>
   <form method="post" action="/wizard">{{ hidden(d) }}
    <input type="hidden" name="step" value="details"><input type="hidden" name="conn" value="relay">
    <button>🛰️ Remote site (via a relay)</button></form>
  </div>
  <div class="note">🏠 Same network → enter its LAN IP. Wake-on-LAN works directly.<br>
   🌐 Remote (Tailscale on the PC) → the PC itself runs Tailscale; enter its 100.x IP. Wake-on-LAN does NOT work this way.<br>
   🛰️ Remote site (via a relay) → an always-on device (Pi/PC) on that LAN forwards Wake + proxies SSH. <b>Best for waking remote PCs.</b> Add the relay first in Settings → Relays.</div>
 </div>

{% elif step == 'details' %}
 <div class="card"><div class="step">Step 4 of 4</div><h2>Device details</h2>
  <p class="sub">Don't know a value? Run the small command under the box on the target PC
   ({{ 'Windows PowerShell' if d.os=='windows' else 'terminal' }}) — it prints the answer.</p>
  <form method="post" action="/wizard">{{ hidden(d) }}<input type="hidden" name="step" value="finish">
   <div class="row">
    <div><label>Display name (anything you like)</label><input name="name" placeholder="Living Room PC" required></div>
    <div><label>Short id</label><input name="id" placeholder="living-pc" required></div>
   </div>
   {% if d.conn == 'relay' %}
    <label>Relay / site (the always-on device that reaches this PC)</label>
    {% if relays %}
     <select name="relay" required>
      {% for r in relays %}<option value="{{ r.id }}" {% if d.relay==r.id %}selected{% endif %}>{{ r.name or r.id }} — {{ r.ssh }}</option>{% endfor %}
     </select>
    {% else %}
     <div class="note">⚠️ No relays defined yet. Add one in <a href="/settings">Settings → Relays</a> first (an always-on Pi/PC at that site, on your tailnet), then come back.</div>
    {% endif %}
   {% endif %}
   <label>{{ 'LAN IP address' if d.conn in ['lan','relay'] else 'Tailscale IP / hostname' }}</label>
   <input name="host" placeholder="{{ '192.168.1.50' if d.conn in ['lan','relay'] else '100.x.x.x' }}" required>
   <div class="hint">Don't know it? Run: <code>{{ host_cmd }}</code>
     <button type="button" class="copy" onclick="cp(this)">Copy</button></div>
   <label>SSH username on that PC</label>
   <input name="ssh_user" placeholder="user" required>
   <div class="hint">Don't know it? Run: <code>{{ user_cmd }}</code>
     <button type="button" class="copy" onclick="cp(this)">Copy</button></div>
   <label><input type="checkbox" name="wol" value="1" {% if d.wol %}checked{% endif %} style="width:auto"> Enable Wake-on-LAN — turn this PC on while it's off (wired Ethernet)</label>
   {% if d.conn == 'lan' %}
    <div class="note">⚠️ To wake a powered-off PC you must FIRST enable Wake-on-LAN in its BIOS/firmware — the final screen shows exactly how. Shutdown and Reboot work without this, so leave it unchecked if you don't need Wake.</div>
   {% elif d.conn == 'relay' %}
    <div class="note">⚠️ The relay sends the magic packet on this PC's LAN, so Wake works remotely. You still must enable Wake-on-LAN in the PC's BIOS first (wired Ethernet). Shutdown/Reboot are proxied through the relay.</div>
   {% else %}
    <div class="note">⚠️ Wake needs the magic packet to reach the PC's local network. Over plain Tailscale this won't work — use a 🛰️ relay instead. Enable WoL in the BIOS first; Shutdown/Reboot work without it.</div>
   {% endif %}
   <label>MAC address (needed for the Wake / Aç button)</label>
   <input name="mac" placeholder="aa:bb:cc:dd:ee:ff" value="{{ d.mac or '' }}">
   <div class="hint">Don't know it? Run: <code>{{ mac_cmd }}</code>
     <button type="button" class="copy" onclick="cp(this)">Copy</button></div>
   <br><button>Continue →</button>
  </form>
 </div>

{% elif step == 'finish' %}
 <div class="card"><div class="step">Last step</div>
  <h2>Set up “{{ d.name }}” — do these {{ steps|length }} steps on that PC</h2>
  <p class="sub">Run each box in order on the <b>{{ d.name }}</b> computer
   ({{ 'PowerShell as Administrator' if d.os=='windows' else 'a terminal' }}).</p>
  {% for s in steps %}
   <div class="stepbox"><div class="num">{{ loop.index }}</div>
    <div style="flex:1;min-width:0">
     <b>{{ s.title }}</b><p class="sub">{{ s.desc }}</p>
     {% if s.cmd %}<pre>{{ s.cmd }}</pre>
       <button type="button" class="copy" onclick="cp(this)">Copy</button>{% endif %}
    </div></div>
  {% endfor %}
  <form method="post" action="/settings/add" style="margin-top:18px">{{ hidden(d) }}
   <button class="full">✓ I did these — add the device</button></form>
 </div>
{% endif %}
"""

RELAY_SETUP = """
<div class="top"><h1>🛰️ Relay setup — {{ r.name or r.id }}</h1><a class="pill" href="/settings">← Settings</a></div>
<div class="card">
 <p class="sub">Prepare this always-on device ({{ r.os|default('linux') }}). Panel reaches it at <b>{{ r.ssh }}</b>.</p>
 {% for s in steps %}
  <div class="stepbox"><div class="num">{{ loop.index }}</div>
   <div style="flex:1;min-width:0">
    <b>{{ s.title }}</b><p class="sub">{{ s.desc }}</p>
    {% if s.cmd %}<pre>{{ s.cmd }}</pre>
      <button type="button" class="copy" onclick="cp(this)">Copy</button>{% endif %}
   </div></div>
 {% endfor %}
 <p style="margin-top:16px"><a href="/wizard"><button class="full">➕ Now add a PC that uses this relay</button></a></p>
</div>
"""

HIDDEN_MACRO = (
    "{% macro hidden(d) %}{% for k in ['os','distro','conn','name','id','host','ssh_user','mac','wol','relay'] %}"
    "{% if d.get(k) %}<input type='hidden' name='{{k}}' value='{{ d[k] }}'>{% endif %}{% endfor %}{% endmacro %}"
)


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
def _noauth(cfg):
    a = cfg.get("auth") or {}
    return not (a.get("user") or a.get("password"))


@app.route("/")
def index():
    cfg = load_config()
    return page(render_template_string(
        PANEL, devices=cfg["devices"], noauth=_noauth(cfg), msg=request.args.get("msg")))


@app.route("/settings")
def settings():
    cfg = load_config()
    return page(render_template_string(
        SETTINGS, devices=cfg["devices"], relays=cfg.get("relays", []),
        auth=cfg.get("auth") or {}, noauth=_noauth(cfg),
        pubkey=get_pubkey(), msg=request.args.get("msg")), "Settings")


@app.route("/settings/password", methods=["POST"])
def set_password():
    cfg = load_config()
    cfg["auth"] = {"user": request.form.get("user", "").strip(),
                   "password": request.form.get("password", "")}
    save_config(cfg)
    return redirect("/settings?msg=" + quote("Password saved."))


@app.route("/settings/delete/<dev_id>", methods=["POST"])
def delete_device(dev_id):
    cfg = load_config()
    cfg["devices"] = [d for d in cfg["devices"] if d.get("id") != dev_id]
    save_config(cfg)
    return redirect("/settings?msg=" + quote("Device removed."))


@app.route("/wizard", methods=["GET", "POST"])
def wizard():
    keys = ["os", "distro", "conn", "name", "id", "host", "ssh_user", "mac", "wol", "relay"]
    d = {k: request.form.get(k, "") for k in keys}
    step = request.form.get("step", "os") if request.method == "POST" else "os"
    host_cmd, user_cmd, mac_cmd = field_helpers(d)
    steps = setup_steps(d, get_pubkey()) if step == "finish" else []
    body = render_template_string(
        HIDDEN_MACRO + WIZARD, step=step, d=d, distros=DISTROS,
        relays=load_config().get("relays", []),
        steps=steps, host_cmd=host_cmd, user_cmd=user_cmd, mac_cmd=mac_cmd)
    return page(body, "Add device")


@app.route("/settings/add", methods=["POST"])
def add_device():
    cfg = load_config()
    f = request.form
    host = "127.0.0.1" if f.get("conn") == "local" else f.get("host", "").strip()
    dev_id = f.get("id", "").strip()
    ssh_user = (f.get("ssh_user") or "user").strip()

    if not RE_ID.match(dev_id):
        return redirect("/settings?msg=" + quote("Invalid id — use letters, digits, . _ - only."))
    if not RE_HOST.match(host):
        return redirect("/settings?msg=" + quote("Invalid host / IP address."))
    if not RE_USER.match(ssh_user):
        return redirect("/settings?msg=" + quote("Invalid SSH username."))

    osv = f.get("os", "linux")
    device = {
        "id": dev_id,
        "name": f.get("name", "").strip() or dev_id,
        "os": osv if osv in ("windows", "mac", "linux") else "linux",
        "ssh": ssh_user + "@" + host,
        "wol": bool(f.get("wol")),
    }
    if f.get("distro") in DISTROS:
        device["distro"] = f.get("distro")
    if f.get("mac", "").strip():
        mac = clean_mac(f.get("mac"))
        if not mac:
            return redirect("/settings?msg=" + quote("Invalid MAC address (use aa:bb:cc:dd:ee:ff)."))
        device["mac"] = mac
    if f.get("conn") == "relay" and f.get("relay", "").strip():
        rid = f.get("relay").strip()
        if not find_relay(cfg, rid):
            return redirect("/settings?msg=" + quote("Unknown relay."))
        device["relay"] = rid
    cfg["devices"] = [x for x in cfg["devices"] if x.get("id") != dev_id] + [device]
    save_config(cfg)
    return redirect("/?msg=" + quote("Added " + device["name"] + "."))


@app.route("/wake/<dev_id>", methods=["POST"])
def wake(dev_id):
    cfg = load_config()
    d = find_device(cfg, dev_id)
    mac = clean_mac(d.get("mac")) if d else None
    if not mac:
        return redirect("/?msg=" + quote(
            "Wake needs a valid MAC address — re-run the wizard for this device to add one."))

    host = d.get("ssh", "").split("@")[-1].strip()
    targets = ["255.255.255.255"]
    bc = directed_broadcast(host)
    if bc:
        targets.append(bc)

    relay = find_relay(cfg, d.get("relay")) if d.get("relay") else None
    if relay and relay.get("ssh"):
        if not parse_ssh_target(relay["ssh"]):
            return redirect("/?msg=" + quote("Invalid relay SSH target in config."))
        shell = relay_wake_shell(relay.get("os", "linux"), mac, targets)
        cmd = ["ssh"] + SSH_OPTS + [relay["ssh"], shell]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            ok = r.returncode == 0
            err = (r.stderr or r.stdout or "").strip().splitlines()
        except Exception:  # noqa: BLE001
            ok, err = False, []
        rname = relay.get("name", relay["id"])
        msg = (f"📶 {d.get('name', dev_id)}: wake sent via relay '{rname}'."
               if ok else
               f"❌ Relay '{rname}' problem: {err[-1] if err else 'unreachable — is it online?'}")
    else:
        wake_on_lan(mac, cfg["wol_broadcasts"], [host] if host else None)
        msg = (f"📶 {d.get('name', dev_id)}: magic packet sent. "
               "(If it doesn't power on, enable Wake-on-LAN in the BIOS — same network only.)")
    return redirect("/?msg=" + quote(msg))


@app.route("/reboot/<dev_id>", methods=["POST"])
def reboot(dev_id):
    return _power(dev_id, "reboot")


@app.route("/shutdown/<dev_id>", methods=["POST"])
def shutdown(dev_id):
    return _power(dev_id, "shutdown")


def _power(dev_id, action):
    cfg = load_config()
    d = find_device(cfg, dev_id)
    if not d or not d.get("ssh"):
        return redirect("/?msg=" + quote("No SSH target for this device."))
    relay = find_relay(cfg, d.get("relay")) if d.get("relay") else None
    return redirect("/?msg=" + quote(f"{d.get('name', dev_id)}: " + run_power(d, action, relay)))


# --------------------------------------------------------------------------- #
# Relay management
# --------------------------------------------------------------------------- #
@app.route("/settings/relay/add", methods=["POST"])
def add_relay():
    cfg = load_config()
    f = request.form
    rid = f.get("id", "").strip()
    ssh = parse_ssh_target(f.get("ssh"))
    if not RE_ID.match(rid):
        return redirect("/settings?msg=" + quote("Invalid relay id."))
    if not ssh:
        return redirect("/settings?msg=" + quote("Relay SSH must be user@host (no special characters)."))
    osv = f.get("os", "linux")
    relay = {"id": rid, "name": f.get("name", "").strip() or rid,
             "os": osv if osv in ("windows", "mac", "linux") else "linux", "ssh": ssh}
    cfg["relays"] = [x for x in cfg.get("relays", []) if x.get("id") != rid] + [relay]
    save_config(cfg)
    return redirect("/relay/" + quote(rid))


@app.route("/settings/relay/delete/<rid>", methods=["POST"])
def delete_relay(rid):
    cfg = load_config()
    cfg["relays"] = [x for x in cfg.get("relays", []) if x.get("id") != rid]
    save_config(cfg)
    return redirect("/settings?msg=" + quote("Relay removed."))


@app.route("/relay/<rid>")
def relay_page(rid):
    cfg = load_config()
    r = find_relay(cfg, rid)
    if not r:
        return redirect("/settings?msg=" + quote("Relay not found."))
    steps = relay_setup_steps(r, get_pubkey())
    return page(render_template_string(RELAY_SETUP, r=r, steps=steps), "Relay setup")


@app.route("/healthz")
def healthz():
    return {"status": "ok"}
