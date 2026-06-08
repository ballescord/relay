"""
PC Power Panel — a tiny self-hosted web panel to wake / reboot / shut down
machines on your LAN.

- Wake:   sends a Wake-on-LAN magic packet (needs the device MAC).
- Reboot / Shutdown: connects over SSH and runs `sudo systemctl reboot|poweroff`
  on the target (needs an SSH key + passwordless sudo on the target).

All devices are declared in a YAML config file (see config.example.yaml).
"""

import os
import socket
import subprocess
from functools import wraps
from urllib.parse import quote

import yaml
from flask import Flask, Response, redirect, render_template_string, request

CONFIG_PATH = os.environ.get("CONFIG_PATH", "/config/config.yaml")
SSH_KEY = os.environ.get("SSH_KEY", "/config/id_ed25519")

SSH_OPTS = [
    "-i", SSH_KEY,
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=5",
]

app = Flask(__name__)


def load_config():
    try:
        with open(CONFIG_PATH) as f:
            cfg = yaml.safe_load(f) or {}
    except FileNotFoundError:
        cfg = {}
    cfg.setdefault("devices", [])
    cfg.setdefault("wol_broadcasts", ["255.255.255.255"])
    cfg.setdefault("auth", {})
    # index devices by id for quick lookup
    cfg["_by_id"] = {d["id"]: d for d in cfg["devices"] if d.get("id")}
    return cfg


def find_device(cfg, dev_id):
    return cfg["_by_id"].get(dev_id)


# --------------------------------------------------------------------------- #
# Optional HTTP Basic Auth
# --------------------------------------------------------------------------- #
@app.before_request
def _auth():
    if request.path == "/healthz":
        return  # health check is always open
    auth_cfg = load_config().get("auth") or {}
    user, pw = auth_cfg.get("user"), auth_cfg.get("password")
    if not user and not pw:
        return  # auth disabled
    a = request.authorization
    if not a or a.username != user or a.password != pw:
        return Response(
            "Authentication required.", 401,
            {"WWW-Authenticate": 'Basic realm="PC Power Panel"'},
        )


# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #
def wake_on_lan(mac, broadcasts):
    mac = mac.replace(":", "").replace("-", "")
    packet = bytes.fromhex("FF" * 6 + mac * 16)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    for addr in broadcasts:
        try:
            s.sendto(packet, (addr, 9))
        except OSError:
            pass
    s.close()


def run_power_command(ssh_target, command):
    cmd = ["ssh"] + SSH_OPTS + [ssh_target, f"sudo systemctl {command}"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
        if r.returncode == 0:
            return f"✅ '{command}' sent."
        err = (r.stderr or r.stdout or "").strip().splitlines()
        return f"❌ {err[-1] if err else 'exit ' + str(r.returncode)}"
    except subprocess.TimeoutExpired:
        # reboot/poweroff drops the connection — almost certainly fine
        return f"✅ '{command}' sent (connection dropped — expected)."
    except FileNotFoundError:
        return "❌ ssh not found in the container image."
    except Exception as e:  # noqa: BLE001
        return f"❌ {e}"


# --------------------------------------------------------------------------- #
# Web UI
# --------------------------------------------------------------------------- #
HTML = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PC Power Panel</title>
<style>
  body { font-family: system-ui, Arial, sans-serif; background:#111; color:#eee; padding:24px; }
  h1 { margin:0 0 20px; }
  .grid { display:flex; gap:20px; flex-wrap:wrap; }
  .card { background:#1e1e1e; padding:20px; border-radius:14px; width:320px; box-shadow:0 2px 8px #0006; }
  .card h2 { margin:0 0 4px; }
  .sub { color:#888; font-size:13px; margin-bottom:8px; word-break:break-all; }
  form { margin-top:10px; }
  button { width:100%; padding:14px; font-size:16px; cursor:pointer; border:0; border-radius:10px; color:#fff; }
  .wake { background:#2d7d46; } .reboot { background:#b8860b; } .shutdown { background:#9b2226; }
  button:hover { filter:brightness(1.1); }
  .msg { background:#1f3a5f; color:#cfe3ff; padding:12px 16px; border-radius:10px; margin-bottom:20px; }
  .empty { color:#888; }
  footer { margin-top:30px; color:#555; font-size:12px; }
</style>
</head>
<body>
<h1>⚡ PC Power Panel</h1>
{% if msg %}<div class="msg">{{ msg }}</div>{% endif %}
<div class="grid">
{% for d in devices %}
  <div class="card">
    <h2>{{ d.name or d.id }}</h2>
    <div class="sub">{{ d.ssh or '' }}{% if d.mac %} · {{ d.mac }}{% endif %}</div>
    {% if d.wol and d.mac %}
    <form action="/wake/{{ d.id }}" method="post"><button class="wake">Wake / Aç</button></form>
    {% endif %}
    {% if d.ssh %}
    <form action="/reboot/{{ d.id }}" method="post"><button class="reboot">Reboot</button></form>
    <form action="/shutdown/{{ d.id }}" method="post"><button class="shutdown">Shutdown</button></form>
    {% endif %}
  </div>
{% else %}
  <p class="empty">No devices configured. Edit <code>config.yaml</code> and refresh.</p>
{% endfor %}
</div>
<footer>PC Power Panel · Wake-on-LAN + SSH power control</footer>
</body>
</html>
"""


@app.route("/")
def index():
    cfg = load_config()
    return render_template_string(HTML, devices=cfg["devices"], msg=request.args.get("msg"))


@app.route("/wake/<dev_id>", methods=["POST"])
def wake(dev_id):
    cfg = load_config()
    d = find_device(cfg, dev_id)
    if d and d.get("wol") and d.get("mac"):
        wake_on_lan(d["mac"], cfg["wol_broadcasts"])
        msg = f"📶 {d.get('name', dev_id)}: magic packet sent."
    else:
        msg = "Wake is not available for this device."
    return redirect("/?msg=" + quote(msg))


@app.route("/reboot/<dev_id>", methods=["POST"])
def reboot(dev_id):
    return _power(dev_id, "reboot")


@app.route("/shutdown/<dev_id>", methods=["POST"])
def shutdown(dev_id):
    return _power(dev_id, "poweroff")


def _power(dev_id, command):
    cfg = load_config()
    d = find_device(cfg, dev_id)
    if not d or not d.get("ssh"):
        return redirect("/?msg=" + quote("No SSH target for this device."))
    name = d.get("name", dev_id)
    return redirect("/?msg=" + quote(f"{name}: " + run_power_command(d["ssh"], command)))


@app.route("/healthz")
def healthz():
    return {"status": "ok"}
