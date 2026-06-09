# ⚡ PC Power Panel

A tiny self-hosted web panel to **wake**, **reboot**, and **shut down** your
machines — from any browser or phone.

- **Wake** – sends a Wake-on-LAN magic packet (needs the device's MAC).
- **Reboot / Shutdown** – connects over SSH; OS-aware commands for **Windows, macOS and Linux**.
- **Remote sites via a relay** – an always-on device (Raspberry Pi, mini-PC, NAS… any OS) on a
  remote LAN, joined to your [Tailscale](https://tailscale.com) tailnet, wakes that site's PCs and
  proxies SSH to them (`ssh -J`) — so the PCs themselves don't need Tailscale.
- **Browser wizard** – step-by-step device setup; each field shows a "how to find this" command and
  the final screen prints the exact, copyable setup steps for the target OS.
- Runs in **Docker**, configured with a simple `config.yaml`.
- Optional built-in **HTTP basic auth**.

![panel](docs/screenshot.png)

> ⚠️ **Security:** this panel can power your machines off and holds an SSH key to them. **Set a
> password** and keep it on a trusted network (LAN / Tailscale). Do **not** expose it to the
> internet without authentication — ideally also put it behind a VPN, reverse-proxy auth, or
> Cloudflare Access. See [Privacy & Security](#privacy--security) below.

---

## 1. Get the files

```bash
git clone https://github.com/YOURNAME/pc-power-panel.git
cd pc-power-panel
mkdir -p config
cp config.example.yaml config/config.yaml
```

## 2. Generate an SSH key (for reboot/shutdown)

This key lets the panel run power commands on your machines.

```bash
ssh-keygen -t ed25519 -N "" -C "pc-power-panel" -f config/id_ed25519
```

The Wake feature alone does **not** need this key — skip this step if you only
want Wake-on-LAN.

## 3. Configure your devices

Edit `config/config.yaml`:

```yaml
auth:
  user: "admin"          # leave empty to disable the login prompt
  password: "change-me"

wol_broadcasts:
  - "255.255.255.255"

devices:
  - id: desktop
    name: "My Desktop"
    mac: "aa:bb:cc:dd:ee:ff"   # for Wake
    ssh: "user@192.168.1.50"   # for Reboot/Shutdown
    wol: true
  - id: server
    name: "Home Server"
    ssh: "user@192.168.1.10"
    wol: false
```

## 4. Prepare each target machine

Do this **once per machine** you want to reboot/shutdown (the `ssh:` targets).

**a) Authorize the panel's key** (run on the target, as the `user` from `ssh:`):

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo 'PASTE_CONTENTS_OF_config/id_ed25519.pub_HERE' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

**b) Allow passwordless power commands** (run on the target):

```bash
echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl reboot, /usr/bin/systemctl poweroff" \
  | sudo tee /etc/sudoers.d/pc-power-panel
sudo chmod 440 /etc/sudoers.d/pc-power-panel
```

**c) (Wake only) Enable Wake-on-LAN** on the target — needs **wired Ethernet**:

```bash
# find your interface (e.g. enp6s0):
ip -br link
# enable WoL now:
sudo ethtool -s <iface> wol g
```

Also enable **"Wake on LAN" in the BIOS/UEFI**. To make it persist across cold
boots, create a small systemd service:

```bash
printf '[Unit]\nDescription=Enable WoL\nAfter=network-online.target\n\n[Service]\nType=oneshot\nExecStart=/usr/sbin/ethtool -s <iface> wol g\n\n[Install]\nWantedBy=multi-user.target\n' \
  | sudo tee /etc/systemd/system/wol-enable.service
sudo systemctl enable --now wol-enable.service
```

## 5. Run it

```bash
docker compose up -d --build
```

Open **http://SERVER-IP:8765**.

> `network_mode: host` is used so Wake-on-LAN broadcasts reach your LAN. If your
> platform doesn't support host networking, switch to the `ports:` mapping in
> `docker-compose.yml` — Wake may then require a directed broadcast in
> `wol_broadcasts` and a network that forwards it.

---

## How it works

```
pc-power-panel (container, host network)
  ├── Wake     → UDP magic packet → LAN broadcast (port 9)
  └── Reboot   → ssh -i id_ed25519 user@host  "sudo systemctl reboot"
      Shutdown → ssh -i id_ed25519 user@host  "sudo systemctl poweroff"
```

The panel's own host can be a target too — point `ssh:` at `user@127.0.0.1`
(works with host networking).

## Configuration reference

| Key | Description |
|---|---|
| `auth.user` / `auth.password` | Enable HTTP basic auth (empty = disabled). |
| `wol_broadcasts` | List of broadcast addresses for magic packets. |
| `devices[].id` | Unique id used in URLs. |
| `devices[].name` | Label shown on the card. |
| `devices[].mac` | MAC address (required for Wake). |
| `devices[].ssh` | `user@host` SSH target (required for Reboot/Shutdown). |
| `devices[].wol` | `true` to show the Wake button. |

Environment overrides: `CONFIG_PATH` (default `/config/config.yaml`),
`SSH_KEY` (default `/config/id_ed25519`).

## Troubleshooting

| Problem | Likely cause |
|---|---|
| Reboot/Shutdown shows an SSH error | Key not in target's `authorized_keys`, or sudoers rule missing. |
| Reboot says "a password is required" | The `NOPASSWD` sudoers rule (step 4b) is missing/incorrect. |
| Wake does nothing | WoL disabled in BIOS/NIC, machine on Wi-Fi (use Ethernet), or wrong broadcast. |
| 500 / `ssh not found` | Rebuild the image (`docker compose up -d --build`). |

## Privacy & Security

**Your data never leaves your infrastructure.**

- **No telemetry, no analytics, no phone-home.** The app makes **no outbound connection** to any
  third party. The UI loads no external scripts, fonts, or CDNs — all CSS/JS is inline.
- **Everything stays local.** Whatever you enter (IPs, MACs, SSH usernames, the panel password) is
  written only to your own `config/config.yaml` on your own host, and is used solely to connect to
  the machines **you** configure. The only network traffic the app generates is: Wake-on-LAN packets
  on your LAN, and SSH to the hosts/relays you defined.
- **Secrets stay out of git.** `config/` and `id_ed25519*` are git-ignored — your config, password
  and SSH key are never committed.

**Hardening built in:**

- **Input validation** on every device/relay field (IDs, hostnames, SSH usernames, MACs) to block
  SSH-argument and shell-command injection — values that could be parsed as SSH options (e.g. a
  leading `-`) or contain shell metacharacters are rejected.
- **CSRF protection** — cross-origin state-changing requests are blocked (the panel uses Basic Auth,
  which browsers auto-send, so this matters).
- **Constant-time** password comparison.
- A loud **warning banner** when no password is set.

**Your responsibilities:**

- **Set a password** (Settings → Panel password). Without one, anyone who can reach the panel can
  power and access your machines.
- **Run it on a trusted network.** The panel speaks plain HTTP (Basic Auth in clear), so keep it on
  your LAN / Tailscale, or terminate TLS at a reverse proxy. Don't expose it to the public internet.
- The panel holds an **SSH key that can reboot/shutdown all your machines** — treat the panel host
  as sensitive. SSH host-key checking is intentionally relaxed for usability, so rely on a trusted/
  encrypted transport (LAN, Tailscale).

## License

MIT — see [LICENSE](LICENSE).
