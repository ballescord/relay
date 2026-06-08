# ⚡ PC Power Panel

A tiny self-hosted web panel to **wake**, **reboot**, and **shut down** the
machines on your LAN — from any browser or phone.

- **Wake** – sends a Wake-on-LAN magic packet (needs the device's MAC).
- **Reboot / Shutdown** – connects over SSH and runs `sudo systemctl reboot|poweroff`.
- Runs in **Docker**, configured with a simple `config.yaml`.
- Optional built-in **HTTP basic auth**.

![panel](docs/screenshot.png)

> ⚠️ **Security:** this panel can power your machines off. Do **not** expose it
> to the internet without authentication. Use the built-in basic auth and/or put
> it behind a VPN, reverse-proxy auth, or Cloudflare Access.

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

## License

MIT — see [LICENSE](LICENSE).
