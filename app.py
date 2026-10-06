from flask import Flask, render_template, redirect, url_for
import subprocess
import re

app = Flask(__name__)

# Trusted devices
AUTHORIZED_DEVICES = {
    "dc-a9-04-93-aa-73": "My MacBook",
    "fa-4e-73-4e-d4-64": "Personal Hotspot"
}

# Devices blocked from the dashboard.
# This is kept simple for the project and resets when Flask restarts.
BLOCKED_DEVICES = set()


def normalize_mac(mac):
    raw_mac = mac.lower().replace("-", ":")
    parts = raw_mac.split(":")

    if len(parts) == 6:
        return "-".join(part.zfill(2) for part in parts)

    return raw_mac.replace(":", "-")


@app.route("/")
def home():
    return render_template("index.html", devices=[])


@app.route("/scan")
def scan():
    devices = []

    result = subprocess.check_output(
        ["arp", "-a"],
        text=True,
        errors="ignore"
    )

    for line in result.splitlines():

        # Supports both macOS and Windows ARP output
        m = re.search(
            r"\(?(\d+\.\d+\.\d+\.\d+)\)?(?:\s+at)?\s+([a-fA-F0-9:-]{11,17})",
            line
        )

        if m:
            ip = m.group(1)
            mac = normalize_mac(m.group(2))

            # Ignore broadcast and multicast addresses
            if ip.startswith(("224.", "239.", "255.")):
                continue

            if mac == "ff-ff-ff-ff-ff-ff":
                continue

            # Check whether device is authorized, blocked, or unauthorized
            if mac in AUTHORIZED_DEVICES:
                name = AUTHORIZED_DEVICES[mac]
                status = "Authorized"
                ai = "Normal"
            elif mac in BLOCKED_DEVICES:
                name = "Unknown Device"
                status = "Blocked"
                ai = "Blocked"
            else:
                name = "Unknown Device"
                status = "Unauthorized"
                ai = "Anomalous"

            devices.append({
                "name": name,
                "ip": ip,
                "mac": mac,
                "status": status,
                "ai": ai
            })

    return render_template("index.html", devices=devices)


@app.route("/block/<mac>", methods=["POST"])
def block_device(mac):
    mac = normalize_mac(mac)

    # Never block a trusted device
    if mac not in AUTHORIZED_DEVICES:
        BLOCKED_DEVICES.add(mac)

    return redirect(url_for("scan"))


# Run Flask using HTTPS
app.run(debug=True, ssl_context="adhoc")
