from flask import Flask, render_template
import subprocess
import re

app = Flask(__name__)

# Your laptop's MAC address
AUTHORIZED = "d2-f3-ab-41-6e-dc"


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

        m = re.search(
            r"(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9-]{17})",
            line
        )

        if m:
            ip = m.group(1)
            mac = m.group(2).lower()

            # Ignore broadcast and multicast addresses
            if ip.startswith(("224.", "239.", "255.")):
                continue

            if mac == "ff-ff-ff-ff-ff-ff":
                continue

            # Check whether device is authorized
            if mac == AUTHORIZED:
                status = "Authorized"
                ai = "Normal"
            else:
                status = "Unauthorized"
                ai = "Anomalous"

            devices.append({
                "ip": ip,
                "mac": mac,
                "status": status,
                "ai": ai
            })

    return render_template("index.html", devices=devices)


# Run Flask using HTTPS
app.run(debug=True, ssl_context="adhoc")
