from flask import Flask, render_template, redirect, url_for
import concurrent.futures
import ipaddress
import platform
import re
import subprocess

app = Flask(__name__)

# Trusted devices
AUTHORIZED_DEVICES = {
    "dc-a9-04-93-aa-73": "My MacBook",
    "fa-4e-73-4e-d4-64": "Personal Hotspot"
}

# Devices blocked inside this demo dashboard.
# This resets when Flask restarts.
BLOCKED_DEVICES = set()


def normalize_mac(mac):
    raw_mac = mac.lower().replace("-", ":")
    parts = raw_mac.split(":")

    if len(parts) == 6:
        return "-".join(part.zfill(2) for part in parts)

    return raw_mac.replace(":", "-")


def get_local_ip():
    system = platform.system()

    if system == "Darwin":
        try:
            route = subprocess.check_output(
                ["route", "-n", "get", "default"],
                text=True,
                errors="ignore"
            )
            interface_match = re.search(r"interface:\s+(\S+)", route)

            if interface_match:
                interface = interface_match.group(1)
                ip = subprocess.check_output(
                    ["ipconfig", "getifaddr", interface],
                    text=True,
                    errors="ignore"
                ).strip()

                if ip:
                    return ip
        except subprocess.CalledProcessError:
            pass

    if system == "Windows":
        try:
            output = subprocess.check_output(
                ["ipconfig"],
                text=True,
                errors="ignore"
            )
            matches = re.findall(
                r"IPv4 Address[^:]*:\s*(\d+\.\d+\.\d+\.\d+)",
                output
            )
            for ip in matches:
                if not ip.startswith("127."):
                    return ip
        except subprocess.CalledProcessError:
            pass

    return None


def ping_host(ip):
    system = platform.system()

    if system == "Windows":
        command = ["ping", "-n", "1", "-w", "250", str(ip)]
    else:
        command = ["ping", "-c", "1", "-W", "250", str(ip)]

    subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )


def discover_network():
    local_ip = get_local_ip()

    if not local_ip:
        return None

    # Keep the project simple: scan the current /24 network.
    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)

    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as executor:
        list(executor.map(ping_host, network.hosts()))

    return str(network)


def read_arp_devices():
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

        if not m:
            continue

        ip = m.group(1)
        mac = normalize_mac(m.group(2))

        # Ignore broadcast and multicast addresses
        if ip.startswith(("224.", "239.", "255.")):
            continue

        if mac == "ff-ff-ff-ff-ff-ff":
            continue

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

    return devices


@app.route("/")
def home():
    return render_template(
        "index.html",
        devices=[],
        network=None,
        message=None
    )


@app.route("/scan")
def scan():
    network = discover_network()
    devices = read_arp_devices()

    if network:
        message = (
            f"Active scan completed for {network}. "
            "Some hotspots may hide isolated clients."
        )
    else:
        message = (
            "Could not determine the local network. "
            "Showing devices already present in the ARP table."
        )

    return render_template(
        "index.html",
        devices=devices,
        network=network,
        message=message
    )


@app.route("/block/<mac>", methods=["POST"])
def block_device(mac):
    mac = normalize_mac(mac)

    # Never block a trusted device
    if mac not in AUTHORIZED_DEVICES:
        BLOCKED_DEVICES.add(mac)

    return redirect(url_for("scan"))


# Run Flask using HTTPS
app.run(debug=True, ssl_context="adhoc")
