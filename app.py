from flask import Flask, render_template, redirect, url_for
import concurrent.futures
import ipaddress
import platform
import re
import socket
import subprocess
import uuid

app = Flask(__name__)

# Demo-only blocked devices. This resets when Flask restarts.
BLOCKED_DEVICES = set()


def normalize_mac(mac):
    raw_mac = mac.lower().replace("-", ":")
    parts = raw_mac.split(":")

    if len(parts) == 6:
        return "-".join(part.zfill(2) for part in parts)

    return raw_mac.replace(":", "-")


def get_local_ip():
    # Cross-platform way to find the IP used for the current network route.
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except OSError:
        return None


def get_local_mac():
    value = uuid.getnode()
    return "-".join(f"{(value >> shift) & 0xff:02x}" for shift in range(40, -1, -8))


def get_gateway_ip():
    system = platform.system()

    try:
        if system == "Darwin":
            output = subprocess.check_output(
                ["route", "-n", "get", "default"],
                text=True,
                errors="ignore"
            )
            match = re.search(r"gateway:\s+(\d+\.\d+\.\d+\.\d+)", output)
            return match.group(1) if match else None

        if system == "Windows":
            output = subprocess.check_output(
                ["ipconfig"],
                text=True,
                errors="ignore"
            )
            matches = re.findall(
                r"Default Gateway[^:]*:\s*(\d+\.\d+\.\d+\.\d+)",
                output
            )
            return matches[0] if matches else None

        # Linux and other Unix-like systems
        output = subprocess.check_output(
            ["ip", "route", "show", "default"],
            text=True,
            errors="ignore"
        )
        match = re.search(r"default via\s+(\d+\.\d+\.\d+\.\d+)", output)
        return match.group(1) if match else None

    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def ping_host(ip):
    system = platform.system()

    if system == "Windows":
        command = ["ping", "-n", "1", "-w", "300", str(ip)]
    elif system == "Darwin":
        command = ["ping", "-c", "1", "-W", "300", str(ip)]
    else:
        command = ["ping", "-c", "1", "-W", "1", str(ip)]

    try:
        subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1.5
        )
    except subprocess.TimeoutExpired:
        pass


def discover_network(local_ip):
    if not local_ip:
        return None

    # Simple project assumption: scan the current /24 LAN.
    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)

    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as executor:
        list(executor.map(ping_host, network.hosts()))

    return str(network)


def read_arp_entries():
    entries = []

    try:
        result = subprocess.check_output(
            ["arp", "-a"],
            text=True,
            errors="ignore"
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return entries

    for line in result.splitlines():
        # macOS/Linux example:
        # ? (192.168.1.10) at aa:bb:cc:dd:ee:ff ...
        # Windows example:
        # 192.168.1.10    aa-bb-cc-dd-ee-ff    dynamic
        match = re.search(
            r"\(?(\d+\.\d+\.\d+\.\d+)\)?(?:\s+at)?\s+([a-fA-F0-9:-]{11,17})",
            line
        )

        if not match:
            continue

        ip = match.group(1)
        mac = normalize_mac(match.group(2))

        if ip.startswith(("224.", "239.", "255.")):
            continue

        if mac == "ff-ff-ff-ff-ff-ff":
            continue

        entries.append({"ip": ip, "mac": mac})

    return entries


def build_device_list(local_ip, gateway_ip):
    devices = []
    seen_ips = set()

    for entry in read_arp_entries():
        ip = entry["ip"]
        mac = entry["mac"]

        if ip == local_ip:
            name = "This Device"
            status = "Authorized"
            analysis = "Trusted host"
        elif ip == gateway_ip:
            name = "Network Gateway"
            status = "Authorized"
            analysis = "Trusted gateway"
        elif mac in BLOCKED_DEVICES:
            name = "Third-Party Device"
            status = "Blocked"
            analysis = "Access blocked (demo)"
        else:
            name = "Third-Party Device"
            status = "Unauthorized"
            analysis = "Unknown device"

        devices.append({
            "name": name,
            "ip": ip,
            "mac": mac,
            "status": status,
            "analysis": analysis
        })
        seen_ips.add(ip)

    # Some operating systems do not place the host itself in their ARP table.
    if local_ip and local_ip not in seen_ips:
        devices.insert(0, {
            "name": "This Device",
            "ip": local_ip,
            "mac": get_local_mac(),
            "status": "Authorized",
            "analysis": "Trusted host"
        })

    return devices


def dashboard_data(run_scan=False):
    local_ip = get_local_ip()
    gateway_ip = get_gateway_ip()
    network = discover_network(local_ip) if run_scan else (
        str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
        if local_ip else None
    )

    devices = build_device_list(local_ip, gateway_ip) if run_scan else []

    authorized = sum(d["status"] == "Authorized" for d in devices)
    unauthorized = sum(d["status"] == "Unauthorized" for d in devices)
    blocked = sum(d["status"] == "Blocked" for d in devices)

    return {
        "devices": devices,
        "local_ip": local_ip,
        "gateway_ip": gateway_ip,
        "network": network,
        "authorized_count": authorized,
        "unauthorized_count": unauthorized,
        "blocked_count": blocked
    }


@app.route("/")
def home():
    data = dashboard_data(run_scan=False)
    return render_template("index.html", scanned=False, **data)


@app.route("/scan")
def scan():
    data = dashboard_data(run_scan=True)
    return render_template("index.html", scanned=True, **data)


@app.route("/block/<mac>/<ip>", methods=["POST"])
def block_device(mac, ip):
    local_ip = get_local_ip()
    gateway_ip = get_gateway_ip()
    mac = normalize_mac(mac)

    # The current host and the network gateway are always trusted.
    if ip not in {local_ip, gateway_ip}:
        BLOCKED_DEVICES.add(mac)

    return redirect(url_for("scan"))


@app.route("/unblock/<mac>", methods=["POST"])
def unblock_device(mac):
    BLOCKED_DEVICES.discard(normalize_mac(mac))
    return redirect(url_for("scan"))


if __name__ == "__main__":
    app.run(debug=True, ssl_context="adhoc")
