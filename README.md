# Unauthorized Device Detection System

A simple Flask-based Computer Networks project that actively probes the local network, reads the ARP table, and classifies detected devices as authorized or unauthorized using their MAC addresses.

## What the Project Does

When **Scan Network** is clicked:

1. The app determines the Mac/PC's current local IP address.
2. It actively probes the current /24 local subnet.
3. The operating system learns reachable neighboring devices.
4. The app reads the ARP table.
5. Each MAC address is normalized.
6. Known MAC addresses are marked **Authorized / Normal**.
7. Other detected MAC addresses are marked **Unauthorized / Anomalous**.
8. Unauthorized devices get a **Block** button.

## Trusted Devices

Trusted devices are defined in `app.py`:

```python
AUTHORIZED_DEVICES = {
    "dc-a9-04-93-aa-73": "My MacBook",
    "fa-4e-73-4e-d4-64": "Personal Hotspot"
}
```

Add another known device by adding its normalized MAC address and a name.

## Important Network Limitation

The app can discover only devices that are visible from the computer running Flask.

A normal Wi-Fi router/LAN usually allows much better local discovery.

Some mobile hotspots, including Personal Hotspot configurations, can isolate connected clients from one another. In that case another phone may be connected to the hotspot but still remain invisible to the Mac. A Flask application running on the Mac cannot override that hotspot isolation.

## About the Block Button

The **Block** button currently marks the device as blocked inside the dashboard.

It does not disconnect that device from the Wi-Fi network. Actual Wi-Fi disconnection requires administrative control of the router/access point or hotspot. The specific implementation depends on the router/hotspot platform.

## Project Structure

```text
Unauthorised-device-detection/
│
├── app.py
├── README.md
├── requirements.txt
└── templates/
    └── index.html
```

## Requirements

- Python 3
- Flask
- pyOpenSSL

Install:

```bash
pip install -r requirements.txt
```

## Run

```bash
python3 app.py
```

Then open:

```text
https://127.0.0.1:5000
```

A browser certificate warning is expected because the local Flask server uses a self-signed development certificate.

## Main Technologies

- Python
- Flask
- HTML
- ARP
- ICMP/ping-based local discovery
- Regular expressions
- MAC-address allowlisting

## Purpose

This project demonstrates local-network device discovery and simple allowlist-based unauthorized-device detection for a Computer Networks project.
