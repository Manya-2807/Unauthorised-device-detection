# Unauthorized Device Detection System

A simple Flask-based Computer Networks project that discovers visible devices on the current local network and automatically classifies them by role.

## Automatic Authorization Logic

The project no longer depends on hardcoded MAC addresses.

On every computer where the app runs:

- **This Device** — the computer running Flask — is automatically **Authorized**.
- **Network Gateway** — the router or hotspot providing the connection — is automatically **Authorized**.
- **Every other visible device** is classified as **Unauthorized**.
- Unauthorized devices receive a demo **Block** option.

This makes the same project portable across macOS, Windows, Linux, iPhone hotspots, Android hotspots, and normal Wi-Fi routers without editing trusted-device MAC addresses.

## How Scan Network Works

1. Detect the current device's local IP address.
2. Detect the network's default gateway.
3. Probe the current /24 local subnet.
4. Read the operating system ARP table.
5. Compare each discovered IP with the local host and gateway.
6. Classify devices as Authorized, Unauthorized, or Blocked.
7. Display results in the Flask dashboard.

## Demo Blocking

The **Block** button intentionally simulates blocking inside the dashboard.

It changes the selected third-party device to **Blocked** and offers an **Unblock** button.

A future version can connect this same UI action to a router/access-point API or firewall management system for real network enforcement.

## Important Network Limitation

The project can discover only devices that are visible from the computer running Flask.

A normal Wi-Fi LAN usually gives better peer visibility. Some mobile hotspots isolate connected clients. If a hotspot hides one client from another, that device may not appear even though it is connected. Client isolation is controlled by the hotspot/router and cannot be overridden by this Flask application.

## Project Structure

```text
Unauthorised-device-detection/
│
├── app.py
├── README.md
├── requirements.txt
├── static/
│   └── style.css
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

A browser certificate warning is expected because Flask is using a local self-signed development certificate.

## Main Technologies

- Python
- Flask
- HTML/CSS
- ARP
- ICMP/ping-based LAN discovery
- Default-gateway discovery
- Role-based device authorization

## Purpose

This project demonstrates local-network discovery, simple automatic authorization, unauthorized-device identification, and a simulated response workflow for a Computer Networks project.
