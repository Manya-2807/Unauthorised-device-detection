# Unauthorized Device Detection System

A simple Flask-based network security project that scans devices visible on the local network and identifies whether each device is authorized or unauthorized using its MAC address.

## Project Overview

The application uses the system ARP table to detect devices connected to the local network. Each detected device is compared against a predefined authorized MAC address.

The result is displayed in a simple web dashboard showing:

- IP Address
- MAC Address
- Authorization Status
- Basic Analysis Result

## How It Works

1. The Flask application starts a local HTTPS web server.
2. The user opens the dashboard in a browser.
3. Clicking **Scan Network** runs the `arp -a` command.
4. The program extracts IP and MAC addresses from the result.
5. Broadcast and multicast addresses are ignored.
6. Each device MAC address is compared with the authorized MAC address.
7. The dashboard displays whether each device is:
   - **Authorized / Normal**
   - **Unauthorized / Anomalous**

## Project Structure

```text
Unauthorised-device-detection/
│
├── app.py
├── requirements.txt
└── templates/
    └── index.html
```

## Requirements

- Python 3
- Flask
- pyOpenSSL

Install the required packages using:

```bash
pip install -r requirements.txt
```

## Running the Project

Run:

```bash
python app.py
```

Flask will start the application using HTTPS.

Open the local address shown in the terminal in your browser.

Because the project uses a self-signed development certificate, the browser may display a security warning when opening the page locally.

## Main Technologies

- Python
- Flask
- HTML
- ARP network discovery
- Regular expressions

## Important Note

The authorized MAC address is currently defined directly inside `app.py`:

```python
AUTHORIZED = "d2-f3-ab-41-6e-dc"
```

Change this value if the system needs to recognize a different device as authorized.

## Purpose

This project is intended as a simple demonstration of local network device detection and basic unauthorized-device identification for a Computer Networks project.
