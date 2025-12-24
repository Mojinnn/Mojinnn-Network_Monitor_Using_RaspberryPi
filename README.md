# Network Monitor Using Raspberry Pi

A comprehensive network monitoring system built on Raspberry Pi that provides real-time traffic analysis, latency monitoring, and automatic DoS/DDoS protection.

## Features

- **Real-time Packet Monitoring**: Capture and analyze network packets using TShark
- **Latency & Jitter Measurement**: Track network performance metrics with ping-based monitoring
- **Automatic DDoS Protection**: Detect and block malicious IP addresses automatically
- **Web Dashboard**: Visualize network statistics and metrics in real-time
- **Data Logging**: Store packet captures and latency data for historical analysis

## Project Structure

```
.
├── docs/
│   ├── report          # Project documentation and reports
│   └── slide           # Presentation slides
│
├── srcs/
│   ├── autoblock_DDoS.py       # Automatic IP blocking for DDoS protection
│   ├── tshark_probe.py         # Packet capture and counting module
│   ├── ping_probe.py           # Latency and jitter measurement module
│   ├── main_monitor.py         # Main monitoring script (integrates modules)
│   ├── dashboard_app_new.py    # Web dashboard application
│   │
│   ├── logs/                   # Error logs and system logs
│   └── data/                   # Stored packet captures and latency data
│
└── README.md
```

## Components

### Core Modules

#### 1. `autoblock_DDoS.py`
Automatically detects and blocks suspicious IP addresses based on traffic patterns to prevent DDoS attacks.

**Key Features:**
- Pattern-based threat detection
- Automatic firewall rule management
- IP blacklist maintenance

#### 2. `tshark_probe.py`
Monitors network traffic and counts packets using TShark packet analyzer.

**Key Features:**
- Real-time packet capture
- Protocol analysis
- Traffic statistics collection

#### 3. `ping_probe.py`
Measures network performance metrics through ICMP ping requests.

**Key Features:**
- Latency measurement
- Jitter calculation
- Connection quality monitoring

#### 4. `main_monitor.py`
Integrates packet monitoring and latency measurement modules into a unified monitoring system.

**Key Features:**
- Combines tshark_probe and ping_probe functionality
- Centralized data collection
- Coordinated monitoring operations

#### 5. `dashboard_app_new.py`
Web-based dashboard for visualizing network metrics and statistics.

**Key Features:**
- Real-time data visualization
- Interactive charts and graphs
- Network status overview

### Data Storage

- **logs/**: Contains error logs and system operation logs
- **data/**: Stores captured packet data and latency measurements

## Requirements

- Raspberry Pi (3B+ or newer recommended)
- Raspbian OS / Raspberry Pi OS
- Python 3.7+
- TShark (Wireshark CLI)
- Root/sudo privileges for packet capture

## Usage

### Start the Main Monitor
```bash
cd srcs
sudo python3 main_monitor.py
```

### Launch the Web Dashboard
```bash
cd srcs
python3 dashboard_app_new.py
```

Access the dashboard at `http://<raspberry-pi-ip>:5000`

### Enable DDoS Protection
```bash
cd srcs
sudo python3 autoblock_DDoS.py
```

## Configuration

Configuration files and settings can be adjusted within each Python module. Key parameters include:

- Monitoring intervals
- Threat detection thresholds
- Dashboard refresh rates
- Data retention periods

## Documentation

Detailed documentation including system architecture, implementation details, and usage guides can be found in the `docs/` directory.

## Demo

We have a demo video uploaded on YouTube: [https://www.youtube.com/watch?v=THcwg60FWyQ](https://www.youtube.com/watch?v=THcwg60FWyQ)

## Author

Tran Anh Toan
Trinh Minh Viet
Tran Le Long Vu
