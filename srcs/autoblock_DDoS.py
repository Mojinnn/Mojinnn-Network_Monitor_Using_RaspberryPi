#!/usr/bin/env python3
import subprocess
import time
import logging
import threading
import json
import os
from collections import defaultdict, deque
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# ------------------ Config ------------------
CONFIG = {
    'bridge_iface': 'bridge0',
    'time_window': 60,

    # Network-layer floods (per IP)
    'syn_threshold': 10000,  # Test:  SYN packets
    'icmp_threshold': 5000,  # Test: ICMP packets
    'udp_threshold': 3000,  # Test: 30 UDP packets

    # Application-layer (HTTP flood per IP)
    'http_ports': [80, 443],
    'http_threshold': 5000,  # Test: 50 HTTP requests

    # DDoS Detection
    'ddos_enable': True,  # Enable DDoS detection
    'ddos_syn_total': 100, 
    'ddos_icmp_total': 5000, 
    'ddos_udp_total': 5000,  
    'ddos_http_total': 5000, 
    'ddos_unique_ips': 2,  

    'check_interval': 5,
    'whitelist': [
        '127.0.0.1',
        '192.168.1.1',
        '192.168.1.22',
        '192.168.1.10',
        '192.168.1.11'
    ],
    'log_file': '/var/log/firewall_auto_block.log',
    'alert_file': '/var/log/firewall_alerts.json'
}

# ------------------ Logging ------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(CONFIG['log_file']),
        logging.StreamHandler()
    ]
)


class DDoSDetector:
    def __init__(self):
        self.syn_count = defaultdict(lambda: deque(maxlen=5000))
        self.icmp_count = defaultdict(lambda: deque(maxlen=5000))
        self.udp_count = defaultdict(lambda: deque(maxlen=5000))
        self.http_count = defaultdict(lambda: deque(maxlen=5000))

        self.total_syn = deque(maxlen=50000)
        self.total_icmp = deque(maxlen=50000)
        self.total_udp = deque(maxlen=50000)
        self.total_http = deque(maxlen=50000)

        self.syn_sources = defaultdict(lambda: deque(maxlen=1000))
        self.icmp_sources = defaultdict(lambda: deque(maxlen=1000))
        self.udp_sources = defaultdict(lambda: deque(maxlen=1000))
        self.http_sources = defaultdict(lambda: deque(maxlen=1000))

        self.blocked_ips = set()
        self.ddos_mode = False 
        self.lock = threading.Lock()
        self.load_blocked_ips()

    # ------------------ Load blocked IP ------------------
    def load_blocked_ips(self):
        try:
            result = subprocess.run(
                ['iptables', '-t', 'raw', '-L', 'PREROUTING', '-n'],
                capture_output=True,
                text=True
            )
            for line in result.stdout.splitlines():
                if 'DROP' in line:
                    for part in line.split():
                        if self.is_valid_ip(part):
                            self.blocked_ips.add(part)
        except Exception as e:
            logging.error(f"Lỗi load blocked IPs: {e}")

    @staticmethod
    def is_valid_ip(ip):
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    # ------------------ packet process ------------------
    def process_packet(self, pkt):
        if IP not in pkt:
            return

        src_ip = pkt[IP].src
        now = time.time()

        if src_ip in CONFIG['whitelist'] or not self.is_valid_ip(src_ip):
            return

        with self.lock:
            # SYN flood
            if pkt.haslayer(TCP) and pkt[TCP].flags & 0x02:
                self.syn_count[src_ip].append(now)
                self.total_syn.append(now)
                self.syn_sources[src_ip].append(now)

            # HTTP request flood (TCP to port 80/443)
            if pkt.haslayer(TCP) and pkt[TCP].dport in CONFIG['http_ports']:
                self.http_count[src_ip].append(now)
                self.total_http.append(now)
                self.http_sources[src_ip].append(now)

            # ICMP flood
            elif pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
                self.icmp_count[src_ip].append(now)
                self.total_icmp.append(now)
                self.icmp_sources[src_ip].append(now)

            # UDP flood
            elif pkt.haslayer(UDP):
                self.udp_count[src_ip].append(now)
                self.total_udp.append(now)
                self.udp_sources[src_ip].append(now)

    # ------------------ Clean old data ------------------
    def clean_old(self, counter):
        cutoff = time.time() - CONFIG['time_window']
        for ip in list(counter.keys()):
            while counter[ip] and counter[ip][0] < cutoff:
                counter[ip].popleft()
            if not counter[ip]:
                del counter[ip]

    def clean_old_deque(self, deque_obj):
        cutoff = time.time() - CONFIG['time_window']
        while deque_obj and deque_obj[0] < cutoff:
            deque_obj.popleft()

    # ------------------ DDoS detection ------------------
    def detect_ddos(self):        
        if not CONFIG['ddos_enable']:
            return

        with self.lock:
            self.clean_old_deque(self.total_syn)
            self.clean_old_deque(self.total_icmp)
            self.clean_old_deque(self.total_udp)
            self.clean_old_deque(self.total_http)
            self.clean_old(self.syn_sources)
            self.clean_old(self.icmp_sources)
            self.clean_old(self.udp_sources)
            self.clean_old(self.http_sources)

            unique_syn_ips = len(self.syn_sources)
            unique_icmp_ips = len(self.icmp_sources)
            unique_udp_ips = len(self.udp_sources)
            unique_http_ips = len(self.http_sources)

            if (len(self.total_syn) > CONFIG['ddos_syn_total'] and
                    unique_syn_ips >= CONFIG['ddos_unique_ips']):
                self.activate_ddos_mode(
                    'SYN',
                    len(self.total_syn),
                    unique_syn_ips,
                    self.syn_sources
                )

            elif (len(self.total_icmp) > CONFIG['ddos_icmp_total'] and
                  unique_icmp_ips >= CONFIG['ddos_unique_ips']):
                self.activate_ddos_mode(
                    'ICMP',
                    len(self.total_icmp),
                    unique_icmp_ips,
                    self.icmp_sources
                )

            elif (len(self.total_udp) > CONFIG['ddos_udp_total'] and
                  unique_udp_ips >= CONFIG['ddos_unique_ips']):
                self.activate_ddos_mode(
                    'UDP',
                    len(self.total_udp),
                    unique_udp_ips,
                    self.udp_sources
                )

            elif (len(self.total_http) > CONFIG['ddos_http_total'] and
                  unique_http_ips >= CONFIG['ddos_unique_ips']):
                self.activate_ddos_mode(
                    'HTTP',
                    len(self.total_http),
                    unique_http_ips,
                    self.http_sources
                )

    # ------------------ Active DDoS mode ------------------
    def activate_ddos_mode(self, attack_type, total_packets, unique_ips, sources):
        if self.ddos_mode:
            return

        self.ddos_mode = True

        reason = f"DDoS {attack_type} detected: {total_packets} packets from {unique_ips} IPs"
        logging.critical(f"ALERT: {reason}")

        self.write_alert({
            'timestamp': time.time(),
            'type': 'DDOS_DETECTED',
            'attack_type': attack_type,
            'total_packets': total_packets,
            'unique_ips': unique_ips
        })

        sorted_ips = sorted(sources.items(), key=lambda x: len(x[1]), reverse=True)
        block_count = 0

        for ip, packets in sorted_ips[:100]:  # Block top 100 IP
            if len(packets) > 100: 
                self.block_ip(ip, f"{reason} - Contributor: {len(packets)} packets")
                block_count += 1

        logging.warning(f"DDoS Mode ACTIVE: Blocked {block_count} IPs permanently")

    # ------------------ deactive DDoS mode ------------------
    def deactivate_ddos_mode(self):
        self.ddos_mode = False
        logging.info("DDoS Mode DEACTIVATED: Traffic normalized")

        self.write_alert({
            'timestamp': time.time(),
            'type': 'DDOS_ENDED',
            'message': 'Traffic returned to normal'
        })

    # ------------------ detect DoS attack ------------------
    def check_for_attacks(self):
        with self.lock:
            self.clean_old(self.syn_count)
            self.clean_old(self.icmp_count)
            self.clean_old(self.udp_count)
            self.clean_old(self.http_count)

            for ip, times in self.syn_count.items():
                if len(times) > CONFIG['syn_threshold']:
                    self.block_ip(ip, f"SYN flood {len(times)}/{CONFIG['time_window']}s")

            for ip, times in self.icmp_count.items():
                if len(times) > CONFIG['icmp_threshold']:
                    self.block_ip(ip, f"ICMP flood {len(times)}/{CONFIG['time_window']}s")

            for ip, times in self.udp_count.items():
                if len(times) > CONFIG['udp_threshold']:
                    self.block_ip(ip, f"UDP flood {len(times)}/{CONFIG['time_window']}s")

            for ip, times in self.http_count.items():
                if len(times) > CONFIG['http_threshold']:
                    self.block_ip(
                        ip,
                        f"HTTP request flood {len(times)}/{CONFIG['time_window']}s"
                    )

    # ------------------ Block IP ------------------
    def block_ip(self, ip, reason):
        if ip in self.blocked_ips:
            return

        try:
            subprocess.run(
                ['iptables', '-t', 'raw', '-I', 'PREROUTING', '1', '-s', ip, '-j', 'DROP'],
                check=True
            )
            self.blocked_ips.add(ip)

            logging.warning(f"BLOCK {ip}: {reason}")
            self.write_alert({
                'timestamp': time.time(),
                'ip': ip,
                'reason': reason
            })
        except subprocess.CalledProcessError as e:
            logging.error(f"Lỗi block IP {ip}: {e}")

    # ------------------ Alert ------------------
    def write_alert(self, alert):
        try:
            alerts = []
            if os.path.exists(CONFIG['alert_file']):
                with open(CONFIG['alert_file']) as f:
                    alerts = json.load(f)

            alerts.append(alert)
            alerts = alerts[-200:]

            with open(CONFIG['alert_file'], 'w') as f:
                json.dump(alerts, f, indent=2)
        except Exception as e:
            logging.error(f"Lỗi ghi alert: {e}")

    # ------------------ Monitor thread ------------------
    def monitor(self):
        while True:
            self.detect_ddos() 
            self.check_for_attacks()
            time.sleep(CONFIG['check_interval'])

    # ------------------ Run ------------------
    def run(self):
        logging.info("Giám sát DoS/DDoS: SYN/ICMP/UDP/HTTP flood trên bridge")
        logging.info(f"DDoS Detection: {'ENABLED' if CONFIG['ddos_enable'] else 'DISABLED'}")
        threading.Thread(target=self.monitor, daemon=True).start()
        sniff(
            iface=CONFIG['bridge_iface'],
            prn=self.process_packet,
            store=False,
            filter="ip"
        )


def main():
    DDoSDetector().run()


if __name__ == "__main__":
    main()
