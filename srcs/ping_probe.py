
import csv
import time
from datetime import datetime
from statistics import mean
from ping3 import ping
import os
import sqlite3

# ========================
# CONFIGURATION
# ========================
TARGET_HOST = "192.168.1.1"     # IP address or domain to ping (this is my wifi)
PING_COUNT = 3              # ping times each cycle
INTERVAL = 10               # time interval between 2 measure time (s)
CSV_FILE = "data/ping_probe.csv" # output file

# ========================
# CYCLIC MEASURE FUNCTION
# ========================
def measure_ping(host, count=5):
    latencies = []
    for i in range(count):
        rtt = ping(host, timeout=2)  # get round trip time (s) or none (time out)
        if rtt is not None:
            latencies.append(rtt * 1000)  # change to ms
        time.sleep(1)
    return latencies

def compute_stats(latencies, total_sent):
    received = len(latencies)
    loss = ((total_sent - received) / total_sent) * 100 if total_sent > 0 else 0
    if received > 0:
        avg = mean(latencies)
        # jitter = average |diff 2 consecutive measure time|
        diffs = [abs(latencies[i] - latencies[i - 1]) for i in range(1, len(latencies))]
        jitter = mean(diffs) if diffs else 0
    else:
        avg, jitter = 0, 0
    return avg, jitter, loss

def ensure_csv_header(file):
    if not os.path.exists(file):
        with open(file, mode="w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "host", "latency_ms", "jitter_ms", "loss_percent"])

# ========================
# MAIN FUNCTION
# ========================
def main():
    ensure_csv_header(CSV_FILE)
    print(f"Starting ping probe to {TARGET_HOST}. Data will be saved to {CSV_FILE}")
    while True:
        latencies = measure_ping(TARGET_HOST, PING_COUNT)
        avg, jitter, loss = compute_stats(latencies, PING_COUNT)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open(CSV_FILE, mode="a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, TARGET_HOST,
                             f"{avg:.2f}" if avg else "NaN",
                             f"{jitter:.2f}" if jitter else "NaN",
                             f"{loss:.2f}"])
                        
        avg_str = f"{avg: .2f}" if avg else "NaN";
        jitter_str = f"{jitter: .2f}" if jitter else "NaN";
        loss_str = f"{loss: .1f}";

        print(f"[{timestamp}] avg = {avg_str}ms | jitter = {jitter_str}ms | loss= {loss_str}%")
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()

# implement with cmd: sudo /home/pi/venv/bin/python ping_probe.py
