import pandas as pd
import os
import time
from datetime import datetime

# -------------------------
# CONFIG
# -------------------------
DATA_DIR = "data"
OUTPUT_FILE = os.path.join(DATA_DIR, "merged_summary.csv")
INTERVAL = 60  # seconds
PING_FILE = os.path.join(DATA_DIR, "ping_probe.csv")
TSHARK_FILE = os.path.join(DATA_DIR, "tshark_probe.csv")

# -------------------------
# HELPERS
# -------------------------
def read_last_row(file_path):
    if not os.path.exists(file_path) or os.stat(file_path).st_size == 0:
        return None
    try:
        df = pd.read_csv(file_path)
        return df.iloc[-1].to_dict()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def ensure_header(file):
    if not os.path.exists(file):
        os.makedirs(os.path.dirname(file), exist_ok=True)
        with open(file, "w") as f:
            f.write("timestamp,latency_ms,jitter_ms,loss_percent,total_bytes,total_pkts,tcp,udp,icmp,other\n")

# -------------------------
# MAIN LOOP
# -------------------------
def main():
    ensure_header(OUTPUT_FILE)
    print(f"[Monitor] Starting data merger, output -> {OUTPUT_FILE}")

    while True:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ping = read_last_row(PING_FILE) or {}
        tshark = read_last_row(TSHARK_FILE) or {}

        # Sử dụng tshark cho dữ liệu traffic
        merged = {
            "timestamp": now,
            "latency_ms": ping.get("latency_ms", "NaN"),
            "jitter_ms": ping.get("jitter_ms", "NaN"),
            "loss_percent": ping.get("loss_percent", "NaN"),
            "total_bytes": tshark.get("total_bytes", "NaN"),
            "total_pkts": tshark.get("total_packets", "NaN"),
            "tcp": tshark.get("tcp", "NaN"),
            "udp": tshark.get("udp", "NaN"),
            "icmp": tshark.get("icmp", "NaN"),
            "other": tshark.get("other", "NaN"),
        }

        with open(OUTPUT_FILE, "a") as f:
            f.write(",".join(str(merged[k]) for k in merged.keys()) + "\n")

        print(f"[{now}] Merged data saved.")
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
