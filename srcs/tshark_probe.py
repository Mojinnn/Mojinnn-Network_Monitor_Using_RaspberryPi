import subprocess
import json
import tempfile
import os
import csv
import time
import shutil
from datetime import datetime
import argparse

# -------------------------
# CONFIG
# -------------------------
DEFAULT_IFACE = "bridge0"        # None -> tshark use default interface, or get "eth0"/"Wi-Fi"
CAPTURE_TIME = 10           # capture time for each cyclic
INTERVAL = 60               # between 2 capture times
CSV_FILE = "data/tshark_probe.csv"

# -------------------------
# HELPERS
# -------------------------
def check_tshark():
    tshark_path = shutil.which("tshark")
    if not tshark_path:
        raise RuntimeError("tshark can not found. Install Wireshark/tshark before run, please.")
    return tshark_path

def capture_to_pcap(iface, duration, out_pcap_path):
    cmd = ["tshark"] 
    if iface:
        cmd += ["-i", iface]
    cmd += ["-a", f"duration:{duration}", "-w", out_pcap_path]
    subprocess.run(cmd, check=True)

def tshark_pcap_to_json(pcap_path):
    cmd = ["tshark", "-r", pcap_path, "-T", "json"]  # transfer pcap to json with cmd
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)  # implement cmd to get JSON output
    data = proc.stdout.decode('utf-8', errors='replace')    # utf-8 (JSON standard data) to string
    return json.loads(data) # return JSON to Python object to analyze

def analyze_packets_from_json(json_packets):
    total = 0
    tcp = udp = icmp = other = 0
    total_bytes = 0

    # get data len (byte) function
    for pkt in json_packets:
        total += 1
        layers = pkt.get("_source", {}).get("layers", {})
        frame = layers.get("frame", {})
        fl = 0
        if isinstance(frame, dict):     # check frame is dict (what Python work)
            flv = frame.get("frame.len")
            if isinstance(flv, list) and len(flv) > 0: # check if flv is list data type
                try:
                    fl = int(flv[0])
                except:
                    fl = 0
            elif isinstance(flv, str):  # check if flv is string data type
                try:
                    fl = int(flv)
                except:
                    fl = 0
        total_bytes += fl

        # put all keys to a set to check
        keys = set(k.lower() for k in layers.keys())

        if "tcp" in keys:
            tcp += 1
        elif "udp" in keys:
            udp += 1
        elif "icmp" in keys or "icmpv6" in keys:
            icmp += 1
        else:
            other += 1

    return {
        "total": total,
        "tcp": tcp,
        "udp": udp,
        "icmp": icmp,
        "other": other,
        "bytes": total_bytes
    }

def ensure_csv_header(file):
    if not os.path.exists(file):
        os.makedirs(os.path.dirname(file), exist_ok=True)
        with open(file, mode="w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "iface", "capture_time_s", "total_pkts", "tcp", "udp", "icmp", "other", "total_bytes"])


# -------------------------
# MAIN LOOP
# -------------------------
def main(args):
    tshark_path = check_tshark()
    iface = args.iface or DEFAULT_IFACE
    capture_time = args.capture_time
    interval = args.interval
    csv_file = args.csv

    ensure_csv_header(csv_file)
    print("tshark path:", tshark_path)
    print(f"Start TShark probe — iface={iface} capture_time={capture_time}s interval={interval}s → CSV: {csv_file}")
    print("Note: you may need to run this script with Administrator / sudo to capture on an interface.\n")

    try:
        while True:
            # create temporary pcap
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                tmp_path = tmp.name
            try:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Capturing {capture_time}s into {tmp_path} ...")
                # capture
                capture_to_pcap(iface, capture_time, tmp_path)
                # convert to JSON
                json_packets = tshark_pcap_to_json(tmp_path)
                # analyze
                stats = analyze_packets_from_json(json_packets)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                # append to CSV
                with open(csv_file, mode="a", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([timestamp, iface or "default", capture_time,
                                     stats["total"], stats["tcp"], stats["udp"], stats["icmp"], stats["other"], stats["bytes"]])
                print(f"[{timestamp}] total={stats['total']} | tcp={stats['tcp']} | udp={stats['udp']} | icmp={stats['icmp']} | other={stats['other']} | bytes={stats['bytes']}")
            finally:
                # delete temporary pcap
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

            time.sleep(interval)

    except KeyboardInterrupt:
        print("Stopped by user.")

# -------------------------
# CLI
# -------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TShark probe: capture -> json -> analyze -> csv")
    parser.add_argument("--iface", "-i", default=DEFAULT_IFACE, help="Interface name (e.g. eth0, Wi-Fi). If omitted, tshark default interface is used.")
    parser.add_argument("--capture-time", "-c", type=int, default=CAPTURE_TIME, help="Capture duration in seconds")
    parser.add_argument("--interval", "-t", type=int, default=INTERVAL, help="Interval between captures (seconds)")
    parser.add_argument("--csv", default=CSV_FILE, help="CSV output filename")
    args = parser.parse_args()
    main(args)

    # run code: sudo python3 tshark_probe.py
    # run code with example cli: sudo python3 tshark_probe.py --iface bridge0 --capture-time 10 --interval 60 --csv data/tshark_probe.csv
    # run code always with: sudo nohup python3 tshark_probe.py --iface bridge0 --capture-time 10 --interval 60 --csv data/tshark_probe.csv &
