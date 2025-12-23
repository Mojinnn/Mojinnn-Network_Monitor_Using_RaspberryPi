#!/usr/bin/env python3
# app.py — Flask dashboard for Pi NetWatch (strict 2-day data only)
from flask import Flask, render_template_string, jsonify
import pandas as pd
import os
from datetime import datetime, timedelta

app = Flask(__name__)

# Files produced by your probes / merger
MERGED_CSV = "data/merged_summary.csv"
PING_CSV = "data/ping_probe.csv"
TSHARK_CSV = "data/tshark_probe.csv"

# Configuration for strict 2-day retention
MAX_RECORDS = 2880  # 2 days * 24 hours * 60 minutes (1min interval)
CHART_DISPLAY_LIMIT = 2880  # Only load last 2 days
AUTO_CLEANUP_THRESHOLD = 3000  # More aggressive cleanup
RETENTION_DAYS = 2  # Strict 2-day retention

# HTML template with 2-day data only
TEMPLATE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Pi NetWatch — Dashboard </title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body { font-family: Inter, Arial, sans-serif; margin:12px; background:#f6f7fb; color:#111; }
h1 { text-align:center; margin-bottom:8px; }
.status-bar { text-align:center; margin:10px auto; padding:8px; background:#e3f2fd; border-radius:8px; max-width:800px; font-size:13px; }
.retention-info { text-align:center; margin:5px auto; padding:5px; background:#fff3cd; border-radius:6px; max-width:600px; font-size:12px; color:#856404; }
.donut-row { display:flex; gap:18px; flex-wrap:wrap; justify-content:center; padding-bottom:6px; }
.card { background:#fff; border-radius:12px; box-shadow:0 4px 18px rgba(20,20,40,0.06); padding:14px; }
.donut-card { flex:0 0 auto; width:400px; padding:10px; text-align:center; min-height:280px; display:flex; flex-direction:column; justify-content:flex-start; }
.donut-card canvas { width:100% !important; height:240px !important; }
.chart-card { width:90%; max-width:1200px; margin:10px auto; padding:16px 12px; position:relative; overflow:visible; }
.chart-card canvas { width:100% !important; max-height:280px !important; height:280px !important; display:block; margin:0 auto; }
.label { font-weight:600; margin-bottom:6px; display:block; }
.kpi { font-size:18px; margin-top:8px; }
@media (max-width:900px){ .donut-card{ width:48%; } .chart-card{ width:95%; } }
@media (max-width:520px){ .donut-card{ width:100%; } }
</style>
</head>
<body>
<h1>📡 Pi NetWatch — Dashboard </h1>
<div class="status-bar" id="statusBar">
  Loading data... | Records: <span id="recordCount">0</span> | Displayed: <span id="displayCount">0</span> | Last update: <span id="lastUpdate">N/A</span>
</div>
<div class="retention-info">
  ℹ️ Displaying data from last 2 days only • Older data automatically cleaned
</div>

<div class="donut-row" style="margin-bottom:14px;">
  <div class="card donut-card">
    <div class="label">Ping: Success vs Loss (%)</div>
    <canvas id="pingDonut"></canvas>
    <div class="kpi" id="ping_kpi"></div>
  </div>

  <div class="card donut-card">
    <div class="label">TShark: Proto distribution (pkts)</div>
    <canvas id="tsharkDonut"></canvas>
    <div class="kpi" id="tshark_kpi"></div>
  </div>
</div>

<div class="chart-card card">
  <div class="label">Ping — Latency (ms) & Loss (%) <span style="font-weight:400;font-size:12px;">(Last 2 days: <span id="pingPoints">0</span> points)</span></div>
  <canvas id="pingChart"></canvas>
</div>

<div class="chart-card card">
  <div class="label">TShark — Protocol History (TCP, UDP, ICMP, Other) <span style="font-weight:400;font-size:12px;">(Last 2 days: <span id="protocolPoints">0</span> points)</span></div>
  <canvas id="protocolChart"></canvas>
</div>

<div class="chart-card card">
  <div class="label">TShark — Packets & Bytes <span style="font-weight:400;font-size:12px;">(Last 2 days: <span id="tsharkPoints">0</span> points)</span></div>
  <canvas id="tsharkChart"></canvas>
</div>

<script>
const protoColors=['#2ca8ff','#ff6b8a','#ffb463','#ffe07a'];

function mkDonut(el){
  return new Chart(document.getElementById(el), {
    type:'doughnut',
    data:{labels:['TCP','UDP','ICMP','Other'], datasets:[{data:[0,0,0,0], backgroundColor:protoColors, borderColor:'#fff', borderWidth:2}]},
    options:{maintainAspectRatio:false, plugins:{legend:{position:'top'}}}
  });
}

const pingDonut = new Chart(document.getElementById('pingDonut'), {
  type:'doughnut',
  data:{labels:['Success %','Loss %'], datasets:[{data:[100,0], backgroundColor:['#2ca8ff','#ff6b8a'], borderColor:'#fff', borderWidth:2}]},
  options:{maintainAspectRatio:false, plugins:{legend:{position:'top'}}}
});
const tsharkDonut = mkDonut('tsharkDonut');

// Filter data to STRICT last 2 days only
function filterLast2Days(data) {
  if (!data || data.length === 0) return [];

  // Get the most recent timestamp
  const lastRecord = data[data.length - 1];
  if (!lastRecord || !lastRecord.timestamp) return data;

  try {
    // Parse the last timestamp (format: YYYY-MM-DD HH:MM:SS)
    const lastTime = new Date(lastRecord.timestamp);

    // Calculate EXACTLY 2 days ago from the last timestamp
    const twoDaysAgo = new Date(lastTime.getTime() - (2 * 24 * 60 * 60 * 1000));

    // Filter data within last 2 days ONLY
    const filtered = data.filter(record => {
      if (!record.timestamp) return false;
      const recordTime = new Date(record.timestamp);
      return recordTime >= twoDaysAgo && recordTime <= lastTime;
    });

    console.log(`📊 Filtered: ${filtered.length} records from last 2 days (${twoDaysAgo.toISOString()} to ${lastTime.toISOString()})`);
    return filtered;
  } catch (e) {
    console.warn('Error filtering by date:', e);
    return data.slice(-2880); // Fallback: keep last 2880 records (2 days if 1min interval)
  }
}

// Smart sampling for better chart readability
function smartSample(data, maxPoints = 120) {
  if (!data || data.length === 0) return [];
  if (data.length <= maxPoints) return data;

  const result = [];
  result.push(data[0]); // Always include first point

  const middleCount = maxPoints - 2;
  const totalMiddle = data.length - 2;
  const step = totalMiddle / middleCount;

  for (let i = 1; i <= middleCount; i++) {
    const index = Math.round(i * step);
    if (index > 0 && index < data.length - 1) {
      result.push(data[index]);
    }
  }

  if (data.length > 1) {
    result.push(data[data.length - 1]); // Always include last point
  }

  return result;
}

// Line charts
function mkLine(el, labels=[], datasetDefs=[]){
  return new Chart(document.getElementById(el), {
    type:'line',
    data:{labels:labels, datasets: datasetDefs},
    options:{
      responsive:true,
      maintainAspectRatio:false,
      layout: {
        padding: {
          left: 10,
          right: 25,
          top: 10,
          bottom: 10
        }
      },
      plugins:{
        legend:{position:'top'},
        tooltip:{
          mode: 'index',
          intersect: false
        }
      },
      scales:{
        x:{
          ticks:{
            autoSkip: false,
            maxRotation: 45,
            minRotation: 45,
            font: {
              size: 9
            },
            callback: function(value, index, ticks) {
              const totalLabels = this.chart.data.labels.length;
              if (index === 0 || index === ticks.length - 1) {
                return this.getLabelForValue(value);
              }
              const maxLabels = 12;
              const step = Math.ceil(totalLabels / maxLabels);
              if (index % step === 0) {
                return this.getLabelForValue(value);
              }
              return null;
            }
          },
          grid: {
            display: true,
            drawBorder: true
          }
        },
        y: {
          ticks: {
            font: {
              size: 10
            }
          },
          grid: {
            display: true,
            drawBorder: true
          }
        }
      }
    }
  });
}

const pingChart = mkLine('pingChart', [], [
  {label:'Latency (ms)', data:[], borderColor:'#2ca8ff', backgroundColor:'rgba(44,168,255,0.1)', borderWidth:2, tension:0.3, fill:true},
  {label:'Loss (%)', data:[], borderColor:'#ff6b8a', backgroundColor:'rgba(255,107,138,0.1)', borderWidth:2, tension:0.3, fill:true}
]);

const protocolChart = mkLine('protocolChart', [], [
  {label:'TCP', data:[], borderColor:'#2ca8ff', backgroundColor:'rgba(44,168,255,0.1)', borderWidth:2, tension:0.3, fill:false},
  {label:'UDP', data:[], borderColor:'#ff6b8a', backgroundColor:'rgba(255,107,138,0.1)', borderWidth:2, tension:0.3, fill:false},
  {label:'ICMP', data:[], borderColor:'#ffb463', backgroundColor:'rgba(255,180,99,0.1)', borderWidth:2, tension:0.3, fill:false},
  {label:'Other', data:[], borderColor:'#ffe07a', backgroundColor:'rgba(255,224,122,0.1)', borderWidth:2, tension:0.3, fill:false}
]);

const tsharkChart = mkLine('tsharkChart', [], [
  {label:'TShark Packets', data:[], borderColor:'#2ca8ff', backgroundColor:'rgba(44,168,255,0.1)', borderWidth:2, tension:0.3, fill:true},
  {label:'TShark Bytes', data:[], borderColor:'#ffb463', backgroundColor:'rgba(255,180,99,0.1)', borderWidth:2, tension:0.3, fill:true, yAxisID:'y1'}
]);

tsharkChart.options.scales.y1 = {
  type: 'linear',
  position: 'right',
  grid: {drawOnChartArea: false},
  ticks: {
    font: {size: 10}
  }
};

async function fetchJson(url){
  try{
    const r=await fetch(url);
    return r.ok?await r.json():null
  } catch(e){
    console.warn(e);
    return null
  }
}

async function updateDonuts(){
  const merged = await fetchJson('/api/summary');
  const latest = (merged && merged.length>0)? merged[merged.length-1] : null;

  if(latest){
    document.getElementById('recordCount').innerText = merged.length;
    document.getElementById('lastUpdate').innerText = latest.timestamp || 'N/A';

    const loss = Number(latest.loss_percent||0);
    const success = Math.max(0,100-loss);
    pingDonut.data.datasets[0].data = [success, loss];
    pingDonut.update();
    document.getElementById('ping_kpi').innerText = `Latency ${latest.latency_ms||'N/A'} ms • Jitter ${latest.jitter_ms||'N/A'} ms`;
  }

  const tshark_latest = await fetchJson('/api/tshark_latest');
  if(tshark_latest && Object.keys(tshark_latest).length>0){
    const ttcp=Number(tshark_latest.tcp||0), tudp=Number(tshark_latest.udp||0),
          ticmp=Number(tshark_latest.icmp||0), tother=Number(tshark_latest.other||0);
    tsharkDonut.data.datasets[0].data = [ttcp,tudp,ticmp,tother];
    tsharkDonut.update();
    document.getElementById('tshark_kpi').innerText = `Total packets: ${(tshark_latest.total_pkts||0).toLocaleString()} • Bytes: ${(tshark_latest.total_bytes||0).toLocaleString()}`;
  } else {
    tsharkDonut.data.datasets[0].data = [0,0,0,0];
    tsharkDonut.update();
    document.getElementById('tshark_kpi').innerText = `TShark data unavailable`;
  }
}

async function updateLines(){
  const merged = await fetchJson('/api/summary') || [];

  // STRICT: Filter to last 2 days only
  const last2Days = filterLast2Days(merged);
  const sampled = smartSample(last2Days, 120);
  const labels = sampled.map(r => r.timestamp || '');

  document.getElementById('displayCount').innerText = last2Days.length;

  // Update ping chart
  pingChart.data.labels = labels;
  pingChart.data.datasets[0].data = sampled.map(r => Number(r.latency_ms||0));
  pingChart.data.datasets[1].data = sampled.map(r => Number(r.loss_percent||0));
  pingChart.update();
  document.getElementById('pingPoints').innerText = sampled.length;

  // Update tshark charts
  const tshark_summary = await fetchJson('/api/tshark_summary') || [];
  const tshark_last2Days = filterLast2Days(tshark_summary);
  const tshark_sampled = smartSample(tshark_last2Days, 120);
  const t_labels = tshark_sampled.map(r => r.timestamp || '');

  // Protocol History Chart
  protocolChart.data.labels = t_labels;
  protocolChart.data.datasets[0].data = tshark_sampled.map(r => Number(r.tcp||0));
  protocolChart.data.datasets[1].data = tshark_sampled.map(r => Number(r.udp||0));
  protocolChart.data.datasets[2].data = tshark_sampled.map(r => Number(r.icmp||0));
  protocolChart.data.datasets[3].data = tshark_sampled.map(r => Number(r.other||0));
  protocolChart.update();
  document.getElementById('protocolPoints').innerText = tshark_sampled.length;

  // Total Packets & Bytes Chart
  tsharkChart.data.labels = t_labels;
  tsharkChart.data.datasets[0].data = tshark_sampled.map(r => Number(r.total_pkts||0));
  tsharkChart.data.datasets[1].data = tshark_sampled.map(r => Number(r.total_bytes||0));
  tsharkChart.update();
  document.getElementById('tsharkPoints').innerText = tshark_sampled.length;
}

window.addEventListener('load', ()=>{
  updateDonuts();
  updateLines();
  setInterval(updateDonuts, 5000);
  setInterval(updateLines, 15000);
});
</script>
</body>
</html>
"""

# --------------------
# Strict 2-day cleanup
# --------------------
def cleanup_old_data(filepath, retention_days=RETENTION_DAYS):
    """Remove data older than retention period (default: 2 days)"""
    if not os.path.exists(filepath):
        return

    try:
        df = pd.read_csv(filepath)
        total_records = len(df)

        if total_records < 100:  # Don't cleanup if very few records
            return

        # Parse timestamps and filter by date
        if 'timestamp' in df.columns:
            df['_datetime'] = pd.to_datetime(df['timestamp'], errors='coerce')
            
            # Get most recent timestamp
            latest_time = df['_datetime'].max()
            if pd.isna(latest_time):
                return
            
            # Calculate cutoff (retention_days ago from latest)
            cutoff_time = latest_time - timedelta(days=retention_days)
            
            # Keep only data within retention period
            df_filtered = df[df['_datetime'] >= cutoff_time].copy()
            df_filtered = df_filtered.drop('_datetime', axis=1)
            
            if len(df_filtered) < total_records:
                df_filtered.to_csv(filepath, index=False)
                print(f"[CLEANUP] {filepath}: kept {len(df_filtered)}/{total_records} records (last {retention_days} days)")
        else:
            # Fallback: keep last MAX_RECORDS if no timestamp column
            if total_records > AUTO_CLEANUP_THRESHOLD:
                df_filtered = df.tail(MAX_RECORDS)
                df_filtered.to_csv(filepath, index=False)
                print(f"[CLEANUP] {filepath}: kept {len(df_filtered)}/{total_records} records (last {MAX_RECORDS})")
                
    except Exception as e:
        print(f"[CLEANUP ERROR] {filepath}: {e}")

def _load_csv_tail(path, tail=None, expected_cols=None, auto_cleanup=True):
    """Load CSV and filter to last 2 days. Normalize column names."""
    if not os.path.exists(path):
        return []

    # Periodic cleanup
    if auto_cleanup:
        cleanup_old_data(path)

    try:
        df = pd.read_csv(path)
    except Exception:
        try:
            df = pd.read_csv(path, header=None)
            if expected_cols:
                mapping = {i: expected_cols[i] for i in range(min(len(expected_cols), len(df.columns)))}
                df = df.rename(columns=mapping)
            else:
                df.columns = [str(c) for c in df.columns]
        except Exception:
            return []

    # Normalize column names
    df.columns = [str(c).strip().lower() for c in df.columns]

    # Ensure expected columns exist
    if expected_cols:
        for c in expected_cols:
            if c not in df.columns:
                df[c] = 0

    # Filter to last 2 days based on timestamp
    if 'timestamp' in df.columns and len(df) > 0:
        try:
            df['_datetime'] = pd.to_datetime(df['timestamp'], errors='coerce')
            latest_time = df['_datetime'].max()
            
            if not pd.isna(latest_time):
                two_days_ago = latest_time - timedelta(days=2)
                df = df[df['_datetime'] >= two_days_ago].copy()
                df = df.drop('_datetime', axis=1)
        except Exception as e:
            print(f"[WARNING] Could not filter by timestamp: {e}")
            # Fallback to tail if date filtering fails
            if tail:
                df = df.tail(tail)

    # Coerce numeric columns
    numcols = [c for c in df.columns if c not in ['timestamp','iface','interface']]
    for c in numcols:
        try:
            df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0)
        except Exception:
            pass

    df = df.fillna(0)
    records = df.to_dict(orient='records')

    # Ensure serializable
    for rec in records:
        for k,v in list(rec.items()):
            if pd.isna(v):
                rec[k] = 0
            elif isinstance(v, (float, int)):
                if float(v).is_integer():
                    rec[k] = int(v)
                else:
                    rec[k] = round(float(v), 2)
            else:
                rec[k] = str(v)
    return records

# --------------------
# Routes
# --------------------
@app.route('/')
def index():
    return render_template_string(TEMPLATE)

@app.route('/api/summary')
def api_summary():
    expected = ["timestamp","latency_ms","jitter_ms","loss_percent",
                "total_packets","tcp","udp","icmp","other","total_bytes",
                "total_pkts","tshark_tcp","tshark_udp","tshark_icmp","tshark_other","tshark_bytes"]
    recs = _load_csv_tail(MERGED_CSV, expected_cols=expected)
    return jsonify(recs)

@app.route('/api/tshark_summary')
def api_tshark_summary():
    expected = ["timestamp","iface","capture_time_s","total_pkts","tcp","udp","icmp","other","total_bytes"]
    recs = _load_csv_tail(TSHARK_CSV, expected_cols=expected)
    if not recs:
        merged = _load_csv_tail(MERGED_CSV)
        recs = []
        for r in merged:
            recs.append({
                "timestamp": r.get("timestamp",""),
                "iface": r.get("iface",""),
                "total_pkts": int(r.get("total_pkts",0)),
                "tcp": int(r.get("tshark_tcp", r.get("tcp",0))),
                "udp": int(r.get("tshark_udp", r.get("udp",0))),
                "icmp": int(r.get("tshark_icmp", r.get("icmp",0))),
                "other": int(r.get("tshark_other", r.get("other",0))),
                "total_bytes": int(r.get("tshark_bytes", r.get("total_bytes",0)))
            })
    return jsonify(recs)

@app.route('/api/tshark_latest')
def api_tshark_latest():
    recs = _load_csv_tail(TSHARK_CSV, tail=1, expected_cols=["timestamp","iface","capture_time_s","total_pkts","tcp","udp","icmp","other","total_bytes"], auto_cleanup=False)
    if recs:
        return jsonify(recs[-1])
    merged = _load_csv_tail(MERGED_CSV, tail=1, auto_cleanup=False)
    if merged:
        r = merged[-1]
        return jsonify({
            "timestamp": r.get("timestamp",""),
            "iface": r.get("iface",""),
            "total_pkts": int(r.get("total_pkts",0)),
            "tcp": int(r.get("tshark_tcp", r.get("tcp",0))),
            "udp": int(r.get("tshark_udp", r.get("udp",0))),
            "icmp": int(r.get("tshark_icmp", r.get("icmp",0))),
            "other": int(r.get("tshark_other", r.get("other",0))),
            "total_bytes": int(r.get("tshark_bytes", r.get("total_bytes",0)))
        })
    return jsonify({})

@app.route('/api/cleanup')
def api_cleanup():
    """Manual cleanup endpoint - removes data older than 2 days"""
    cleanup_old_data(MERGED_CSV)
    cleanup_old_data(PING_CSV)
    cleanup_old_data(TSHARK_CSV)
    return jsonify({"status": "cleanup completed", "retention_days": RETENTION_DAYS})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=False)
