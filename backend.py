"""
Enhanced AI-driven Network Intrusion Prevention System Backend
"""
import os
import time
import subprocess
import ipaddress
import threading
import struct
import socket
from collections import defaultdict, deque
from datetime import datetime, timezone
from netfilterqueue import NetfilterQueue
from sklearn.ensemble import IsolationForest
from flask import Flask, request, jsonify, Response
from waitress import serve as wserve

# === Configuration ===
BASELINE_SECONDS = int(os.getenv("BASELINE_SECONDS", "45"))
WINDOW_SEC = int(os.getenv("WINDOW_SEC", "60"))
CONTAMINATION = float(os.getenv("CONTAMINATION", "0.02"))
BLOCK_SECONDS = int(os.getenv("BLOCK_SECONDS", "3600"))
MIN_SAMPLES = int(os.getenv("MIN_SAMPLES", "200"))
GLOBAL_SYN_ALERT = int(os.getenv("GLOBAL_SYN_ALERT", "120"))
MAX_LOG = int(os.getenv("MAX_LOG", "1500"))
QUEUE_START = int(os.getenv("QUEUE_START", "1"))
QUEUE_END = int(os.getenv("QUEUE_END", "4"))

class NIPSBackend:
    def __init__(self):
        self.lock = threading.RLock()
        self.per_src = defaultdict(lambda: {
            "times": deque(),
            "sizes": deque(),
            "dports": deque(),
            "tcp_syn": deque(),
            "tcp_rst": deque(),
            "tcp_fin": deque(),
            "udp_pkts": deque(),
            "icmp_pkts": deque()
        })
        self.syn_times_global = deque()
        self.logs = deque(maxlen=MAX_LOG)
        self.blocked = {}
        self.model = None
        self.feature_rows = []
        self.learning_until = time.time() + BASELINE_SECONDS
        self.metrics = {
            "total_pkts": 0,
            "accepted": 0,
            "dropped": 0,
            "alerts": 0,
            "start": time.time(),
            "queues": [],
            "attack_types": defaultdict(int)
        }
        
        # Start background tasks
        self._start_background_tasks()

    def _start_background_tasks(self):
        """Start background cleanup and monitoring tasks"""
        threading.Thread(target=self._gc_worker, daemon=True).start()
        threading.Thread(target=self._monitor_worker, daemon=True).start()

    def _gc_worker(self):
        """Background thread for garbage collection"""
        while True:
            time.sleep(10)
            self._gc_blocklist()
    
    def _monitor_worker(self):
        """Background thread for monitoring global conditions"""
        while True:
            time.sleep(5)
            self._check_global_conditions()

    def now_iso(self):
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    def log(self, evt, data):
        with self.lock:
            self.logs.appendleft({"t": self.now_iso(), "evt": evt, "data": data})

    def sh(self, cmd):
        result = subprocess.run(
            cmd, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        return result

    def ensure_ipsets(self):
        """Ensure ipset tables exist"""
        self.sh("ipset create blocked_v4 hash:ip family inet -! >/dev/null 2>&1")
        self.sh("ipset create blocked_v6 hash:ip family inet6 -! >/dev/null 2>&1")

    def ipset_add(self, ip):
        fam = "v6" if ":" in ip else "v4"
        self.sh(f"ipset add blocked_{fam} {ip} -! >/dev/null 2>&1")
        return fam

    def ipset_del(self, ip):
        fam = "v6" if ":" in ip else "v4"
        self.sh(f"ipset del blocked_{fam} {ip} -! >/dev/null 2>&1")

    def block_ip(self, ip, reason, features, attack_type):
        if ip in self.blocked:
            return
        
        fam = self.ipset_add(ip)
        with self.lock:
            self.blocked[ip] = {
                "until": time.time() + BLOCK_SECONDS,
                "reason": reason,
                "features": features,
                "first_seen": time.time(),
                "family": fam,
                "attack_type": attack_type
            }
            self.metrics["alerts"] += 1
            self.metrics["attack_types"][attack_type] += 1
        
        self.log("block", {
            "ip": ip, 
            "reason": reason, 
            "features": features,
            "attack_type": attack_type
        })

    def unblock_ip(self, ip):
        self.ipset_del(ip)
        with self.lock:
            self.blocked.pop(ip, None)
        self.log("unblock", {"ip": ip})

    def temp_allow_ip(self, ip):
        """Temporarily allow an IP by removing from blocklist"""
        with self.lock:
            # Remove from blocked list if it exists
            if ip in self.blocked:
                self.unblock_ip(ip)
            self.log("manual_allow", {"ip": ip, "reason": "Manual override via dashboard"})

    def _gc_blocklist(self):
        now = time.time()
        for ip, meta in list(self.blocked.items()):
            if now >= meta["until"]:
                self.unblock_ip(ip)

    def _check_global_conditions(self):
        """Check for global attack patterns"""
        current_time = time.time()
        cutoff = current_time - 30  # Check last 30 seconds
        
        # Count recent SYN packets globally
        recent_syns = sum(1 for ts in self.syn_times_global if ts >= cutoff)
        if recent_syns > GLOBAL_SYN_ALERT:
            self.log("global_alert", {
                "type": "Global SYN Flood",
                "count": recent_syns,
                "threshold": GLOBAL_SYN_ALERT
            })

    def _purge_old(self, deq, cutoff):
        while deq and (deq[0][0] if isinstance(deq[0], tuple) else deq[0]) < cutoff:
            deq.popleft()

    def update_stats(self, src, pkt_len, dport, syn, rst, fin, udp, icmp, ts):
        st = self.per_src[src]
        cutoff = ts - WINDOW_SEC
        
        st["times"].append(ts)
        self._purge_old(st["times"], cutoff)
        
        st["sizes"].append((ts, pkt_len))
        self._purge_old(st["sizes"], cutoff)
        
        st["dports"].append((ts, dport))
        self._purge_old(st["dports"], cutoff)
        
        st["tcp_syn"].append((ts, syn))
        self._purge_old(st["tcp_syn"], cutoff)
        
        st["tcp_rst"].append((ts, rst))
        self._purge_old(st["tcp_rst"], cutoff)
        
        st["tcp_fin"].append((ts, fin))
        self._purge_old(st["tcp_fin"], cutoff)
        
        st["udp_pkts"].append((ts, udp))
        self._purge_old(st["udp_pkts"], cutoff)
        
        st["icmp_pkts"].append((ts, icmp))
        self._purge_old(st["icmp_pkts"], cutoff)
        
        if syn:
            self.syn_times_global.append(ts)
            # Purge old global SYN times
            while self.syn_times_global and self.syn_times_global[0] < cutoff:
                self.syn_times_global.popleft()

    def extract_features(self, src):
        st = self.per_src[src]
        pkt_count = len(st["times"])
        uniq_ports = len({p for _, p in st["dports"]})
        secs = max(1.0, WINDOW_SEC)
        
        syn_rate = sum(1 for _, s in st["tcp_syn"] if s) / secs
        rst_rate = sum(1 for _, r in st["tcp_rst"] if r) / secs
        fin_rate = sum(1 for _, f in st["tcp_fin"] if f) / secs
        udp_rate = sum(1 for _, u in st["udp_pkts"] if u) / secs
        icmp_rate = sum(1 for _, i in st["icmp_pkts"] if i) / secs
        
        bytes_per_sec = sum(sz for _, sz in st["sizes"]) / secs if st["sizes"] else 0.0
        avg_size = (sum(sz for _, sz in st["sizes"]) / pkt_count) if pkt_count else 0.0
        
        return {
            "pkt_count": pkt_count,
            "uniq_ports": uniq_ports,
            "syn_rate": syn_rate,
            "rst_rate": rst_rate,
            "fin_rate": fin_rate,
            "udp_rate": udp_rate,
            "icmp_rate": icmp_rate,
            "bytes_per_sec": bytes_per_sec,
            "avg_size": avg_size,
            "syn_rate_global": len(self.syn_times_global) / secs
        }

    def feat_vector(self, feat):
        return [
            feat["pkt_count"], 
            feat["uniq_ports"], 
            feat["syn_rate"],
            feat["rst_rate"], 
            feat["bytes_per_sec"], 
            feat["avg_size"], 
            feat["syn_rate_global"],
            feat["fin_rate"],
            feat["udp_rate"],
            feat["icmp_rate"]
        ]

    def infer_attack_type(self, proto, features, syn, rst, fin, udp, icmp):
        """Identify specific attack types"""
        if proto == "TCP":
            # SYN Flood Detection
            if syn and features["syn_rate"] > 5:
                return "SYN Flood", "SYN flood attack detected"
            
            # TCP-based port scanning
            if features["uniq_ports"] >= 5 and features["pkt_count"] >= 5:
                if features["syn_rate"] > 2:
                    return "TCP Port Scan", "TCP SYN port scanning detected"
                else:
                    return "TCP Connection Scan", "TCP connection port scanning detected"
            
            # FIN scan detection
            if fin and features["fin_rate"] > 2 and features["uniq_ports"] >= 3:
                return "FIN Scan", "TCP FIN port scanning detected"
            
            # RST scan detection
            if rst and features["rst_rate"] > 2 and features["uniq_ports"] >= 3:
                return "RST Scan", "TCP RST port scanning detected"
            
            # High volume TCP DoS
            if features["bytes_per_sec"] > 100000 and features["pkt_count"] > 10:
                return "TCP DoS", "High volume TCP DoS attack"
        
        elif proto == "UDP":
            # UDP flood detection
            if features["udp_rate"] > 10:
                return "UDP Flood", "UDP flooding attack detected"
            
            # UDP port scanning
            if features["uniq_ports"] >= 3 and features["pkt_count"] >= 3:
                return "UDP Port Scan", "UDP port scanning detected"
            
            # High volume UDP DoS
            if features["bytes_per_sec"] > 50000 and features["pkt_count"] > 5:
                return "UDP DoS", "High volume UDP DoS attack"
        
        elif proto == "ICMP":
            # ICMP flood detection
            if features["icmp_rate"] > 10:
                return "ICMP Flood", "ICMP flooding attack detected"
            
            # Ping of death detection (large ICMP packets)
            if features["avg_size"] > 1000:
                return "Ping of Death", "Large ICMP packet attack detected"
        
        # Generic anomaly detection using ML model
        if hasattr(self, '_has_trained_model') and self._has_trained_model:
            try:
                score = self.model.decision_function([self.feat_vector(features)])
                if score[0] < -0.5:  # Anomaly threshold
                    return "Anomalous Traffic", "ML-detected anomalous traffic pattern"
            except:
                pass
        
        return "Reconnaissance", "Suspicious reconnaissance activity"

    def parse_fast(self, payload: bytes):
        """Fast packet parsing function"""
        length = len(payload)
        if length < 1: 
            return None, "OTHER", 0, 0, 0, 0, 0, 0, length
        
        ver = (payload[0] >> 4) & 0xF
        try:
            if ver == 4 and length >= 20:
                ihl = (payload[0] & 0x0F) * 4
                proto = payload[9]
                src_ip = socket.inet_ntoa(payload[12:16])
                
                if proto == 6 and length >= ihl + 20:  # TCP
                    dport = struct.unpack("!H", payload[ihl+2:ihl+4])[0]
                    flags = payload[ihl+13]
                    syn = 1 if (flags & 0x02) else 0
                    rst = 1 if (flags & 0x04) else 0
                    fin = 1 if (flags & 0x01) else 0
                    return src_ip, "TCP", dport, syn, rst, fin, 0, 0, length
                
                elif proto == 17 and length >= ihl + 8:  # UDP
                    dport = struct.unpack("!H", payload[ihl+2:ihl+4])[0]
                    return src_ip, "UDP", dport, 0, 0, 0, 1, 0, length
                
                elif proto == 1:  # ICMP
                    return src_ip, "ICMP", 0, 0, 0, 0, 0, 1, length
                
                return src_ip, "OTHER", 0, 0, 0, 0, 0, 0, length
            
            elif ver == 6 and length >= 40:  # IPv6
                nexthdr = payload[6]
                src_ip = socket.inet_ntop(socket.AF_INET6, payload[8:24])
                off = 40
                
                if nexthdr == 6 and length >= off + 20:  # TCP
                    dport = struct.unpack("!H", payload[off+2:off+4])[0]
                    flags = payload[off+13]
                    syn = 1 if (flags & 0x02) else 0
                    rst = 1 if (flags & 0x04) else 0
                    fin = 1 if (flags & 0x01) else 0
                    return src_ip, "TCP", dport, syn, rst, fin, 0, 0, length
                
                elif nexthdr == 17 and length >= off + 8:  # UDP
                    dport = struct.unpack("!H", payload[off+2:off+4])[0]
                    return src_ip, "UDP", dport, 0, 0, 0, 1, 0, length
                
                elif nexthdr == 58:  # ICMPv6
                    return src_ip, "ICMP", 0, 0, 0, 0, 0, 1, length
                
                else:
                    return src_ip, "OTHER", 0, 0, 0, 0, 0, 0, length
            
            else:
                return None, "OTHER", 0, 0, 0, 0, 0, 0, length
        except Exception:
            return None, "OTHER", 0, 0, 0, 0, 0, 0, length

    def maybe_fit_model(self):
        """Train the ML model when enough data is available"""
        if self.model is None and len(self.feature_rows) >= MIN_SAMPLES:
            self.model = IsolationForest(
                contamination=CONTAMINATION, 
                random_state=42, 
                n_estimators=200, 
                n_jobs=-1
            )
            self.model.fit(self.feature_rows)
            self._has_trained_model = True
            self.log("model_fit", {
                "rows": len(self.feature_rows), 
                "contamination": CONTAMINATION
            })

    def handle_packet(self, pkt):
        """Handle incoming network packets"""
        ts = time.time()
        payload = pkt.get_payload()
        
        with self.lock:
            self.metrics["total_pkts"] += 1

        # Parse packet
        src, proto, dport, syn, rst, fin, udp, icmp, plen = self.parse_fast(payload)

        # Log raw packet info for debugging
        if src:
            self.log("raw", {
                "ip": src,
                "dport": dport,
                "proto": proto,
                "len": plen,
                "syn": syn,
                "rst": rst,
                "fin": fin,
                "udp": udp,
                "icmp": icmp
            })

        drop_now = False
        attack_type = None
        reason = None

        if src:
            with self.lock:
                # Update statistics
                self.update_stats(src, plen, dport, syn, rst, fin, udp, icmp, ts)
                
                # Extract features
                features = self.extract_features(src)
                
                # Check for global SYN flood
                if features["syn_rate_global"] > GLOBAL_SYN_ALERT:
                    drop_now = True
                    attack_type = "Global SYN Flood"
                    reason = "Global SYN flood detected"
                    self.block_ip(src, reason, features, attack_type)
                else:
                    # Learning phase: collect features for training
                    if time.time() <= self.learning_until:
                        if features["pkt_count"] % 8 == 0:
                            self.feature_rows.append(self.feat_vector(features))
                    else:
                        # Model is ready or will be trained soon
                        self.maybe_fit_model()
                        
                        if self.model:
                            try:
                                score = self.model.decision_function([self.feat_vector(features)])
                                if score[0] < -0.5 and src not in self.blocked:  # Anomaly detected
                                    attack_type, reason = self.infer_attack_type(
                                        proto, features, syn, rst, fin, udp, icmp
                                    )
                                    self.block_ip(src, reason, features, attack_type)
                                    drop_now = True
                            except:
                                pass
                        else:
                            # During learning phase, use rule-based detection
                            if src not in self.blocked:
                                attack_type, reason = self.infer_attack_type(
                                    proto, features, syn, rst, fin, udp, icmp
                                )
                                if attack_type != "Reconnaissance":  # Only block clear attacks during learning
                                    self.block_ip(src, reason, features, attack_type)
                                    drop_now = True

        # Drop or accept packet based on decision
        if drop_now or (src and src in self.blocked):
            pkt.drop()
            with self.lock:
                self.metrics["dropped"] += 1
            if src:
                self.log("drop", {
                    "ip": src,
                    "proto": proto,
                    "dport": dport,
                    "attack_type": attack_type or "Unknown"
                })
        else:
            pkt.accept()
            with self.lock:
                self.metrics["accepted"] += 1

    def nfqueue_worker(self, qnum):
        """Worker thread for handling netfilter queue"""
        nfq = NetfilterQueue()
        nfq.bind(qnum, self.handle_packet, max_len=4096)
        
        with self.lock:
            if qnum not in self.metrics["queues"]:
                self.metrics["queues"].append(qnum)
        
        try:
            nfq.run()
        except KeyboardInterrupt:
            pass
        finally:
            nfq.unbind()

    def start_nfqueue_workers(self):
        """Start all netfilter queue worker threads"""
        for q in range(QUEUE_START, QUEUE_END + 1):
            t = threading.Thread(target=self.nfqueue_worker, args=(q,), daemon=True)
            t.start()
        
        self.log("status", {
            "msg": "NIPS started", 
            "queues": list(range(QUEUE_START, QUEUE_END + 1))
        })

# Global backend instance
backend = NIPSBackend()

# Flask app
app = Flask(__name__)

@app.route("/")
def index():
    """Serve the main dashboard page"""
    try:
        with open("frontend3.html", "r") as f:
            return Response(f.read(), mimetype="text/html")
    except FileNotFoundError:
        return Response("""
        <h1>AI-Powered Network Defense Dashboard</h1>
        <p>Frontend file not found. Please ensure 'frontend.html' exists in the same directory.</p>
        """, mimetype="text/html")

@app.route("/api/metrics")
def api_metrics():
    with backend.lock:
        out = dict(backend.metrics)
        out["start"] = backend.metrics["start"]
        return jsonify(out)

@app.route("/api/logs")
def api_logs():
    n = int(request.args.get("limit", 100))
    with backend.lock:
        return jsonify(list(list(backend.logs)[0:n]))

@app.route("/api/blocked")
def api_blocked():
    backend._gc_blocklist()
    with backend.lock:
        return jsonify({ip: meta for ip, meta in backend.blocked.items()})

@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    data = request.get_json(force=True)
    ip = data.get("ip", "")
    try:
        ipaddress.ip_address(ip)
    except:
        return jsonify({"ok": False, "error": "invalid ip"}), 400
    
    backend.unblock_ip(ip)
    return jsonify({"ok": True})

@app.route("/api/override", methods=["POST"])
def api_override():
    """Manual override endpoint for allowing/dropping packets"""
    data = request.get_json(force=True)
    action = data.get("action")  # "allow" or "block"
    ip = data.get("ip", "")
    
    try:
        ipaddress.ip_address(ip)
    except:
        return jsonify({"ok": False, "error": "invalid ip"}), 400
    
    if action == "allow":
        # Temporarily allow this IP (remove from blocklist if present)
        backend.temp_allow_ip(ip)
        return jsonify({"ok": True, "message": f"IP {ip} temporarily allowed"})
    
    elif action == "block":
        # Block this IP immediately
        features = {"manual_block": True, "pkt_count": 0, "uniq_ports": 0, 
                   "syn_rate": 0, "rst_rate": 0, "fin_rate": 0, "udp_rate": 0, 
                   "icmp_rate": 0, "bytes_per_sec": 0, "avg_size": 0, "syn_rate_global": 0}
        backend.block_ip(ip, "Manual block via dashboard", features, "Manual Block")
        return jsonify({"ok": True, "message": f"IP {ip} blocked"})
    
    else:
        return jsonify({"ok": False, "error": "invalid action"}), 400

@app.route("/api/stats")
def api_stats():
    """Additional stats endpoint for detailed monitoring"""
    with backend.lock:
        # Calculate some additional metrics
        total_packets = backend.metrics["total_pkts"]
        drop_rate = (backend.metrics["dropped"] / max(total_packets, 1)) * 100 if total_packets > 0 else 0
        
        # Get top attacking IPs
        top_attacks = {}
        for ip, data in backend.blocked.items():
            if "attack_type" in data:
                attack_type = data["attack_type"]
                if attack_type not in top_attacks:
                    top_attacks[attack_type] = 0
                top_attacks[attack_type] += 1
        
        active_blocks = len(backend.blocked)
        
        return jsonify({
            "drop_rate_percent": round(drop_rate, 2),
            "active_blocks": active_blocks,
            "top_attack_types": top_attacks,
            "total_packets": total_packets
        })

def main():
    """Main function to start the NIPS system"""
    # Ensure ipsets exist
    backend.ensure_ipsets()
    
    # Start netfilter queue workers
    backend.start_nfqueue_workers()
    
    # Start Flask server in a separate thread
    def run_flask():
        app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
    
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    
    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down NIPS...")
        exit(0)

if __name__ == "__main__":
    main()
