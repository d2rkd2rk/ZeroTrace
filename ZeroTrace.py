#!/usr/bin/env python3
"""
=============================================================================
ZeroTrace - AI-Powered Linux Network Intrusion Detection System (NIDS)
Created By: Marwan Swedan
-----------------------------------------------------------------------------
Requires root/sudo privileges to capture network traffic and modify iptables.
=============================================================================
"""

import os
import sys
import time
import threading
import subprocess
from collections import defaultdict, deque
import numpy as np
import joblib

# Scapy & Rich Imports
try:
    from scapy.all import sniff, IP, TCP, UDP
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.text import Text
except ImportError:
    print("[-] Missing dependencies! Install them using: pip install scapy rich joblib numpy scikit-learn")
    sys.exit(1)

# Ensure script runs with Root privileges
if os.geteuid() != 0:
    print("[-] Error: ZeroTrace must be executed with root/sudo privileges!")
    sys.exit(1)


# ==========================================
# 1. FIREWALL MANAGER (iptables Integration)
# ==========================================
class FirewallManager:
    """Manages system iptables rules for real IP blocking/unblocking."""
    def __init__(self):
        self.blocked_ips = set()

    def block_ip(self, ip_address: str) -> bool:
        """Applies iptables rule to drop all incoming traffic from target IP."""
        if ip_address in self.blocked_ips or ip_address in ["127.0.0.1", "0.0.0.0"]:
            return False
        
        cmd = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.blocked_ips.add(ip_address)
            return True
        except subprocess.CalledProcessError:
            return False

    def unblock_ip(self, ip_address: str) -> bool:
        """Removes iptables block rule for target IP."""
        if ip_address not in self.blocked_ips:
            return False

        cmd = ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.blocked_ips.remove(ip_address)
            return True
        except subprocess.CalledProcessError:
            return False


# ==========================================
# 2. AI DETECTOR & FEATURE EXTRACTION
# ==========================================
class NIDSDetector:
    """Handles Feature Extraction and AI Inference."""
    def __init__(self, model_path="nids_model.pkl"):
        self.model = None
        self.flow_tracker = defaultdict(lambda: {"count": 0, "start_time": time.time(), "bytes": 0})
        self.labels = {
            0: "BENIGN",
            1: "DoS / DDoS Attack",
            2: "Port Scanning",
            3: "Brute Force",
            4: "Web Attack (SQLi/XSS)",
            5: "Botnet Activity"
        }
        self.load_or_train_model(model_path)

    def load_or_train_model(self, path):
        if not os.path.exists(path):
            self.auto_train(path)

        try:
            self.model = joblib.load(path)
        except Exception:
            self.model = None

    def auto_train(self, save_path):
        try:
            from sklearn.ensemble import RandomForestClassifier
            np.random.seed(42)
            n_samples = 12000

            X, y = [], []
            for _ in range(n_samples):
                label = np.random.choice([0, 1, 2, 3, 4, 5], p=[0.70, 0.10, 0.08, 0.05, 0.04, 0.03])
                if label == 0:
                    pkt_len = np.random.randint(60, 1500)
                    proto = np.random.choice([6, 17])
                    src_port = np.random.randint(1024, 65535)
                    dst_port = np.random.choice([80, 443, 53])
                    flags = np.random.choice([16, 24])
                    rate = np.random.uniform(0.1, 15.0)
                elif label == 1:
                    pkt_len = np.random.choice([60, 120])
                    proto = np.random.choice([6, 17])
                    src_port = np.random.randint(1024, 65535)
                    dst_port = 80
                    flags = 2
                    rate = np.random.uniform(300.0, 2000.0)
                else:
                    pkt_len = 54
                    proto = 6
                    src_port = np.random.randint(1024, 65535)
                    dst_port = np.random.randint(1, 1024)
                    flags = 0
                    rate = np.random.uniform(30.0, 100.0)

                X.append([pkt_len, proto, src_port, dst_port, flags, rate])
                y.append(label)

            clf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
            clf.fit(X, y)
            joblib.dump(clf, save_path)
        except Exception:
            pass

    def extract_features(self, packet):
        if IP not in packet:
            return None, None, None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        pkt_len = len(packet)
        proto = packet[IP].proto

        flags = 0
        src_port, dst_port = 0, 0
        if TCP in packet:
            flags = int(packet[TCP].flags)
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        flow_key = (src_ip, dst_ip, proto)
        flow = self.flow_tracker[flow_key]
        flow["count"] += 1
        flow["bytes"] += pkt_len
        
        duration = max(time.time() - flow["start_time"], 0.5)
        if flow["count"] > 3:
            pkt_rate = flow["count"] / duration
        else:
            pkt_rate = 1.0

        features = np.array([[pkt_len, proto, src_port, dst_port, flags, pkt_rate]])
        return features, src_ip, dst_ip

    def predict(self, features):
        if self.model is not None:
            pred = self.model.predict(features)[0]
            return pred, self.labels.get(pred, "Unknown Threat")
        else:
            pkt_len, proto, src_port, dst_port, flags, rate = features[0]
            if rate > 250 and flags == 2:
                return 1, "DoS / DDoS Attack"
            elif rate > 500:
                return 1, "DoS / DDoS Attack"
            elif dst_port in [22, 21, 3389] and rate > 30:
                return 3, "Brute Force"
            elif flags == 0 and rate > 40:
                return 2, "Port Scanning"
            return 0, "BENIGN"


# ==========================================
# 3. NIDS ENGINE & CLI DASHBOARD
# ==========================================
class NIDSEngine:
    def __init__(self, interface="eth0", auto_block=False):
        self.interface = interface
        self.auto_block = auto_block
        self.firewall = FirewallManager()
        self.detector = NIDSDetector()
        self.console = Console()

        self.total_packets = 0
        self.total_threats = 0
        self.recent_alerts = deque(maxlen=10)
        self.ip_threat_counts = defaultdict(int)
        self.last_cmd_message = ""
        self.running = True

    def process_packet(self, packet):
        self.total_packets += 1
        features, src_ip, dst_ip = self.detector.extract_features(packet)

        if features is None or src_ip == "127.0.0.1":
            return

        pred_id, pred_label = self.detector.predict(features)
        timestamp = time.strftime("%H:%M:%S")

        # 1. إذا كان باكت هجوم (Threat): يتم تسجيله فوراً ودائماً
        if pred_id != 0:
            self.total_threats += 1
            self.ip_threat_counts[src_ip] += 1

            status = "DETECTED"
            if self.auto_block:
                if self.firewall.block_ip(src_ip):
                    status = "BLOCKED (Auto)"

            alert_entry = {
                "time": timestamp,
                "src": src_ip,
                "dst": dst_ip,
                "threat": pred_label,
                "status": status,
                "is_threat": True
            }
            self.recent_alerts.appendleft(alert_entry)

        # 2. إذا كان باكت طبيعي (BENIGN): نعرض 1 من كل 10 باكتس لتوضيح حيوية الأداة
        else:
            if self.total_packets % 10 == 0:
                alert_entry = {
                    "time": timestamp,
                    "src": src_ip,
                    "dst": dst_ip,
                    "threat": "BENIGN (Normal)",
                    "status": "PASSED",
                    "is_threat": False
                }
                self.recent_alerts.appendleft(alert_entry)

    def manual_block_cli(self):
        while self.running:
            try:
                cmd = input().strip()
                if cmd.startswith("block "):
                    ip_to_block = cmd.split(" ")[1].strip()
                    if self.firewall.block_ip(ip_to_block):
                        self.last_cmd_message = f"[+] Successfully blocked {ip_to_block}"
                    else:
                        self.last_cmd_message = f"[-] Failed to block {ip_to_block}"
                elif cmd.startswith("unblock "):
                    ip_to_unblock = cmd.split(" ")[1].strip()
                    if self.firewall.unblock_ip(ip_to_unblock):
                        self.last_cmd_message = f"[+] Successfully unblocked {ip_to_unblock}"
                    else:
                        self.last_cmd_message = f"[-] Failed to unblock {ip_to_unblock}"
            except Exception:
                pass

    def build_dashboard(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3)
        )
        layout["main"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=1)
        )

        mode_str = "[bold red]Auto-Block ON[/bold red]" if self.auto_block else "[bold yellow]Manual Mode[/bold yellow]"
        model_status = "[bold green]AI Active (.pkl)[/bold green]" if self.detector.model else "[bold yellow]Heuristic Engine[/bold yellow]"
        
        header_text = Text(
            f"🛡️ ZeroTrace AI-NIDS  |  By: Marwan Swedan  |  IFACE: {self.interface}  |  Defense: {mode_str}  |  Engine: {model_status}", 
            justify="center", 
            style="bold white"
        )
        layout["header"].update(Panel(header_text, style="blue"))

        # Live Inspection Log Table (Mix of 1/10 Normal Traffic & 100% Threats)
        alert_table = Table(title="Live Traffic & Threat Inspection Stream", expand=True)
        alert_table.add_column("Time", style="cyan", width=10)
        alert_table.add_column("Source IP", style="magenta")
        alert_table.add_column("Target IP", style="white")
        alert_table.add_column("AI Classification", width=22)
        alert_table.add_column("Status / Action", width=16)

        for alert in self.recent_alerts:
            if alert["is_threat"]:
                threat_style = f"[bold red]{alert['threat']}[/bold red]"
                status_style = f"[bold yellow]{alert['status']}[/bold yellow]"
            else:
                threat_style = f"[green]{alert['threat']}[/green]"
                status_style = f"[dim green]{alert['status']}[/dim green]"

            alert_table.add_row(alert["time"], alert["src"], alert["dst"], threat_style, status_style)

        layout["left"].update(Panel(alert_table, title="Real-Time Traffic Stream (1:10 Sampled)"))

        stats_table = Table(expand=True, show_header=False)
        stats_table.add_column("Metric")
        stats_table.add_column("Value")
        stats_table.add_row("Total Packets Captured", str(self.total_packets))
        stats_table.add_row("Threats Intercepted", f"[bold red]{self.total_threats}[/bold red]")
        stats_table.add_row("Active Firewall Blocks", f"[bold green]{len(self.firewall.blocked_ips)}[/bold green]")

        blocked_list = "\n".join(list(self.firewall.blocked_ips)[-5:]) if self.firewall.blocked_ips else "No active firewall blocks"
        right_panel_content = Layout()
        right_panel_content.split_column(
            Layout(Panel(stats_table, title="System Metrics"), ratio=1),
            Layout(Panel(Text(blocked_list, style="bold red"), title="Active iptables Blocks"), ratio=1)
        )
        layout["right"].update(right_panel_content)

        cmd_status = f" | Status: {self.last_cmd_message}" if self.last_cmd_message else ""
        footer_text = Text(f"Commands: 'block <IP>' | 'unblock <IP>' | Press Ctrl+C to Exit{cmd_status}", style="dim white")
        layout["footer"].update(Panel(footer_text, style="grey39"))

        return layout

    def start(self):
        cmd_thread = threading.Thread(target=self.manual_block_cli, daemon=True)
        cmd_thread.start()

        sniff_thread = threading.Thread(
            target=lambda: sniff(iface=self.interface, prn=self.process_packet, store=0),
            daemon=True
        )
        sniff_thread.start()

        try:
            with Live(self.build_dashboard(), refresh_per_second=2, console=self.console, transient=False) as live:
                while self.running:
                    time.sleep(0.5)
                    live.update(self.build_dashboard())
        except KeyboardInterrupt:
            self.running = False
            self.console.print("\n[bold yellow][*] Shutting down ZeroTrace NIDS Engine... Clean exit.[/bold yellow]")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ZeroTrace - AI-Powered Linux NIDS by Marwan Swedan")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface to monitor (e.g., eth0, wlan0)")
    parser.add_argument("--auto-block", action="store_true", help="Enable automatic iptables IP blocking upon threat detection")
    args = parser.parse_args()

    engine = NIDSEngine(interface=args.interface, auto_block=args.auto_block)
    engine.start()