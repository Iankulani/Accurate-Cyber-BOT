import sys
import socket
import threading
import time
import datetime
import psutil
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import requests
import json
import platform
import subprocess
import netifaces
import dpkt
from collections import defaultdict
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP
import logging
from logging.handlers import RotatingFileHandler
import os
import queue

# Constants
CONFIG_FILE = "config.json"
LOG_FILE = "cyber_monitor.log"
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
BACKUP_COUNT = 3
UPDATE_INTERVAL = 5  # seconds for GUI updates
TELEGRAM_API_URL = "https://api.telegram.org/bot{}/sendMessage"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=BACKUP_COUNT),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NetworkMonitor:
    def __init__(self):
        self.monitoring = False
        self.target_ip = None
        self.telegram_bot_token = None
        self.telegram_chat_id = None
        self.alert_thresholds = {
            'dos': 100,  # packets per second
            'port_scan': 10,  # ports per second
            'unusual_traffic': 50  # % increase over baseline
        }
        self.traffic_stats = defaultdict(lambda: defaultdict(int))
        self.baseline_stats = defaultdict(lambda: defaultdict(int))
        self.baseline_established = False
        self.baseline_duration = 300  # 5 minutes for baseline
        self.packet_queue = queue.Queue()
        self.alert_queue = queue.Queue()
        self.sniffer_thread = None
        self.analysis_thread = None
        self.alert_thread = None
        self.load_config()

    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.telegram_bot_token = config.get('telegram_bot_token')
                    self.telegram_chat_id = config.get('telegram_chat_id')
                    self.alert_thresholds = config.get('alert_thresholds', self.alert_thresholds)
        except Exception as e:
            logger.error(f"Error loading config: {e}")

    def save_config(self):
        try:
            config = {
                'telegram_bot_token': self.telegram_bot_token,
                'telegram_chat_id': self.telegram_chat_id,
                'alert_thresholds': self.alert_thresholds
            }
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving config: {e}")

    def start_monitoring(self, target_ip):
        if self.monitoring:
            logger.warning("Monitoring is already running")
            return False

        self.target_ip = target_ip
        self.monitoring = True
        self.baseline_established = False
        self.traffic_stats.clear()
        
        # Start packet capture thread
        self.sniffer_thread = threading.Thread(target=self._packet_capture, daemon=True)
        self.sniffer_thread.start()
        
        # Start analysis thread
        self.analysis_thread = threading.Thread(target=self._analyze_traffic, daemon=True)
        self.analysis_thread.start()
        
        # Start alert thread
        self.alert_thread = threading.Thread(target=self._process_alerts, daemon=True)
        self.alert_thread.start()
        
        logger.info(f"Started monitoring {target_ip}")
        return True

    def stop_monitoring(self):
        self.monitoring = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=2)
        if self.analysis_thread and self.analysis_thread.is_alive():
            self.analysis_thread.join(timeout=2)
        if self.alert_thread and self.alert_thread.is_alive():
            self.alert_thread.join(timeout=2)
        logger.info("Stopped monitoring")

    def _packet_capture(self):
        """Capture network packets using scapy"""
        try:
            filter_str = f"host {self.target_ip}" if self.target_ip else ""
            sniff(prn=self._process_packet, filter=filter_str, store=0, stop_filter=lambda x: not self.monitoring)
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
            self.monitoring = False

    def _process_packet(self, packet):
        """Process captured packets"""
        if not self.monitoring:
            return

        try:
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                
                # Check if packet is to/from our target IP
                if ip_src == self.target_ip or ip_dst == self.target_ip:
                    timestamp = datetime.datetime.now().timestamp()
                    protocol = "unknown"
                    port = 0
                    
                    if TCP in packet:
                        protocol = "tcp"
                        port = packet[TCP].dport
                    elif UDP in packet:
                        protocol = "udp"
                        port = packet[UDP].dport
                    elif ICMP in packet:
                        protocol = "icmp"
                    
                    # Put packet info in queue for analysis
                    self.packet_queue.put({
                        'timestamp': timestamp,
                        'src_ip': ip_src,
                        'dst_ip': ip_dst,
                        'protocol': protocol,
                        'port': port,
                        'size': len(packet)
                    })
        except Exception as e:
            logger.error(f"Packet processing error: {e}")

    def _analyze_traffic(self):
        """Analyze network traffic for threats"""
        baseline_start = time.time()
        
        while self.monitoring:
            try:
                # Process packets from queue
                while not self.packet_queue.empty():
                    packet = self.packet_queue.get()
                    
                    # Update traffic stats
                    current_minute = int(packet['timestamp'] // 60)
                    direction = "inbound" if packet['dst_ip'] == self.target_ip else "outbound"
                    
                    self.traffic_stats[current_minute]['total_packets'] += 1
                    self.traffic_stats[current_minute][f"{direction}_packets"] += 1
                    self.traffic_stats[current_minute][f"{packet['protocol']}_packets"] += 1
                    
                    if packet['port'] > 0:
                        self.traffic_stats[current_minute]['ports_scanned'].add(packet['port'])
                
                # Check if baseline period is complete
                if not self.baseline_established and (time.time() - baseline_start) >= self.baseline_duration:
                    self._establish_baseline()
                
                # Check for threats if baseline is established
                if self.baseline_established:
                    self._check_for_dos()
                    self._check_for_port_scan()
                    self._check_for_unusual_traffic()
                
                time.sleep(1)  # Prevent CPU overload
            except Exception as e:
                logger.error(f"Traffic analysis error: {e}")
                time.sleep(5)

    def _establish_baseline(self):
        """Establish baseline traffic patterns"""
        try:
            # Calculate average traffic over baseline period
            total_packets = sum(stats['total_packets'] for stats in self.traffic_stats.values())
            avg_packets = total_packets / len(self.traffic_stats) if self.traffic_stats else 0
            
            self.baseline_stats['avg_packets_per_minute'] = avg_packets
            self.baseline_established = True
            logger.info(f"Baseline established: {avg_packets:.1f} packets/minute")
            
            # Send notification
            message = f"🚦 Baseline established for {self.target_ip}\n" \
                     f"📦 Avg packets/minute: {avg_packets:.1f}"
            self._send_telegram_alert(message)
        except Exception as e:
            logger.error(f"Error establishing baseline: {e}")

    def _check_for_dos(self):
        """Check for DOS/DDOS attacks"""
        try:
            current_minute = int(time.time() // 60)
            current_stats = self.traffic_stats.get(current_minute, {})
            inbound_packets = current_stats.get('inbound_packets', 0)
            
            # Calculate packets per second (approx)
            elapsed_seconds = time.time() % 60
            packets_per_second = inbound_packets / elapsed_seconds if elapsed_seconds > 0 else 0
            
            if packets_per_second > self.alert_thresholds['dos']:
                alert_msg = f"⚠️ Possible DOS attack on {self.target_ip}\n" \
                          f"📦 Packets/sec: {packets_per_second:.1f} (Threshold: {self.alert_thresholds['dos']})"
                logger.warning(alert_msg)
                self.alert_queue.put(('dos', alert_msg))
        except Exception as e:
            logger.error(f"DOS check error: {e}")

    def _check_for_port_scan(self):
        """Check for port scanning activity"""
        try:
            current_minute = int(time.time() // 60)
            current_stats = self.traffic_stats.get(current_minute, {})
            ports_scanned = len(current_stats.get('ports_scanned', set()))
            
            # Calculate ports per second (approx)
            elapsed_seconds = time.time() % 60
            ports_per_second = ports_scanned / elapsed_seconds if elapsed_seconds > 0 else 0
            
            if ports_per_second > self.alert_thresholds['port_scan']:
                alert_msg = f"🔍 Possible port scan on {self.target_ip}\n" \
                          f"🔢 Ports scanned/sec: {ports_per_second:.1f} (Threshold: {self.alert_thresholds['port_scan']})"
                logger.warning(alert_msg)
                self.alert_queue.put(('port_scan', alert_msg))
        except Exception as e:
            logger.error(f"Port scan check error: {e}")

    def _check_for_unusual_traffic(self):
        """Check for unusual traffic patterns"""
        try:
            current_minute = int(time.time() // 60)
            current_stats = self.traffic_stats.get(current_minute, {})
            current_packets = current_stats.get('total_packets', 0)
            
            baseline = self.baseline_stats['avg_packets_per_minute']
            if baseline > 0:
                increase = ((current_packets - baseline) / baseline) * 100
                
                if increase > self.alert_thresholds['unusual_traffic']:
                    alert_msg = f"📈 Unusual traffic on {self.target_ip}\n" \
                              f"📦 Traffic increase: {increase:.1f}% (Threshold: {self.alert_thresholds['unusual_traffic']}%)"
                    logger.warning(alert_msg)
                    self.alert_queue.put(('unusual_traffic', alert_msg))
        except Exception as e:
            logger.error(f"Unusual traffic check error: {e}")

    def _process_alerts(self):
        """Process and send alerts"""
        while self.monitoring:
            try:
                if not self.alert_queue.empty():
                    alert_type, message = self.alert_queue.get()
                    self._send_telegram_alert(message)
                time.sleep(1)
            except Exception as e:
                logger.error(f"Alert processing error: {e}")
                time.sleep(5)

    def _send_telegram_alert(self, message):
        """Send alert to Telegram bot"""
        if not self.telegram_bot_token or not self.telegram_chat_id:
            return False
        
        try:
            url = TELEGRAM_API_URL.format(self.telegram_bot_token)
            payload = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': 'Markdown'
            }
            response = requests.post(url, json=payload)
            if response.status_code != 200:
                logger.error(f"Telegram API error: {response.text}")
                return False
            return True
        except Exception as e:
            logger.error(f"Error sending Telegram alert: {e}")
            return False

    def get_traffic_stats(self):
        """Get current traffic statistics"""
        current_minute = int(time.time() // 60)
        return self.traffic_stats.get(current_minute, {})

    def get_baseline_stats(self):
        """Get baseline statistics"""
        return self.baseline_stats

class CyberSecurityToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Accurate Cyber BOT")
        self.root.geometry("1200x800")
        
        # Initialize network monitor
        self.monitor = NetworkMonitor()
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('.', background='black', foreground='green')
        self.style.configure('TFrame', background='black')
        self.style.configure('TLabel', background='black', foreground='green')
        self.style.configure('TButton', background='black', foreground='green', 
                           bordercolor='green', lightcolor='black', darkcolor='black')
        self.style.configure('TEntry', fieldbackground='black', foreground='green')
        self.style.configure('TCombobox', fieldbackground='black', foreground='green')
        self.style.configure('TNotebook', background='black', bordercolor='green')
        self.style.configure('TNotebook.Tab', background='black', foreground='green', 
                           lightcolor='black', bordercolor='green')
        self.style.map('TButton', background=[('active', 'green'), ('pressed', 'dark green')],
                     foreground=[('active', 'black'), ('pressed', 'black')])
        
        # Create main containers
        self.create_menu()
        self.create_main_frame()
        self.create_terminal()
        self.create_status_bar()
        
        # Start GUI update thread
        self.update_thread = threading.Thread(target=self.update_gui, daemon=True)
        self.update_thread.start()
        
        # Load any saved configuration
        self.load_config()

    def create_menu(self):
        """Create the main menu bar"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0, bg='black', fg='green')
        file_menu.add_command(label="Save Config", command=self.save_config)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0, bg='black', fg='green')
        tools_menu.add_command(label="Ping", command=self.show_ping_dialog)
        tools_menu.add_command(label="Tracert", command=self.show_tracert_dialog)
        tools_menu.add_command(label="Netstat", command=self.run_netstat)
        tools_menu.add_command(label="NSLookup", command=self.show_nslookup_dialog)
        tools_menu.add_command(label="Interface Config", command=self.run_ifconfig)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0, bg='black', fg='green')
        view_menu.add_command(label="Traffic Stats", command=self.show_traffic_stats)
        view_menu.add_command(label="Threat Analysis", command=self.show_threat_analysis)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0, bg='black', fg='green')
        help_menu.add_command(label="Help", command=self.show_help)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)

    def create_main_frame(self):
        """Create the main content frame"""
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Dashboard tab
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        self.create_dashboard()
        
        # Monitoring tab
        self.monitoring_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.monitoring_tab, text="Monitoring")
        self.create_monitoring_panel()
        
        # Settings tab
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text="Settings")
        self.create_settings_panel()

    def create_dashboard(self):
        """Create the dashboard tab"""
        # Left panel for controls
        left_panel = ttk.Frame(self.dashboard_tab)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        # Target IP section
        ip_frame = ttk.LabelFrame(left_panel, text="Target IP")
        ip_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(ip_frame, text="IP Address:").pack(anchor=tk.W)
        self.ip_entry = ttk.Entry(ip_frame)
        self.ip_entry.pack(fill=tk.X, padx=5, pady=2)
        
        self.start_btn = ttk.Button(ip_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_btn.pack(fill=tk.X, padx=5, pady=2)
        
        self.stop_btn = ttk.Button(ip_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(fill=tk.X, padx=5, pady=2)
        
        # Status indicators
        status_frame = ttk.LabelFrame(left_panel, text="Status")
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.status_labels = {
            'monitoring': self.create_status_indicator(status_frame, "Monitoring", "red"),
            'baseline': self.create_status_indicator(status_frame, "Baseline Established", "red"),
            'telegram': self.create_status_indicator(status_frame, "Telegram Connected", "red")
        }
        
        # Right panel for charts
        right_panel = ttk.Frame(self.dashboard_tab)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Traffic chart
        self.traffic_fig, self.traffic_ax = plt.subplots(figsize=(6, 3), facecolor='black')
        self.traffic_ax.set_facecolor('black')
        self.traffic_ax.tick_params(colors='green')
        for spine in self.traffic_ax.spines.values():
            spine.set_color('green')
        self.traffic_canvas = FigureCanvasTkAgg(self.traffic_fig, master=right_panel)
        self.traffic_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Threat chart
        self.threat_fig, self.threat_ax = plt.subplots(figsize=(6, 3), facecolor='black')
        self.threat_ax.set_facecolor('black')
        self.threat_ax.tick_params(colors='green')
        for spine in self.threat_ax.spines.values():
            spine.set_color('green')
        self.threat_canvas = FigureCanvasTkAgg(self.threat_fig, master=right_panel)
        self.threat_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def create_status_indicator(self, parent, text, initial_color="red"):
        """Create a status indicator label"""
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Label(frame, text=text, width=20).pack(side=tk.LEFT)
        canvas = tk.Canvas(frame, width=20, height=20, bg='black', highlightthickness=0)
        canvas.pack(side=tk.RIGHT)
        canvas.create_oval(2, 2, 18, 18, fill=initial_color)
        
        return canvas

    def create_monitoring_panel(self):
        """Create the monitoring panel"""
        # Alerts frame
        alerts_frame = ttk.LabelFrame(self.monitoring_tab, text="Alerts")
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.alerts_text = scrolledtext.ScrolledText(
            alerts_frame, wrap=tk.WORD, bg='black', fg='green', insertbackground='green'
        )
        self.alerts_text.pack(fill=tk.BOTH, expand=True)
        
        # Alert controls
        controls_frame = ttk.Frame(alerts_frame)
        controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(controls_frame, text="Clear", command=self.clear_alerts).pack(side=tk.LEFT)
        ttk.Button(controls_frame, text="Export", command=self.export_alerts).pack(side=tk.LEFT)

    def create_settings_panel(self):
        """Create the settings panel"""
        # Telegram settings
        telegram_frame = ttk.LabelFrame(self.settings_tab, text="Telegram Bot Settings")
        telegram_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(telegram_frame, text="Bot Token:").pack(anchor=tk.W)
        self.bot_token_entry = ttk.Entry(telegram_frame)
        self.bot_token_entry.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Label(telegram_frame, text="Chat ID:").pack(anchor=tk.W)
        self.chat_id_entry = ttk.Entry(telegram_frame)
        self.chat_id_entry.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Button(telegram_frame, text="Test Connection", command=self.test_telegram).pack(fill=tk.X, padx=5, pady=5)
        
        # Alert thresholds
        thresholds_frame = ttk.LabelFrame(self.settings_tab, text="Alert Thresholds")
        thresholds_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(thresholds_frame, text="DOS (packets/sec):").pack(anchor=tk.W)
        self.dos_threshold = ttk.Entry(thresholds_frame)
        self.dos_threshold.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Label(thresholds_frame, text="Port Scan (ports/sec):").pack(anchor=tk.W)
        self.port_scan_threshold = ttk.Entry(thresholds_frame)
        self.port_scan_threshold.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Label(thresholds_frame, text="Unusual Traffic (% increase):").pack(anchor=tk.W)
        self.traffic_threshold = ttk.Entry(thresholds_frame)
        self.traffic_threshold.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Button(thresholds_frame, text="Save Thresholds", command=self.save_thresholds).pack(fill=tk.X, padx=5, pady=5)

    def create_terminal(self):
        """Create the terminal emulator"""
        terminal_frame = ttk.LabelFrame(self.root, text="Terminal")
        terminal_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.terminal_text = scrolledtext.ScrolledText(
            terminal_frame, height=10, wrap=tk.WORD, bg='black', fg='green', insertbackground='green'
        )
        self.terminal_text.pack(fill=tk.BOTH, expand=True)
        
        # Command entry
        cmd_frame = ttk.Frame(terminal_frame)
        cmd_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(cmd_frame, text=">").pack(side=tk.LEFT)
        self.cmd_entry = ttk.Entry(cmd_frame)
        self.cmd_entry.pack(fill=tk.X, expand=True, padx=5)
        self.cmd_entry.bind("<Return>", self.execute_command)
        
        # Add some help text
        self.terminal_help()

    def create_status_bar(self):
        """Create the status bar"""
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    def terminal_help(self):
        """Display help in terminal"""
        help_text = """Cyber Security Monitor Terminal Commands:
ping <ip>       - Ping an IP address
tracert <ip>    - Trace route to an IP
start <ip>      - Start monitoring an IP
stop            - Stop monitoring
view stats      - View traffic statistics
view threats    - View threat analysis
netstat         - Show network statistics
nslookup <host> - DNS lookup
ifconfig        - Show network interfaces
help            - Show this help
clear           - Clear terminal
"""
        self.terminal_text.insert(tk.END, help_text)
        self.terminal_text.see(tk.END)

    def execute_command(self, event=None):
        """Execute terminal command"""
        cmd = self.cmd_entry.get().strip()
        self.cmd_entry.delete(0, tk.END)
        
        if not cmd:
            return
        
        # Echo command
        self.terminal_text.insert(tk.END, f"> {cmd}\n")
        
        # Process command
        parts = cmd.split()
        command = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        try:
            if command == "ping" and args:
                self.run_ping(args[0])
            elif command == "tracert" and args:
                self.run_tracert(args[0])
            elif command == "start" and args:
                self.start_monitoring(args[0])
            elif command == "stop":
                self.stop_monitoring()
            elif command == "view":
                if args and args[0] == "stats":
                    self.show_traffic_stats()
                elif args and args[0] == "threats":
                    self.show_threat_analysis()
                else:
                    self.terminal_text.insert(tk.END, "Usage: view [stats|threats]\n")
            elif command == "netstat":
                self.run_netstat()
            elif command == "nslookup" and args:
                self.run_nslookup(args[0])
            elif command == "ifconfig":
                self.run_ifconfig()
            elif command == "help":
                self.terminal_help()
            elif command == "clear":
                self.terminal_text.delete(1.0, tk.END)
            else:
                self.terminal_text.insert(tk.END, f"Unknown command: {command}\nType 'help' for available commands\n")
        except Exception as e:
            self.terminal_text.insert(tk.END, f"Error: {e}\n")
        
        self.terminal_text.see(tk.END)

    def run_ping(self, ip):
        """Execute ping command"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            count = '4'
            command = ['ping', param, count, ip]
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            self.terminal_text.insert(tk.END, output + "\n")
        except subprocess.CalledProcessError as e:
            self.terminal_text.insert(tk.END, e.output + "\n")
        except Exception as e:
            self.terminal_text.insert(tk.END, f"Ping error: {e}\n")

    def run_tracert(self, ip):
        """Execute tracert/traceroute command"""
        try:
            command = ['tracert', ip] if platform.system().lower() == 'windows' else ['traceroute', ip]
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            self.terminal_text.insert(tk.END, output + "\n")
        except subprocess.CalledProcessError as e:
            self.terminal_text.insert(tk.END, e.output + "\n")
        except Exception as e:
            self.terminal_text.insert(tk.END, f"Tracert error: {e}\n")

    def run_netstat(self):
        """Execute netstat command"""
        try:
            command = ['netstat', '-ano'] if platform.system().lower() == 'windows' else ['netstat', '-tulnp']
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            self.terminal_text.insert(tk.END, output + "\n")
        except subprocess.CalledProcessError as e:
            self.terminal_text.insert(tk.END, e.output + "\n")
        except Exception as e:
            self.terminal_text.insert(tk.END, f"Netstat error: {e}\n")

    def run_nslookup(self, host):
        """Execute nslookup command"""
        try:
            command = ['nslookup', host]
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            self.terminal_text.insert(tk.END, output + "\n")
        except subprocess.CalledProcessError as e:
            self.terminal_text.insert(tk.END, e.output + "\n")
        except Exception as e:
            self.terminal_text.insert(tk.END, f"NSLookup error: {e}\n")

    def run_ifconfig(self):
        """Execute ifconfig/ipconfig command"""
        try:
            command = ['ipconfig', '/all'] if platform.system().lower() == 'windows' else ['ifconfig']
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            self.terminal_text.insert(tk.END, output + "\n")
        except subprocess.CalledProcessError as e:
            self.terminal_text.insert(tk.END, e.output + "\n")
        except Exception as e:
            self.terminal_text.insert(tk.END, f"Interface config error: {e}\n")

    def start_monitoring(self, ip=None):
        """Start monitoring a target IP"""
        if not ip:
            ip = self.ip_entry.get().strip()
        
        if not ip:
            messagebox.showerror("Error", "Please enter a target IP address")
            return
        
        if self.monitor.start_monitoring(ip):
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.update_status_indicators()
            
            # Update terminal
            self.terminal_text.insert(tk.END, f"Started monitoring {ip}\n")
            self.terminal_text.see(tk.END)

    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitor.stop_monitoring()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.update_status_indicators()
        
        # Update terminal
        self.terminal_text.insert(tk.END, "Stopped monitoring\n")
        self.terminal_text.see(tk.END)

    def update_status_indicators(self):
        """Update the status indicators"""
        # Monitoring status
        monitoring_color = "green" if self.monitor.monitoring else "red"
        self.status_labels['monitoring'].itemconfig(1, fill=monitoring_color)
        
        # Baseline status
        baseline_color = "green" if self.monitor.baseline_established else "red"
        self.status_labels['baseline'].itemconfig(1, fill=baseline_color)
        
        # Telegram status
        telegram_color = "green" if self.monitor.telegram_bot_token and self.monitor.telegram_chat_id else "red"
        self.status_labels['telegram'].itemconfig(1, fill=telegram_color)

    def show_ping_dialog(self):
        """Show ping dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Ping")
        dialog.geometry("400x200")
        
        ttk.Label(dialog, text="Enter IP address or hostname:").pack(pady=10)
        ip_entry = ttk.Entry(dialog)
        ip_entry.pack(pady=5, padx=20, fill=tk.X)
        
        output_text = scrolledtext.ScrolledText(
            dialog, wrap=tk.WORD, height=8, bg='black', fg='green', insertbackground='green'
        )
        output_text.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        
        def do_ping():
            ip = ip_entry.get().strip()
            if not ip:
                messagebox.showerror("Error", "Please enter an IP address")
                return
            
            try:
                param = '-n' if platform.system().lower() == 'windows' else '-c'
                count = '4'
                command = ['ping', param, count, ip]
                output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
                output_text.insert(tk.END, output + "\n")
            except subprocess.CalledProcessError as e:
                output_text.insert(tk.END, e.output + "\n")
            except Exception as e:
                output_text.insert(tk.END, f"Error: {e}\n")
            
            output_text.see(tk.END)
        
        ttk.Button(dialog, text="Ping", command=do_ping).pack(pady=5)

    def show_tracert_dialog(self):
        """Show tracert dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Traceroute")
        dialog.geometry("400x200")
        
        ttk.Label(dialog, text="Enter IP address or hostname:").pack(pady=10)
        ip_entry = ttk.Entry(dialog)
        ip_entry.pack(pady=5, padx=20, fill=tk.X)
        
        output_text = scrolledtext.ScrolledText(
            dialog, wrap=tk.WORD, height=8, bg='black', fg='green', insertbackground='green'
        )
        output_text.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        
        def do_tracert():
            ip = ip_entry.get().strip()
            if not ip:
                messagebox.showerror("Error", "Please enter an IP address")
                return
            
            try:
                command = ['tracert', ip] if platform.system().lower() == 'windows' else ['traceroute', ip]
                output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
                output_text.insert(tk.END, output + "\n")
            except subprocess.CalledProcessError as e:
                output_text.insert(tk.END, e.output + "\n")
            except Exception as e:
                output_text.insert(tk.END, f"Error: {e}\n")
            
            output_text.see(tk.END)
        
        ttk.Button(dialog, text="Trace", command=do_tracert).pack(pady=5)

    def show_nslookup_dialog(self):
        """Show nslookup dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("NSLookup")
        dialog.geometry("400x200")
        
        ttk.Label(dialog, text="Enter hostname or IP address:").pack(pady=10)
        host_entry = ttk.Entry(dialog)
        host_entry.pack(pady=5, padx=20, fill=tk.X)
        
        output_text = scrolledtext.ScrolledText(
            dialog, wrap=tk.WORD, height=8, bg='black', fg='green', insertbackground='green'
        )
        output_text.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        
        def do_nslookup():
            host = host_entry.get().strip()
            if not host:
                messagebox.showerror("Error", "Please enter a hostname or IP")
                return
            
            try:
                command = ['nslookup', host]
                output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
                output_text.insert(tk.END, output + "\n")
            except subprocess.CalledProcessError as e:
                output_text.insert(tk.END, e.output + "\n")
            except Exception as e:
                output_text.insert(tk.END, f"Error: {e}\n")
            
            output_text.see(tk.END)
        
        ttk.Button(dialog, text="Lookup", command=do_nslookup).pack(pady=5)

    def show_traffic_stats(self):
        """Show traffic statistics"""
        stats = self.monitor.get_traffic_stats()
        baseline = self.monitor.get_baseline_stats()
        
        # Create dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Traffic Statistics")
        dialog.geometry("600x400")
        
        # Create notebook for different views
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Table view
        table_frame = ttk.Frame(notebook)
        notebook.add(table_frame, text="Table")
        
        tree = ttk.Treeview(table_frame, columns=('Metric', 'Value'), show='headings')
        tree.heading('Metric', text='Metric')
        tree.heading('Value', text='Value')
        tree.column('Metric', width=200)
        tree.column('Value', width=200)
        
        # Add stats to table
        if stats:
            for key, value in stats.items():
                if isinstance(value, set):
                    value = f"{len(value)} ports"
                tree.insert('', tk.END, values=(key.replace('_', ' ').title(), value))
        
        if baseline:
            tree.insert('', tk.END, values=('Baseline Packets/Min', baseline.get('avg_packets_per_minute', 'N/A')))
        
        tree.pack(fill=tk.BOTH, expand=True)
        
        # Chart view
        chart_frame = ttk.Frame(notebook)
        notebook.add(chart_frame, text="Charts")
        
        if stats:
            try:
                # Prepare data for chart
                labels = []
                values = []
                
                for key, value in stats.items():
                    if isinstance(value, (int, float)):
                        labels.append(key.replace('_', ' ').title())
                        values.append(value)
                
                if labels and values:
                    fig, ax = plt.subplots(figsize=(6, 4), facecolor='black')
                    ax.set_facecolor('black')
                    ax.tick_params(colors='green')
                    for spine in ax.spines.values():
                        spine.set_color('green')
                    
                    # Create bar chart
                    bars = ax.bar(labels, values, color='green')
                    ax.set_title('Traffic Statistics', color='green')
                    
                    # Add value labels
                    for bar in bars:
                        height = bar.get_height()
                        ax.text(bar.get_x() + bar.get_width()/2., height,
                                f'{int(height)}', ha='center', va='bottom', color='green')
                    
                    # Embed in Tkinter
                    canvas = FigureCanvasTkAgg(fig, master=chart_frame)
                    canvas.draw()
                    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            except Exception as e:
                logger.error(f"Error creating chart: {e}")
                ttk.Label(chart_frame, text="Error creating chart").pack()

    def show_threat_analysis(self):
        """Show threat analysis"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Threat Analysis")
        dialog.geometry("600x400")
        
        # Create notebook for different views
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Threats frame
        threats_frame = ttk.Frame(notebook)
        notebook.add(threats_frame, text="Threats")
        
        # Create a treeview for threats
        tree = ttk.Treeview(threats_frame, columns=('Type', 'Threshold', 'Current'), show='headings')
        tree.heading('Type', text='Threat Type')
        tree.heading('Threshold', text='Threshold')
        tree.heading('Current', text='Current Value')
        tree.column('Type', width=200)
        tree.column('Threshold', width=150)
        tree.column('Current', width=150)
        
        # Add threat data
        stats = self.monitor.get_traffic_stats()
        thresholds = self.monitor.alert_thresholds
        
        # DOS threat
        inbound_packets = stats.get('inbound_packets', 0)
        elapsed_seconds = time.time() % 60
        packets_per_second = inbound_packets / elapsed_seconds if elapsed_seconds > 0 else 0
        tree.insert('', tk.END, values=(
            'DOS Attack', 
            f"{thresholds['dos']} pkt/sec",
            f"{packets_per_second:.1f} pkt/sec"
        ))
        
        # Port scan threat
        ports_scanned = len(stats.get('ports_scanned', set()))
        ports_per_second = ports_scanned / elapsed_seconds if elapsed_seconds > 0 else 0
        tree.insert('', tk.END, values=(
            'Port Scan', 
            f"{thresholds['port_scan']} ports/sec",
            f"{ports_per_second:.1f} ports/sec"
        ))
        
        # Unusual traffic threat
        baseline = self.monitor.baseline_stats.get('avg_packets_per_minute', 1)
        current_packets = stats.get('total_packets', 0)
        increase = ((current_packets - baseline) / baseline) * 100 if baseline > 0 else 0
        tree.insert('', tk.END, values=(
            'Unusual Traffic', 
            f"{thresholds['unusual_traffic']}% increase",
            f"{increase:.1f}% increase"
        ))
        
        tree.pack(fill=tk.BOTH, expand=True)
        
        # Chart frame
        chart_frame = ttk.Frame(notebook)
        notebook.add(chart_frame, text="Chart")
        
        try:
            # Prepare data for pie chart
            labels = ['Normal', 'Potential Threats']
            sizes = [70, 30]  # Placeholder values
            
            fig, ax = plt.subplots(figsize=(6, 4), facecolor='black')
            ax.set_facecolor('black')
            
            # Create pie chart
            colors = ['green', 'red']
            ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                  startangle=90, textprops={'color': 'green'})
            ax.axis('equal')  # Equal aspect ratio ensures pie is drawn as a circle
            ax.set_title('Threat Distribution', color='green')
            
            # Embed in Tkinter
            canvas = FigureCanvasTkAgg(fig, master=chart_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        except Exception as e:
            logger.error(f"Error creating pie chart: {e}")
            ttk.Label(chart_frame, text="Error creating chart").pack()

    def test_telegram(self):
        """Test Telegram connection"""
        bot_token = self.bot_token_entry.get().strip()
        chat_id = self.chat_id_entry.get().strip()
        
        if not bot_token or not chat_id:
            messagebox.showerror("Error", "Please enter both Bot Token and Chat ID")
            return
        
        try:
            self.monitor.telegram_bot_token = bot_token
            self.monitor.telegram_chat_id = chat_id
            
            if self.monitor._send_telegram_alert("🔌 Test message from Cyber Security Monitor"):
                messagebox.showinfo("Success", "Telegram connection successful!")
                self.update_status_indicators()
            else:
                messagebox.showerror("Error", "Failed to send Telegram message")
        except Exception as e:
            messagebox.showerror("Error", f"Telegram test failed: {e}")

    def save_thresholds(self):
        """Save alert thresholds"""
        try:
            self.monitor.alert_thresholds = {
                'dos': float(self.dos_threshold.get()),
                'port_scan': float(self.port_scan_threshold.get()),
                'unusual_traffic': float(self.traffic_threshold.get())
            }
            self.monitor.save_config()
            messagebox.showinfo("Success", "Thresholds saved successfully")
        except ValueError:
            messagebox.showerror("Error", "Please enter valid numbers for thresholds")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save thresholds: {e}")

    def save_config(self):
        """Save configuration to file"""
        try:
            self.monitor.telegram_bot_token = self.bot_token_entry.get().strip()
            self.monitor.telegram_chat_id = self.chat_id_entry.get().strip()
            self.monitor.save_config()
            messagebox.showinfo("Success", "Configuration saved successfully")
            self.update_status_indicators()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save config: {e}")

    def load_config(self):
        """Load configuration from file"""
        try:
            if self.monitor.telegram_bot_token:
                self.bot_token_entry.insert(0, self.monitor.telegram_bot_token)
            if self.monitor.telegram_chat_id:
                self.chat_id_entry.insert(0, self.monitor.telegram_chat_id)
            
            # Load thresholds
            self.dos_threshold.insert(0, str(self.monitor.alert_thresholds['dos']))
            self.port_scan_threshold.insert(0, str(self.monitor.alert_thresholds['port_scan']))
            self.traffic_threshold.insert(0, str(self.monitor.alert_thresholds['unusual_traffic']))
            
            self.update_status_indicators()
        except Exception as e:
            logger.error(f"Error loading config into GUI: {e}")

    def clear_alerts(self):
        """Clear alerts display"""
        self.alerts_text.delete(1.0, tk.END)

    def export_alerts(self):
        """Export alerts to file"""
        try:
            content = self.alerts_text.get(1.0, tk.END)
            if not content.strip():
                messagebox.showwarning("Warning", "No alerts to export")
                return
            
            filename = f"alerts_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write(content)
            messagebox.showinfo("Success", f"Alerts exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export alerts: {e}")

    def show_help(self):
        """Show help information"""
        help_text = """Accurate Cyber Defense BOT
 
ian Carter Kulani 
Email:iancarterkulani@gmail.com
phone:+265(0)988061969
 
This tool monitors network traffic for potential security threats including:
- DOS/DDOS attacks
- Port scanning activity
- Unusual traffic patterns

Features:
- Real-time traffic monitoring
- Telegram alert notifications
- Traffic statistics and analysis
- Built-in network diagnostic tools

To get started:
1. Enter a target IP address
2. Click 'Start Monitoring'
3. Configure Telegram alerts in Settings
"""
        messagebox.showinfo("Help", help_text)

    def show_about(self):
        """Show about information"""
        about_text = """Cyber Security Monitoring Tool
Version 1.0

A comprehensive network security monitoring solution
with real-time threat detection and alerting.

Developed for advanced cyber security monitoring.
"""
        messagebox.showinfo("About", about_text)

    def update_gui(self):
        """Periodically update the GUI"""
        while True:
            try:
                # Update traffic chart
                self.update_traffic_chart()
                
                # Update threat chart
                self.update_threat_chart()
                
                # Check for new alerts
                self.check_alerts()
                
                # Update status bar
                self.status_bar.config(text=f"Last update: {datetime.datetime.now().strftime('%H:%M:%S')}")
                
                # Update status indicators
                self.update_status_indicators()
            except Exception as e:
                logger.error(f"GUI update error: {e}")
            
            time.sleep(UPDATE_INTERVAL)

    def update_traffic_chart(self):
        """Update the traffic chart"""
        try:
            stats = self.monitor.get_traffic_stats()
            if not stats:
                return
            
            # Clear previous chart
            self.traffic_ax.clear()
            
            # Prepare data
            labels = []
            values = []
            
            for key, value in stats.items():
                if isinstance(value, (int, float)):
                    labels.append(key.replace('_', ' ').title())
                    values.append(value)
            
            if labels and values:
                # Create new chart
                bars = self.traffic_ax.bar(labels, values, color='green')
                self.traffic_ax.set_title('Traffic Statistics', color='green')
                self.traffic_ax.tick_params(colors='green')
                
                # Add value labels
                for bar in bars:
                    height = bar.get_height()
                    self.traffic_ax.text(bar.get_x() + bar.get_width()/2., height,
                                        f'{int(height)}', ha='center', va='bottom', color='green')
                
                # Redraw
                self.traffic_canvas.draw()
        except Exception as e:
            logger.error(f"Error updating traffic chart: {e}")

    def update_threat_chart(self):
        """Update the threat chart"""
        try:
            stats = self.monitor.get_traffic_stats()
            if not stats or not self.monitor.baseline_established:
                return
            
            # Clear previous chart
            self.threat_ax.clear()
            
            # Calculate threat level (simplified)
            inbound_packets = stats.get('inbound_packets', 0)
            elapsed_seconds = time.time() % 60
            packets_per_second = inbound_packets / elapsed_seconds if elapsed_seconds > 0 else 0
            
            dos_risk = min(100, (packets_per_second / self.monitor.alert_thresholds['dos']) * 100)
            threat_level = min(100, dos_risk * 0.7)  # Weighted
            
            # Create pie chart
            labels = ['Normal', 'Potential Threats']
            sizes = [100 - threat_level, threat_level]
            colors = ['green', 'red']
            
            self.threat_ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                              startangle=90, textprops={'color': 'green'})
            self.threat_ax.set_title('Threat Distribution', color='green')
            
            # Redraw
            self.threat_canvas.draw()
        except Exception as e:
            logger.error(f"Error updating threat chart: {e}")

    def check_alerts(self):
        """Check for new alerts from monitor"""
        try:
            while not self.monitor.alert_queue.empty():
                alert_type, message = self.monitor.alert_queue.get()
                self.alerts_text.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {message}\n")
                self.alerts_text.see(tk.END)
        except Exception as e:
            logger.error(f"Error checking alerts: {e}")

def main():
    """Main application entry point"""
    try:
        root = tk.Tk()
        app = CyberSecurityToolGUI(root)
        root.mainloop()
    except Exception as e:
        logger.error(f"Application error: {e}")
        messagebox.showerror("Error", f"Application error: {e}")

if __name__ == "__main__":
    main()