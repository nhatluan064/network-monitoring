import time
import socketio
import threading
import datetime
import logging
from scapy.all import sniff, DNS, DNSQR, IP, TCP, UDP, conf

import json
import os
import sys
import socket

# --- CONFIGURATION ---
# Default fallback
DEFAULT_SERVER_URL = 'http://10.10.85.3:5000'

def load_config():
    config_path = 'config.json'
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                return config.get('server_url', DEFAULT_SERVER_URL)
        except:
            pass
    return DEFAULT_SERVER_URL

SERVER_URL = load_config()
# ---------------------

# Setup Logging to File
log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'agent_debug.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger()

sio = socketio.Client()
my_ip = "Unknown"

def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

my_ip = get_host_ip()

# Connection tracking
recent_connections = set()

def packet_callback(packet):
    if not sio.connected:
        return

    try:
        # DNS Monitoring
        if packet.haslayer(DNS) and packet.haslayer(IP):
            dns_layer = packet.getlayer(DNS)
            if dns_layer.qr == 1 and dns_layer.ancount > 0: # Response
                query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                resolved_ip = "N/A"
                for i in range(dns_layer.ancount):
                    r = dns_layer.an[i]
                    if r.type == 1: 
                        resolved_ip = r.rdata
                        break
                
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                category = "Normal"
                suspicious_keywords = ['youtube', 'facebook', 'tiktok', 'game', 'steam', 'bet', 'movie', 'phim', 'netflix', 'shopee', 'lazada']
                for keyword in suspicious_keywords:
                    if keyword in query_name.lower():
                        category = "Suspicious"
                        break
                
                data = {
                    'timestamp': timestamp,
                    'src_ip': my_ip, # Force Source IP to be THIS machine
                    'domain': query_name,
                    'resolved_ip': resolved_ip,
                    'category': category,
                    'type': 'dns'
                }
                sio.emit('agent_data', data)

        # Connection Monitoring
        elif packet.haslayer(IP):
            if packet[IP].src != my_ip: return # Only track OUTGOING connections from this machine
            
            ip_dst = packet[IP].dst
            protocol = "OTHER"
            src_port = ""
            dst_port = ""
            
            if packet.haslayer(TCP):
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            else:
                return

            conn_sig = f"{my_ip}:{src_port}->{ip_dst}:{dst_port}"
            if conn_sig in recent_connections: return
            recent_connections.add(conn_sig)
            if len(recent_connections) > 1000: recent_connections.clear()
            
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            conn_data = {
                'timestamp': timestamp,
                'src_ip': my_ip,
                'src_port': src_port,
                'dst_ip': ip_dst,
                'dst_port': dst_port,
                'protocol': protocol,
                'type': 'connection'
            }
            sio.emit('agent_data', conn_data)

    except Exception:
        pass

def sniffer_job():
    logger.info(f"Agent Sniffer started on {my_ip}")
    # Sniff on all interfaces
    sniff(filter="ip", prn=packet_callback, store=0)

def connect_to_server():
    while True:
        try:
            if not sio.connected:
                logger.info(f"Connecting to server at {SERVER_URL}...")
                sio.connect(SERVER_URL)
                logger.info("Connected to Server!")
            time.sleep(5)
        except Exception as e:
            logger.error(f"Connection failed: {e}. Retrying in 5s...")
            time.sleep(5)

if __name__ == '__main__':
    # Start connection thread
    conn_thread = threading.Thread(target=connect_to_server, daemon=True)
    conn_thread.start()
    
    # Start sniffer
    sniffer_job()
