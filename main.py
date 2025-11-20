import logging
from flask import Flask, render_template, jsonify, send_file
from flask_socketio import SocketIO
from scapy.all import sniff, DNS, DNSQR, IP, TCP, UDP, get_if_list, conf, arping, Ether, ARP, srp
from scapy.arch.windows import get_windows_if_list
import threading
import datetime
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
import json
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger()

# Global cache for keywords
_keywords_cache = []
_keywords_mtime = 0

def get_suspicious_keywords():
    """
    Returns the list of suspicious keywords, reloading from file if it has changed.
    """
    global _keywords_cache, _keywords_mtime
    
    config_path = 'suspicious_keywords.json'
    default_keywords = [
        'youtube', 'facebook', 'tiktok', 'game', 'steam', 'bet', 'movie', 'phim', 'netflix', 
        'shopee', 'lazada', 'truyen', 'manga', 'comic', 'nettruyen', 'fuhu', '8cache', 'blogtruyen',
        'garena', 'roblox', 'minecraft', 'valorant', 'leagueoflegends'
    ]

    if not os.path.exists(config_path):
        return default_keywords

    try:
        current_mtime = os.path.getmtime(config_path)
        if current_mtime > _keywords_mtime:
            with open(config_path, 'r') as f:
                data = json.load(f)
                _keywords_cache = data.get('keywords', default_keywords)
                _keywords_mtime = current_mtime
                # logger.info("Reloaded suspicious keywords")
    except Exception as e:
        logger.error(f"Error reloading suspicious keywords: {e}")
        if not _keywords_cache:
            return default_keywords
            
    return _keywords_cache

# Initialize
get_suspicious_keywords()

# Global cache for ignored IPs
_ignored_ips_cache = []
_ignored_ips_mtime = 0

def get_ignored_ips():
    """
    Returns the list of ignored IPs, reloading from file if it has changed.
    """
    global _ignored_ips_cache, _ignored_ips_mtime
    
    config_path = 'ignored_ips.json'
    default_ips = []

    if not os.path.exists(config_path):
        return default_ips

    try:
        current_mtime = os.path.getmtime(config_path)
        if current_mtime > _ignored_ips_mtime:
            with open(config_path, 'r') as f:
                data = json.load(f)
                _ignored_ips_cache = data.get('ignored_ips', default_ips)
                _ignored_ips_mtime = current_mtime
    except Exception as e:
        logger.error(f"Error reloading ignored IPs: {e}")
        if not _ignored_ips_cache:
            return default_ips
            
    return _ignored_ips_cache

# Initialize
get_ignored_ips()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, async_mode='threading')

# Global control variables
sniffing_active = False
sniffer_thread = None
selected_interface = None
monitor_mode = "dns"  # "dns" or "connections"

# Connection tracking (to avoid duplicate spam)
recent_connections = set()
CONNECTION_EXPIRE_SECONDS = 5

def packet_callback(packet):
    """
    Callback function to process each captured packet.
    """
    global sniffing_active
    if not sniffing_active:
        return

    try:
        # DNS Monitoring
        # We look for DNS Responses (qr=1) to get the Resolved IP
        # OR DNS Queries (qr=0) to get the intent. 
        # To simplify, let's capture Queries for the request, and if possible responses.
        # BUT, user wants "Domain -> Resolved IP".
        # Let's stick to capturing Queries (qr=0) for responsiveness, and try to resolve locally or wait for response.
        # Actually, capturing Response (qr=1) is better because it contains BOTH the Query Name and the Answer IP.
        
        if packet.haslayer(DNS) and packet.haslayer(IP):
            dns_layer = packet.getlayer(DNS)
            
            # If it's a Response (qr=1) and has answers (ancount > 0)
            if dns_layer.qr == 1 and dns_layer.ancount > 0:
                ip_src = packet[IP].dst # In a response, the DST is the one who asked (the internal client)
                # ip_src here is the Internal IP we want to monitor
                
                # Check Ignored IPs
                if ip_src in get_ignored_ips():
                    return
                
                query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                
                # Extract the first A record (IP address) from answers
                resolved_ip = "N/A"
                for i in range(dns_layer.ancount):
                    r = dns_layer.an[i]
                    if r.type == 1: # Type A (IPv4)
                        resolved_ip = r.rdata
                        break
                
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                category = "Normal"
                category = "Normal"
                suspicious_keywords = get_suspicious_keywords()
                
                for keyword in suspicious_keywords:
                    if keyword in query_name.lower():
                        category = "Suspicious"
                        break
                
                service = identify_service(query_name)

                data = {
                    'timestamp': timestamp,
                    'src_ip': ip_src,
                    'domain': query_name,
                    'resolved_ip': resolved_ip,
                    'category': category,
                    'service': service
                }
                
                socketio.emit('new_log', data)

            # Keep capturing Queries (qr=0) just in case we miss responses or for faster feedback?
            # No, let's switch to Responses primarily for the "Resolved IP" feature. 
            # It reduces noise too.

        
        # IP Connection Monitoring (new)
        elif packet.haslayer(IP):
            ip_src = packet[IP].src
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
                return  # Skip non-TCP/UDP packets
            
            # Create connection signature to avoid spam
            conn_sig = f"{ip_src}:{src_port}->{ip_dst}:{dst_port}"
            
            # Debounce: only emit if not seen recently
            if conn_sig in recent_connections:
                return
            
            recent_connections.add(conn_sig)
            
            # Cleanup old entries (simple expiry)
            if len(recent_connections) > 1000:
                recent_connections.clear()
            
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            conn_data = {
                'timestamp': timestamp,
                'src_ip': ip_src,
                'src_port': src_port,
                'dst_ip': ip_dst,
                'dst_port': dst_port,
                'protocol': protocol
            }
            
            socketio.emit('new_connection', conn_data)

    except Exception as e:
        # logger.error(f"Error processing packet: {e}")
        pass

def sniffer_job(interface_name):
    """
    The background job that runs the sniffer.
    """
    global sniffing_active
    logger.info(f"Sniffer started on interface: {interface_name}")
    
    try:
        # Scapy sniff loop
        # CRITICAL FIX: Only capture DNS to prevent ERP/MES/Printing lag
        sniff(
            iface=interface_name, 
            filter="udp port 53",  # DNS-only prevents production system interference
            prn=packet_callback, 
            store=0,
            stop_filter=lambda x: not sniffing_active
        )
    except Exception as e:
        logger.error(f"Sniffer error: {e}")
        socketio.emit('sniffer_error', {'message': str(e)})
    finally:
        logger.info("Sniffer thread stopped.")
        sniffing_active = False
        recent_connections.clear()
        socketio.emit('status_update', {'status': 'Stopped'})

def scan_network(interface_name, ip_address):
    """
    Performs an ARP scan to find active devices on the local network.
    """
    logger.info(f"Starting Network Scan on {interface_name} with IP {ip_address}...")
    try:
        if not ip_address or ip_address == "0.0.0.0":
            logger.warning("No valid IP provided for scan.")
            return

        # Assume /24
        ip_parts = ip_address.split('.')
        subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        
        logger.info(f"Scanning subnet: {subnet}")
        
        # Use scapy's srp (send/receive packet) for ARP
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), timeout=2, iface=interface_name, verbose=0)
        
        devices = []
        for sent, received in ans:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
            
        logger.info(f"Scan complete. Found {len(devices)} devices.")
        socketio.emit('network_scan_result', {'devices': devices})
        
    except Exception as e:
        logger.error(f"Network scan failed: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/download/keywords')
def download_keywords():
    """Serve the suspicious_keywords.json for agents to download"""
    try:
        return send_file('suspicious_keywords.json', as_attachment=True)
    except:
        # Return default if file not found
        return jsonify({"keywords": [
            "youtube", "facebook", "tiktok", "game", "steam", "bet", 
            "movie", "phim", "netflix", "shopee", "lazada"
        ]})

@app.route('/interfaces')
def get_interfaces():
    """
    Returns a list of available network interfaces using get_windows_if_list.
    """
    try:
        # get_windows_if_list is reliable on this system as per debug
        interfaces = get_windows_if_list()
        
        if_list = []
        for i in interfaces:
            # Filter: Only show interfaces with IP addresses (active ones)
            # This hides the many virtual/loopback adapters that confuse the user
            if not i.get('ips'):
                continue
                
            # Format: "Friendly Name (Connection Name) - IP"
            # e.g. "Intel(R) Ethernet... (Ethernet) - 10.10.85.3"
            ip_str = i['ips'][1] if len(i['ips']) > 1 else i['ips'][0] # Prefer IPv4 if available (usually 2nd in list if IPv6 is first)
            
            # Check if IPv4
            for ip in i['ips']:
                if '.' in ip:
                    ip_str = ip
                    break
            
            friendly_name = f"{i['description']} ({i['name']})"
            
            if_list.append({
                'id': i['name'], # Use the Connection Name (e.g., "Ethernet") for sniffing
                'name': friendly_name,
                'ip': ip_str
            })
            
        return jsonify(if_list)
    except Exception as e:
        logger.error(f"Error listing interfaces: {e}")
        # Fallback to simple list if advanced fails
        return jsonify([{'id': str(i), 'name': str(i), 'ip': ''} for i in get_if_list()])

@socketio.on('start_sniffer')
def handle_start_sniffer(data):
    global sniffing_active, sniffer_thread, selected_interface
    
    interface_id = data.get('interface')
    interface_ip = data.get('ip')

    if not interface_id:
        return
        
    if sniffing_active:
        return

    selected_interface = interface_id
    sniffing_active = True
    
    sniffer_thread = threading.Thread(target=sniffer_job, args=(selected_interface,), daemon=True)
    sniffer_thread.start()
    
    # Start Network Scan in parallel
    scan_thread = threading.Thread(target=scan_network, args=(selected_interface, interface_ip), daemon=True)
    scan_thread.start()
    
    socketio.emit('status_update', {'status': 'Running'})

@socketio.on('get_status')
def handle_get_status():
    global sniffing_active
    status = 'Running' if sniffing_active else 'Stopped'
    socketio.emit('status_update', {'status': status})

@socketio.on('stop_sniffer')
def handle_stop_sniffer():
    global sniffing_active
    sniffing_active = False
    # The sniff() function's stop_filter will catch this flag and exit
    socketio.emit('status_update', {'status': 'Stopping...'})

def identify_service(domain):
    d = domain.lower()
    if any(x in d for x in ['youtube', 'googlevideo', 'ytimg']): return 'YouTube'
    if any(x in d for x in ['facebook', 'fbcdn', 'fbsbx', 'messenger']): return 'Facebook'
    if any(x in d for x in ['google', 'gstatic', 'gvt1', 'gvt2', 'gmail', 'googleapis']): return 'Google'
    if any(x in d for x in ['tiktok', 'byteoversea', 'ibyteimg']): return 'TikTok'
    if any(x in d for x in ['netflix', 'nflxvideo']): return 'Netflix'
    if any(x in d for x in ['shopee']): return 'Shopee'
    if any(x in d for x in ['lazada']): return 'Lazada'
    if any(x in d for x in ['zalo']): return 'Zalo'
    if any(x in d for x in ['instagram', 'cdninstagram']): return 'Instagram'
    if any(x in d for x in ['microsoft', 'live.com', 'office', 'bing', 'azure', 'msn', 'windows']): return 'Microsoft'
    if any(x in d for x in ['apple', 'icloud', 'aaplimg']): return 'Apple'
    if any(x in d for x in ['steam', 'valve']): return 'Steam'
    if any(x in d for x in ['roblox']): return 'Roblox'
    if any(x in d for x in ['garena']): return 'Garena'
    if any(x in d for x in ['cellphones', 'sforum']): return 'Cellphones'
    if any(x in d for x in ['wattpad']): return 'Wattpad'
    if any(x in d for x in ['truyen', 'manga', 'comic', 'nettruyen', 'fuhu', '8cache', 'blogtruyen']): return 'Comics/Stories'
    return 'Other'

def is_background_traffic(domain, service):
    """
    Returns True if the domain is likely background/system traffic.
    """
    d = domain.lower()
    # System/Technical domains
    if any(x in d for x in ['googleapis', 'gstatic', '1e100', 'akamaiedge', 'fastly', 'azure', 'msn.com', 'microsoft.com', 'windowsupdate', 'telemetry', 'doubleclick', 'analytics']):
        return True
    # If it's just "Google" or "Microsoft" generic services, usually background
    if service in ['Google', 'Microsoft', 'Apple']:
        if 'mail' not in d and 'drive' not in d and 'docs' not in d and 'portal' not in d:
            return True
    return False

# --- ALERT ENGINE ---
class AlertEngine:
    def __init__(self):
        self.scores = {} # {ip: score}
        self.threshold = 50
        self.decay_rate = 1

    def process_activity(self, ip, category, service):
        if ip not in self.scores: self.scores[ip] = 0
        
        if category == 'Suspicious':
            self.scores[ip] += 10
        elif category == 'Normal':
            self.scores[ip] = max(0, self.scores[ip] - self.decay_rate)
            
        # Check Threshold
        if self.scores[ip] > self.threshold:
            return True, self.scores[ip]
        return False, self.scores[ip]

alert_engine = AlertEngine()

@socketio.on('agent_data')
def handle_agent_data(data):
    """
    Receives data from remote agents and broadcasts it to the dashboard.
    """
    # Master Switch: If monitoring is stopped, ignore ALL data
    # if not sniffing_active:
    #     return

    # Check Ignored IPs
    src_ip = data.get('src_ip')
    if src_ip in get_ignored_ips():
        return

    # Determine type of data
    data_type = data.get('type')
    
    if data_type == 'dns':
        # IMPORTANT: Re-classify category based on SERVER keywords
        # Agent sends everything as "Normal", server decides if Suspicious
        domain = data.get('domain', '')
        category = "Normal"
        suspicious_keywords = get_suspicious_keywords()
        
        for keyword in suspicious_keywords:
            if keyword in domain.lower():
                category = "Suspicious"
                break
        
        # Update the category with server-side classification
        data['category'] = category
        
        # Enrich with Service Name
        data['service'] = identify_service(domain)
        data['is_background'] = is_background_traffic(domain, data['service'])
        
        # Process for Alerts
        src_ip = data.get('src_ip')
        category = data.get('category')
        is_alert, score = alert_engine.process_activity(src_ip, category, data['service'])
        
        if is_alert:
            alert_data = {
                'src_ip': src_ip,
                'score': score,
                'message': f"High suspicious activity detected from {src_ip} (Score: {score})",
                'timestamp': data.get('timestamp')
            }
            socketio.emit('new_alert', alert_data)

        # Broadcast as new_log
        socketio.emit('new_log', data)
    elif data_type == 'connection':
        # Broadcast as new_connection
        socketio.emit('new_connection', data)
    
    # Optional: Log that we received agent data
    # logger.info(f"Received data from agent {data.get('src_ip')}")

if __name__ == '__main__':
    logger.info("Starting Web Server on http://0.0.0.0:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
