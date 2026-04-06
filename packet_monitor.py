import subprocess
import time
from collections import defaultdict
import threading
import socket
import json

# Global monitoring state
monitoring_active = False
alerts = []

# Network monitoring data
connected_devices = set()
device_activity = defaultdict(int)
last_scan_time = 0

# Known malicious IPs (sample - in production, use threat intelligence feeds)
MALWARE_IPS = {
    "185.176.27.0/24",  # Example malware C2
    "45.155.205.0/24",  # Example botnet
    "91.92.109.43",     # Known malicious IP
    "185.130.5.0/24",   # Ransomware C2
}

SUSPICIOUS_PORTS = {22, 23, 445, 3389, 5900, 6667, 31337}  # Common attack ports

def is_malware_ip(ip):
    """Check if IP is in known malware ranges"""
    for malware_range in MALWARE_IPS:
        if "/" in malware_range:
            # CIDR notation - simplified check
            network = malware_range.split("/")[0]
            if ip.startswith(network.split(".")[:-1]):
                return True
        elif ip == malware_range:
            return True
    return False

def check_network_connectivity():
    """Check if still connected to network"""
    try:
        # Try to get current IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        current_ip = s.getsockname()[0]
        s.close()
        return True, current_ip
    except:
        return False, None

def nmap_network_scan(subnet="192.168.1.0/24"):
    """Use Nmap to scan network for connected devices"""
    try:
        # Try Nmap first
        cmd = f'nmap -sn {subnet} -oX -'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            return parse_nmap_output(result.stdout)
        else:
            # Fallback to basic ping sweep
            return basic_network_scan(subnet)

    except (subprocess.TimeoutExpired, FileNotFoundError):
        # Nmap not available or timeout, use basic scan
        return basic_network_scan(subnet)

def basic_network_scan(subnet="192.168.1.0/24"):
    """Basic network scan using ping"""
    devices = []
    base_ip = subnet.split("/")[0].rsplit(".", 1)[0]

    for i in range(1, 255):
        ip = f"{base_ip}.{i}"
        try:
            result = subprocess.run(f'ping -n 1 -w 100 {ip}',
                                  shell=True, capture_output=True, text=True, timeout=5)
            if result.returncode == 0 or "TTL=" in result.stdout:
                devices.append({
                    "ip": ip,
                    "hostname": "Unknown",
                    "status": "up"
                })
        except:
            continue

    return devices

def parse_nmap_output(xml_output):
    """Parse Nmap XML output"""
    devices = []
    # Simple XML parsing for host entries
    import re

    # Find all host entries
    host_pattern = r'<host.*?>(.*?)</host>'
    hosts = re.findall(host_pattern, xml_output, re.DOTALL)

    for host in hosts:
        ip_match = re.search(r'<address addr="([^"]*)" addrtype="ipv4"', host)
        hostname_match = re.search(r'<hostname name="([^"]*)"', host)

        if ip_match:
            devices.append({
                "ip": ip_match.group(1),
                "hostname": hostname_match.group(1) if hostname_match else "Unknown",
                "status": "up"
            })

    return devices

def analyze_network_changes(current_devices):
    """Analyze changes in network devices"""
    global connected_devices, alerts

    current_ips = {dev['ip'] for dev in current_devices}
    new_devices = current_ips - connected_devices
    disconnected_devices = connected_devices - current_ips

    # Alert for new devices
    for ip in new_devices:
        device = next((d for d in current_devices if d['ip'] == ip), None)
        if device:
            alert = {
                "type": "NEW_DEVICE",
                "severity": "MEDIUM",
                "message": f"🆕 New device connected: {device['ip']} ({device['hostname']})",
                "timestamp": time.time(),
                "details": f"Device joined network: {device['ip']}"
            }
            alerts.append(alert)
            print(f"[MEDIUM] {alert['message']}")

            # Check if it's a suspicious device
            if is_malware_ip(device['ip']):
                alert = {
                    "type": "SUSPICIOUS_DEVICE",
                    "severity": "HIGH",
                    "message": f"🚨 SUSPICIOUS DEVICE: {device['ip']} is a known malicious host!",
                    "timestamp": time.time(),
                    "details": f"Malicious device detected: {device['ip']}"
                }
                alerts.append(alert)
                print(f"[HIGH] {alert['message']}")

    # Alert for disconnected devices
    for ip in disconnected_devices:
        alert = {
            "type": "DEVICE_DISCONNECTED",
            "severity": "LOW",
            "message": f"📴 Device disconnected: {ip}",
            "timestamp": time.time(),
            "details": f"Device left network: {ip}"
        }
        alerts.append(alert)
        print(f"[LOW] {alert['message']}")

    connected_devices = current_ips

def port_scan_target(ip):
    """Scan common ports on a target IP"""
    open_ports = []

    for port in [80, 443, 22, 445, 3389]:  # Common ports to check
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            continue

    return open_ports

def monitor_ports(devices):
    """Monitor for suspicious port activity"""
    global alerts

    for device in devices:
        open_ports = port_scan_target(device['ip'])

        for port in open_ports:
            if port in SUSPICIOUS_PORTS:
                alert = {
                    "type": "SUSPICIOUS_PORT",
                    "severity": "HIGH",
                    "message": f"⚠️ SUSPICIOUS PORT OPEN: {device['ip']} has port {port} open!",
                    "timestamp": time.time(),
                    "details": f"Device {device['ip']} has suspicious port {port} open"
                }
                alerts.append(alert)
                print(f"[HIGH] {alert['message']}")

def continuous_monitoring():
    """Main monitoring loop using Nmap and network analysis"""
    global monitoring_active, alerts, last_scan_time

    print("🔄 Starting Nmap-based network monitoring...")

    while monitoring_active:
        try:
            # Check network connectivity
            connected, current_ip = check_network_connectivity()
            if not connected:
                alert = {
                    "type": "NETWORK_DISCONNECTED",
                    "severity": "INFO",
                    "message": "📡 Network connection lost - monitoring paused",
                    "timestamp": time.time(),
                    "details": "Network connectivity check failed"
                }
                alerts.append(alert)
                print(f"[INFO] {alert['message']}")
                time.sleep(10)
                continue

            # Determine subnet from current IP
            ip_parts = current_ip.split('.')
            subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

            current_time = time.time()

            # Network scan every 60 seconds
            if current_time - last_scan_time > 60:
                print(f"🔍 Scanning network {subnet}...")
                devices = nmap_network_scan(subnet)

                if devices:
                    print(f"📊 Found {len(devices)} devices on network")
                    analyze_network_changes(devices)
                    monitor_ports(devices)

                last_scan_time = current_time

            # Clean old alerts (keep last 50)
            if len(alerts) > 50:
                alerts = alerts[-50:]

            time.sleep(10)  # Check every 10 seconds

        except Exception as e:
            print(f"Monitoring error: {e}")
            time.sleep(10)

    print("🛑 Monitoring stopped")

def start_monitoring():
    """Start the monitoring thread"""
    global monitoring_active

    if monitoring_active:
        print("Monitoring already active")
        return

    monitoring_active = True
    monitoring_thread = threading.Thread(target=continuous_monitoring, daemon=True)
    monitoring_thread.start()
    print("✅ Nmap-based monitoring started")

def stop_monitoring():
    """Stop the monitoring"""
    global monitoring_active
    monitoring_active = False
    print("🛑 Monitoring stopped")

def get_alerts():
    """Get current alerts"""
    return alerts.copy()

def clear_alerts():
    """Clear all alerts"""
    global alerts
    alerts.clear()