"""Packet monitoring module for Smart Public Wi-Fi Trust Analyzer."""

from scapy.all import sniff, IP, TCP, UDP
import time
import socket
import subprocess
import threading
import re
from collections import defaultdict
from logger import log_event

monitoring_active = False
alerts = []
packet_count = 0
ip_counter = defaultdict(int)
last_rate_check = time.time()
last_scan_time = 0
connected_devices = set()

MALWARE_IPS = {
    '185.176.27.0/24',
    '45.155.205.0/24',
    '91.92.109.43',
    '185.130.5.0/24',
}

SUSPICIOUS_PORTS = {22, 23, 445, 3389, 5900, 6667, 31337}
ROUTER_IPS = {'192.168.1.1', '192.168.0.1', '10.0.0.1'}


def add_alert(alert_type, severity, message, details=''):
    alert = {
        'type': alert_type,
        'severity': severity,
        'message': message,
        'timestamp': time.time(),
        'details': details,
    }
    alerts.append(alert)
    log_event(f"{severity} - {message} | {details}")
    return alert


def is_malware_ip(ip):
    for malware_range in MALWARE_IPS:
        if '/' in malware_range:
            prefix = malware_range.split('/')[0]
            if ip.startswith(prefix):
                return True
        elif ip == malware_range:
            return True
    return False


def check_network_connectivity():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        current_ip = s.getsockname()[0]
        s.close()
        return True, current_ip
    except Exception:
        return False, None


def get_local_subnet(current_ip):
    parts = current_ip.split('.')
    if len(parts) != 4:
        return '192.168.1.0/24'
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def nmap_network_scan(subnet='192.168.1.0/24'):
    try:
        cmd = f'nmap -sn {subnet} -oX -'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return parse_nmap_output(result.stdout)
        return basic_network_scan(subnet)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return basic_network_scan(subnet)


def basic_network_scan(subnet='192.168.1.0/24'):
    devices = []
    base_ip = subnet.split('/')[0].rsplit('.', 1)[0]

    for i in range(1, 255):
        ip = f"{base_ip}.{i}"
        try:
            result = subprocess.run(
                f'ping -n 1 -w 100 {ip}',
                shell=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 or 'TTL=' in result.stdout:
                devices.append({'ip': ip, 'hostname': 'Unknown', 'status': 'up'})
        except Exception:
            continue

    return devices


def parse_nmap_output(xml_output):
    devices = []
    hosts = re.findall(r'<host.*?>(.*?)</host>', xml_output, re.DOTALL)
    for host in hosts:
        ip_match = re.search(r'<address addr="([^"]*)" addrtype="ipv4"', host)
        hostname_match = re.search(r'<hostname name="([^"]*)"', host)
        if ip_match:
            devices.append({
                'ip': ip_match.group(1),
                'hostname': hostname_match.group(1) if hostname_match else 'Unknown',
                'status': 'up',
            })
    return devices


def analyze_network_changes(current_devices):
    global connected_devices
    current_ips = {dev['ip'] for dev in current_devices}
    new_devices = current_ips - connected_devices
    disconnected_devices = connected_devices - current_ips

    for ip in new_devices:
        if ip in ROUTER_IPS:
            continue
        device = next((d for d in current_devices if d['ip'] == ip), None)
        if device:
            add_alert(
                'NEW_DEVICE',
                'INFO',
                f'New device connected: {ip} ({device.get("hostname", "Unknown")})',
                'Device joined the local network.',
            )
            if is_malware_ip(ip):
                add_alert(
                    'SUSPICIOUS_DEVICE',
                    'ALERT',
                    f'Suspicious device detected: {ip}',
                    'The discovered device matches a known malicious range.',
                )

    for ip in disconnected_devices:
        add_alert(
            'DEVICE_DISCONNECTED',
            'INFO',
            f'Device disconnected: {ip}',
            'A device left the local network.',
        )

    connected_devices = current_ips


def port_scan_target(ip):
    open_ports = []
    for port in [22, 23, 80, 443, 445, 3389, 5900]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            continue
    return open_ports


def monitor_ports(devices):
    for device in devices:
        ip = device.get('ip')
        if ip in ROUTER_IPS:
            continue
        for port in port_scan_target(ip):
            severity = 'ALERT' if port in SUSPICIOUS_PORTS else 'WARNING'
            add_alert(
                'OPEN_PORT',
                severity,
                f'{ip} has open port {port}',
                f'Open port {port} may expose a service to the public network.',
            )


def analyze_packet(packet):
    global packet_count
    if not monitoring_active:
        return

    packet_count += 1
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if src_ip in ROUTER_IPS or dst_ip in ROUTER_IPS:
            return

        ip_counter[src_ip] += 1

        if is_malware_ip(src_ip) or is_malware_ip(dst_ip):
            add_alert(
                'MALWARE_TRAFFIC',
                'ALERT',
                f'Malware IP seen in traffic: {src_ip if is_malware_ip(src_ip) else dst_ip}',
                f'Traffic between {src_ip} and {dst_ip} detected.',
            )

        if ip_counter[src_ip] > 100:
            add_alert(
                'HIGH_TRAFFIC',
                'WARNING',
                f'High packet volume from {src_ip}',
                f'{ip_counter[src_ip]} packets counted in the current monitoring window.',
            )

    if packet.haslayer(TCP):
        ports = {packet[TCP].sport, packet[TCP].dport}
        for port in ports:
            if port in SUSPICIOUS_PORTS:
                add_alert(
                    'SUSPICIOUS_PORT',
                    'ALERT',
                    f'Suspicious TCP port activity on {port}',
                    'Potential attack or scanning behavior detected.',
                )
            elif port == 80:
                add_alert(
                    'HTTP_TRAFFIC',
                    'INFO',
                    'Unencrypted HTTP traffic observed.',
                    'Traffic on port 80 may be insecure.',
                )
    elif packet.haslayer(UDP):
        ports = {packet[UDP].sport, packet[UDP].dport}
        for port in ports:
            if port in SUSPICIOUS_PORTS:
                add_alert(
                    'SUSPICIOUS_PORT',
                    'WARNING',
                    f'Suspicious UDP port activity on {port}',
                    'UDP port monitoring flagged potential misuse.',
                )

    check_packet_rate()


def check_packet_rate():
    global packet_count, last_rate_check
    now = time.time()
    elapsed = now - last_rate_check
    if elapsed < 10:
        return

    rate = packet_count / max(elapsed, 1)
    if rate > 80:
        add_alert(
            'PACKET_RATE',
            'ALERT',
            f'Very high traffic rate: {rate:.1f} packets/sec',
            'Possible flood or scan activity.',
        )
    elif rate > 30:
        add_alert(
            'PACKET_RATE',
            'WARNING',
            f'High traffic rate: {rate:.1f} packets/sec',
            'Monitor for suspicious behavior.',
        )

    packet_count = 0
    last_rate_check = now


def continuous_monitoring():
    global monitoring_active, last_scan_time
    log_event('Starting continuous monitoring')

    while monitoring_active:
        try:
            connected, current_ip = check_network_connectivity()
            if not connected:
                add_alert(
                    'NETWORK_DISCONNECTED',
                    'INFO',
                    'Network disconnected.',
                    'Monitoring paused until connection returns.',
                )
                time.sleep(10)
                continue

            subnet = get_local_subnet(current_ip)
            now = time.time()
            if now - last_scan_time > 60:
                devices = nmap_network_scan(subnet)
                if devices:
                    analyze_network_changes(devices)
                    monitor_ports(devices)
                last_scan_time = now

            try:
                sniff(prn=analyze_packet, store=False, timeout=20)
            except Exception as exc:
                log_event(f'Scapy sniff error: {exc}')

            if len(alerts) > 200:
                del alerts[:-200]

        except Exception as exc:
            log_event(f'Monitoring loop error: {exc}')
            time.sleep(10)

    log_event('Monitoring stopped')


def start_monitoring():
    global monitoring_active
    if monitoring_active:
        return
    monitoring_active = True
    thread = threading.Thread(target=continuous_monitoring, daemon=True)
    thread.start()
    log_event('Monitoring thread started')


def stop_monitoring():
    global monitoring_active
    monitoring_active = False
    log_event('Monitoring thread stopped')


def get_alerts():
    return alerts.copy()


def clear_alerts():
    alerts.clear()
