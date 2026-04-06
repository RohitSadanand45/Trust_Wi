import subprocess
import re

def scan_wifi():
    print("\n📡 Scanning Wi-Fi networks...\n")

    command = "netsh wlan show networks mode=Bssid"
    result = subprocess.check_output(command, shell=True, text=True, encoding='utf-8', errors='ignore')

    networks = []
    current_ssid = None
    current_security = None

    lines = result.split('\n')

    for line in lines:
        line = line.strip()

        # Match SSID lines: "SSID X : NetworkName"
        ssid_match = re.match(r'^SSID\s+(\d+)\s*:\s*(.+)$', line)
        if ssid_match:
            # Save previous network if we have both SSID and security
            if current_ssid and current_security:
                networks.append({
                    "ssid": current_ssid,
                    "security": current_security
                })

            # Start new network
            current_ssid = ssid_match.group(2).strip()
            current_security = None
            continue

        # Match Authentication lines
        if line.startswith('Authentication') and ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                current_security = parts[1].strip()

    # Don't forget the last network
    if current_ssid and current_security:
        networks.append({
            "ssid": current_ssid,
            "security": current_security
        })

    # Remove duplicates (same SSID with different security might appear)
    seen = set()
    unique_networks = []
    for net in networks:
        key = (net['ssid'], net['security'])
        if key not in seen:
            seen.add(key)
            unique_networks.append(net)

    return unique_networks