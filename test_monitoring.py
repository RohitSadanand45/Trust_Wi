from packet_monitor import nmap_network_scan, basic_network_scan
import socket

print('Testing network scanning...')

# Get current IP to determine subnet
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    current_ip = s.getsockname()[0]
    s.close()

    ip_parts = current_ip.split('.')
    subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

    print(f'Current IP: {current_ip}')
    print(f'Scanning subnet: {subnet}')

    # Test Nmap first (will fallback to basic)
    print('Testing Nmap scan...')
    devices = nmap_network_scan(subnet)
    print(f'Nmap found {len(devices)} devices')

    # Test basic scan
    print('Testing basic ping scan...')
    devices = basic_network_scan(subnet)
    print(f'Basic scan found {len(devices)} devices')

    for device in devices[:10]:  # Show first 10
        print(f'  {device["ip"]} - {device["hostname"]}')

except Exception as e:
    print(f'Error: {e}')