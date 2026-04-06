import requests
import time

print("Testing Alert System...")

# Test clearing alerts
print("Clearing existing alerts...")
response = requests.post('http://127.0.0.1:5000/api/clear_alerts')
print(f"Clear alerts: {response.status_code}")

# Test stopping/starting monitoring
print("Testing monitoring controls...")
response = requests.post('http://127.0.0.1:5000/api/stop_monitoring')
print(f"Stop monitoring: {response.status_code}")

time.sleep(2)

# Note: In a real scenario, monitoring would detect:
# - Malware IPs from known C2 servers
# - Suspicious ports (22/SSH, 445/SMB, etc.)
# - High traffic rates
# - HTTP traffic (unencrypted)
# - Network disconnections

print("\nAlert System Features:")
print("🚨 CRITICAL: Malware C2 server communications")
print("⚠️ HIGH: Suspicious IP activity (>200 packets)")
print("⚠️ MEDIUM: Suspicious port connections")
print("ℹ️ LOW: HTTP traffic detection")
print("📡 INFO: Network connectivity status")

print("\nReal-time alerts will appear in the web interface when:")
print("- Connected to a network and monitoring is active")
print("- Suspicious network traffic is detected")
print("- Known malware IPs are contacted")
print("- Unusual port activity occurs")

print("\nOpen the web interface to see live alerts!")
