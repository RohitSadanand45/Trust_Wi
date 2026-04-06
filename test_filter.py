from wifi_scanner import scan_wifi
from trust_analyzer import analyze_trust

networks = scan_wifi()
result = []

for net in networks:
    ssid = net.get("ssid", "").strip()
    # Skip empty SSIDs
    if not ssid:
        print(f"Skipping empty SSID: {net}")
        continue
        
    status, score, reason = analyze_trust(net)
    result.append({
        "ssid": ssid,
        "security": net.get("security", "Unknown"),
        "status": status
    })

print(f'Networks after filtering: {len(result)}')
for net in result:
    print(f"  - {net['ssid']}: {net['status']}")
