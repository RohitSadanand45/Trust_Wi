from wifi_scanner import scan_wifi
from trust_analyzer import analyze_trust

networks = scan_wifi()
print(f'Networks found: {len(networks)}')
for net in networks:
    status, score, reason = analyze_trust(net)
    print(f"  - {net['ssid']}: {net['security']} ({status})")
