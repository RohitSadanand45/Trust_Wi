from trust_analyzer import analyze_trust

# Test with different network types
test_networks = [
    {"ssid": "Free_Public_WiFi", "security": "Open"},
    {"ssid": "FastFood_Guest", "security": "Open"},
    {"ssid": "Protected_Home", "security": "WPA2-Personal"},
    {"ssid": "Corporate_Network", "security": "WPA3-Personal"},
    {"ssid": "Weak_Security", "security": "WEP"},
]

print("Testing trust_analyzer with different network types:\n")
for net in test_networks:
    status, score, reason = analyze_trust(net)
    print(f"Network: {net['ssid']}")
    print(f"  Security: {net['security']}")
    print(f"  Status: {status} (Risk Score: {score}/100)")
    print(f"  Reason: {reason}\n")
