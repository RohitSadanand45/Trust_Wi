import requests

# First scan to populate networks_cache
print("Scanning networks...")
scan_response = requests.get('http://127.0.0.1:5000/scan')
networks = scan_response.json()
print(f"Found {len(networks)} networks")
for i, net in enumerate(networks):
    print(f"  {i}: {net['ssid']} ({net['status']})")

# Test connecting to the current encrypted network
print("\nTesting connection to encrypted network without password...")
try:
    response = requests.post('http://127.0.0.1:5000/connect/0')  # Index 0 is the current network
    print(f"Status: {response.status_code}")
    data = response.json()
    print(f"Response: {data}")
except Exception as e:
    print(f"Error: {e}")

print("\nTesting connection to encrypted network with password...")
try:
    response = requests.post('http://127.0.0.1:5000/connect/0', 
                           json={"password": "testpassword123"})
    print(f"Status: {response.status_code}")
    data = response.json()
    print(f"Response: {data}")
except Exception as e:
    print(f"Error: {e}")
