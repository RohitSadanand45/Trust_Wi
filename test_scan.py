import requests
response = requests.get('http://127.0.0.1:5000/scan')
data = response.json()
print(f'Networks returned: {len(data)}')
for net in data:
    print(f"  - {net['ssid']}: {net['status']}")
