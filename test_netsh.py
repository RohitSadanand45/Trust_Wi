import subprocess

# Test basic netsh wlan show networks
print("Testing netsh wlan show networks...")
try:
    result = subprocess.run('netsh wlan show networks', shell=True, capture_output=True, text=True, timeout=10)
    print(f"Return code: {result.returncode}")
    if result.returncode == 0:
        print("Success: Networks found")
    else:
        print(f"Error: {result.stderr}")
except Exception as e:
    print(f"Exception: {e}")

# Test connecting to an open network
print("\nTesting connection to open network...")
try:
    result = subprocess.run('netsh wlan connect name="TP-Link_Extender"', shell=True, capture_output=True, text=True, timeout=15)
    print(f"Return code: {result.returncode}")
    if result.returncode == 0:
        print("Success: Connected to open network")
    else:
        print(f"Error: {result.stderr}")
except Exception as e:
    print(f"Exception: {e}")
