import subprocess

command = "netsh wlan show networks mode=Bssid"
result = subprocess.check_output(command, shell=True).decode()

print("Raw output:")
print(result)
print("\n" + "="*50 + "\n")
print("Formatted lines:")
for i, line in enumerate(result.split("\n")):
    if line.strip():
        print(f"{i}: {repr(line)}")
