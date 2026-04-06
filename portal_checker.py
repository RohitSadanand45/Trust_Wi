import requests

def check_portal():
    print("\n🌐 Checking for captive portal...")

    try:
        response = requests.get("http://example.com", timeout=5)

        if response.url != "http://example.com/":
            print("⚠️ Redirect detected (Possible captive portal)")
            return analyze_url(response.url)

        else:
            print("✅ No captive portal detected")
            return "SAFE"

    except:
        print("⚠️ Network issue / captive portal suspected")
        return "UNKNOWN"


def analyze_url(url):
    print(f"🔍 Analyzing URL: {url}")

    if url.startswith("https"):
        return "SAFE"
    else:
        return "RISKY"