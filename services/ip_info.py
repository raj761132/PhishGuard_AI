import socket
import requests
from urllib.parse import urlparse

def get_ip_info(url):
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return None

        ip = socket.gethostbyname(hostname)

        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if response.status_code != 200:
            return None

        data = response.json()

        # lat,long comes as "lat,long"
        loc = data.get("loc", "0,0").split(",")

        return {
            "ip": ip,
            "country": data.get("country", "Unknown"),
            "region": data.get("region", "Unknown"),
            "city": data.get("city", "Unknown"),
            "org": data.get("org", "Unknown"),
            "latitude": float(loc[0]),
            "longitude": float(loc[1])
        }

    except Exception:
        return None
