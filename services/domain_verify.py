import socket
import whois
import datetime

def verify_domain(domain):
    try:
        socket.gethostbyname(domain)

        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return {"valid": False}

        age_days = (datetime.datetime.now() - creation_date).days

        if age_days < 30:
            return {"valid": False}

        return {
            "valid": True,
            "age_days": age_days
        }
    except:
        return {"valid": False}
