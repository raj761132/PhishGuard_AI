import re
import tldextract

def extract_features(url):
    features = []

    # Length of URL
    features.append(len(url))

    # HTTPS present
    features.append(1 if url.startswith("https") else 0)

    # Count dots
    features.append(url.count("."))

    # Count special characters
    features.append(len(re.findall(r"[@\-_%]", url)))

    # Subdomain length
    ext = tldextract.extract(url)
    features.append(len(ext.subdomain))

    return features
