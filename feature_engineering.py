import re
import whois
import pandas as pd
from urllib.parse import urlparse

# ✅ Check if URL contains an IP address
def has_ip_address(url):
    return int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)))

# ✅ Count subdomains
def count_subdomains(url):
    return urlparse(url).netloc.count('.')

# ✅ Get domain length
def domain_length(url):
    return len(urlparse(url).netloc)

# ✅ Get domain age (WHOIS lookup)
def domain_age(url):
    try:
        domain_info = whois.whois(urlparse(url).netloc)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return (pd.Timestamp.now() - pd.Timestamp(creation_date)).days
    except:
        return -1  # WHOIS data unavailable

# ✅ Extract features for a dataset
def extract_features(df):
    df['has_ip'] = df['url'].apply(has_ip_address)
    df['subdomains'] = df['url'].apply(count_subdomains)
    df['domain_length'] = df['url'].apply(domain_length)
    df['domain_age'] = df['url'].apply(domain_age)
    return df
