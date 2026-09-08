import re
from urllib.parse import urlparse
URL=re.compile(r'https?://[^\s<>"\']+')
IP=re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
EMAIL=re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
HASH=re.compile(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b')
def extract(text, urls, attachments):
    domains=[]
    for u in urls:
        try:
            h=urlparse(u).hostname
            if h and h not in domains: domains.append(h)
        except: pass
    for d in re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[A-Za-z]{2,}\b', text or ""):
        if d not in domains: domains.append(d)
    return {"urls":list(dict.fromkeys(urls)),"domains":domains,"ips":list(dict.fromkeys(IP.findall(text or ""))),"emails":list(dict.fromkeys(EMAIL.findall(text or ""))),"hashes":list(dict.fromkeys(HASH.findall(text or "")+[a["sha256"] for a in attachments]))}
