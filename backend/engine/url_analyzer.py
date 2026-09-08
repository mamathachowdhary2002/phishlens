import base64, ipaddress, re
from urllib.parse import urlparse, parse_qs, quote

ACTION=("login","signin","verify","unlock","secure","password","reset","payment","billing","confirm","account","claim","activate","download")
TRACK=("utm_","unsubscribe","preference","tracking","click","/e/c/","/e/o/")
RESOURCE=(".css",".js",".png",".jpg",".jpeg",".gif",".svg",".ico",".woff",".woff2",".webp",".mp4",".mp3",".pdf")
def vt_link(url):
    raw=base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return f"https://www.virustotal.com/gui/url/{raw}/detection"
def analyze(url, sender_domain=""):
    p=urlparse(url); host=(p.hostname or "").lower(); path=(p.path or "").lower()
    typ="NAVIGATION"
    if path.endswith(RESOURCE): typ="RESOURCE"
    elif any(x in (path+"?"+p.query) for x in TRACK): typ="TRACKING"
    elif any(x in path for x in ACTION): typ="ACTION"
    score=0; findings=[]
    try:
        ip=ipaddress.ip_address(host)
        score+=20; findings.append({"severity":"HIGH","title":"URL uses an IP address","detail":host})
    except: ip=None
    if "xn--" in host:
        score+=15; findings.append({"severity":"HIGH","title":"Punycode hostname","detail":"Hostname contains xn-- encoding."})
    if "@" in p.netloc:
        score+=15; findings.append({"severity":"HIGH","title":"Userinfo in URL","detail":"URL contains @ before the hostname."})
    if host.count(".")>=4:
        score+=8; findings.append({"severity":"MEDIUM","title":"Deep subdomain chain","detail":f"{host.count('.')} dots in hostname."})
    if any(x in path for x in ACTION):
        score+=8; findings.append({"severity":"MEDIUM","title":"Sensitive action path","detail":path})
    if len(url)>250: score+=3; findings.append({"severity":"LOW","title":"Long URL","detail":f"{len(url)} characters."})
    qs=parse_qs(p.query)
    if len(qs)>=8: score+=3; findings.append({"severity":"LOW","title":"Many query parameters","detail":str(len(qs))})
    nested=[v for vals in qs.values() for v in vals if v.startswith(("http://","https://"))]
    if nested:
        score+=8; findings.append({"severity":"MEDIUM","title":"Nested URL parameter","detail":"A query parameter contains another URL."})
    if p.scheme=="http":
        findings.append({"severity":"INFO","title":"HTTP transport","detail":"HTTP is informational; it is not treated as malicious by itself."})
    relation="same-domain" if sender_domain and host==sender_domain else ("external" if sender_domain and host else "unknown")
    return {"url":url,"type":typ,"scheme":p.scheme,"hostname":host,"domain":host,"path":p.path,"query":p.query,"query_params":len(qs),"score":score,"findings":findings,"relation":relation,"virustotal_url":vt_link(url),"urlscan_url":"https://urlscan.io/search/#page.url:"+quote(url,safe="")}
