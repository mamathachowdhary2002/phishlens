import socket, ipaddress
import dns.resolver
def analyze(host):
    if not host: return {}
    ips=[]
    try:
        for r in dns.resolver.resolve(host,"A",lifetime=3): ips.append(str(r))
    except Exception: pass
    try:
        for r in dns.resolver.resolve(host,"AAAA",lifetime=3): ips.append(str(r))
    except Exception: pass
    def records(t):
        try: return [str(x) for x in dns.resolver.resolve(host,t,lifetime=3)]
        except Exception: return []
    return {"hostname":host,"ips":list(dict.fromkeys(ips)),"a":ips,"mx":records("MX"),"ns":records("NS"),"txt":records("TXT")}
