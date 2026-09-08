import base64, os, requests
def lookup(url):
    key=os.getenv("VT_API_KEY","")
    if not key: return {"enabled":False}
    ident=base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        r=requests.get(f"https://www.virustotal.com/api/v3/urls/{ident}",headers={"x-apikey":key},timeout=8)
        if r.status_code==404: return {"enabled":True,"status":"not_found"}
        if r.status_code==429: return {"enabled":True,"status":"rate_limited"}
        r.raise_for_status(); d=r.json().get("data",{}); a=d.get("attributes",{})
        return {"enabled":True,"status":"found","malicious":a.get("last_analysis_stats",{}).get("malicious",0),"suspicious":a.get("last_analysis_stats",{}).get("suspicious",0),"harmless":a.get("last_analysis_stats",{}).get("harmless",0),"undetected":a.get("last_analysis_stats",{}).get("undetected",0),"reputation":a.get("reputation"),"last_analysis_date":a.get("last_analysis_date"),"id":d.get("id")}
    except Exception as e: return {"enabled":True,"status":"error","error":str(e)}
