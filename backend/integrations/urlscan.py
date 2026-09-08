import os, requests
def submit(url):
    key=os.getenv("URLSCAN_API_KEY","")
    if not key: return {"enabled":False}
    try:
        r=requests.post("https://urlscan.io/api/v1/scan/",headers={"api-key":key},json={"url":url,"visibility":"private"},timeout=10)
        if r.status_code>=400: return {"enabled":True,"status":"error","error":r.text[:300]}
        d=r.json(); return {"enabled":True,"status":"submitted","uuid":d.get("uuid"),"result":d.get("result")}
    except Exception as e: return {"enabled":True,"status":"error","error":str(e)}
