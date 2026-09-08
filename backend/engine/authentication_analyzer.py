import re
def analyze(auth, from_domain):
    a=(auth or "").lower()
    out={"spf":"unknown","dkim":"unknown","dmarc":"unknown","alignment":[]}
    findings=[]; score=0
    for name in ("spf","dkim","dmarc"):
        m=re.search(rf'\b{name}\s*=\s*([a-z]+)',a)
        if m: out[name]=m.group(1)
    if out["spf"]=="fail":
        score+=20; findings.append({"severity":"HIGH","title":"SPF failed","detail":"Sender authorization did not pass."})
    elif out["spf"] in ("softfail","neutral"):
        score+=8; findings.append({"severity":"MEDIUM","title":"SPF not strong","detail":f"SPF result: {out['spf']}."})
    if out["dkim"]=="fail":
        score+=20; findings.append({"severity":"HIGH","title":"DKIM failed","detail":"DKIM verification failed."})
    if out["dmarc"]=="fail":
        score+=25; findings.append({"severity":"HIGH","title":"DMARC failed","detail":"DMARC verification failed."})
    if all(out[x]=="unknown" for x in out):
        score+=5; findings.append({"severity":"MEDIUM","title":"Authentication unavailable","detail":"No usable SPF/DKIM/DMARC result was found."})
    out["passes"]=sum(out[x]=="pass" for x in ("spf","dkim","dmarc"))
    # Passing auth is evidence, not a safety verdict.
    return {"score":score,"results":out,"findings":findings}
