def score(total, findings):
    total=min(100,max(0,total))
    sev={x.get("severity") for x in findings}
    if "CRITICAL" in sev or total>=90: label="CRITICAL"
    elif total>=70 or sum(x=="HIGH" for x in sev)>=2: label="HIGH"
    elif total>=40: label="SUSPICIOUS"
    elif total>=20: label="GUARDED"
    else: label="LOW"
    return {"score":total,"label":label}
