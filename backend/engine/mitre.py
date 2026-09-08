def map_findings(findings, email, urls):
    text=(email.get("plain_body","")+" "+email.get("subject","")).lower()
    maps=[]
    if urls: maps.append({"id":"T1566.002","name":"Phishing: Spearphishing Link","reason":"Email contains one or more URLs."})
    if email.get("attachments"): maps.append({"id":"T1566.001","name":"Phishing: Spearphishing Attachment","reason":"Email contains attachments."})
    if any(x in text for x in ("password","login","credential","verify your account")):
        maps.append({"id":"T1056.002","name":"Input Capture: GUI Input Capture","reason":"Credential/input language detected."})
    return maps
