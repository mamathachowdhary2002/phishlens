import re
from urllib.parse import urlparse

def domain(value):
    m = re.search(r'[\w.+-]+@([\w.-]+\.[A-Za-z]{2,})', value or "")
    return m.group(1).lower() if m else ""

def header_forensics(email):
    frm = email["from"]; reply = email["reply_to"]; ret = email["return_path"]
    fd, rd, rpd = domain(frm), domain(reply), domain(ret)
    findings=[]; score=0
    if reply and rd and fd and rd != fd:
        score += 25; findings.append({"severity":"HIGH","title":"Reply-To domain mismatch","detail":f"From domain is {fd}, Reply-To is {rd}."})
    if ret and rpd and fd and rpd != fd:
        score += 12; findings.append({"severity":"MEDIUM","title":"Return-Path mismatch","detail":f"From domain is {fd}, Return-Path is {rpd}."})
    if not email["message_id"]:
        score += 3; findings.append({"severity":"LOW","title":"Missing Message-ID","detail":"Message-ID is absent."})
    if not email["received"]:
        score += 5; findings.append({"severity":"LOW","title":"No Received chain","detail":"No Received headers were found."})
    if len(email["received"]) > 10:
        score += 3; findings.append({"severity":"LOW","title":"Long Received chain","detail":f"{len(email['received'])} hops detected."})
    xip = email["headers"].get("X-Originating-IP","")
    received_ips=[]
    for h in email["received"]:
        received_ips += re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', h)
    return {
        "score":score, "sender_domain":fd, "reply_domain":rd, "return_path_domain":rpd,
        "x_originating_ip":xip, "received_ips":list(dict.fromkeys(received_ips)),
        "received_count":len(email["received"]), "findings":findings
    }
