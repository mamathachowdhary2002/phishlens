import os, json
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from dotenv import load_dotenv
load_dotenv()
from engine.email_parser import parse_eml
from engine.header_analyzer import header_forensics
from engine.authentication_analyzer import analyze as auth_analyze
from engine.content_analyzer import analyze as content_analyze
from engine.html_analyzer import analyze as html_analyze
from engine.url_extractor import extract
from engine.url_analyzer import analyze as url_analyze
from engine.domain_analyzer import analyze as domain_analyze
from engine.attachment_analyzer import analyze as attachment_analyze
from engine.ioc_extractor import extract as ioc_extract
from engine.mitre import map_findings
from engine.risk_engine import score
from integrations.virustotal import lookup as vt_lookup
from integrations.urlscan import submit as urlscan_submit
from storage import init, save_case, list_cases
from report import make_pdf

app=Flask(__name__); CORS(app); app.config["MAX_CONTENT_LENGTH"]=10*1024*1024
init()

@app.get("/api/health")
def health(): return jsonify({"status":"healthy","version":"2.0"})

@app.post("/api/analyze")
def analyze():
    f=request.files.get("file")
    if not f: return jsonify({"error":"No file uploaded"}),400
    if not f.filename.lower().endswith(".eml"): return jsonify({"error":"Only .eml files are supported"}),400
    email=parse_eml(f.read())
    headers=header_forensics(email)
    auth=auth_analyze(email["authentication_results"],headers["sender_domain"])
    content=content_analyze(email["plain_body"]+"\n"+email["subject"])
    html=html_analyze(email["html_body"])
    urls_raw=extract(email["plain_body"],email["html_body"])
    urls=[]
    domains={}
    for u in urls_raw:
        x=url_analyze(u,headers["sender_domain"])
        x["domain_intelligence"]=domain_analyze(x["hostname"])
        if os.getenv("ENABLE_VT","false").lower()=="true": x["virustotal"]=vt_lookup(u)
        else: x["virustotal"]={"enabled":False}
        if os.getenv("ENABLE_ACTIVE_URL_SCAN","false").lower()=="true": x["urlscan_submit"]=urlscan_submit(u)
        else: x["urlscan_submit"]={"enabled":False}
        if x["type"]=="ACTION" and x["relation"]=="external":
            x["score"]+=12; x["findings"].append({"severity":"HIGH","title":"External action domain","detail":"Action URL points outside the sender domain."})
        urls.append(x)
        domains[x["hostname"]]=x["domain_intelligence"]
    att=attachment_analyze(email["attachments"])
    iocs=ioc_extract(email["plain_body"]+"\n"+email["html_body"],urls_raw,email["attachments"])
    findings=headers["findings"]+auth["findings"]+content["findings"]+html["findings"]+att["findings"]+[f for u in urls for f in u["findings"]]
    total=headers["score"]+auth["score"]+content["score"]+html["score"]+att["score"]+sum(u["score"] for u in urls)
    risk=score(total,findings)
    summary=f"{risk['label']} email with {len(urls)} URL(s), {len(email['attachments'])} attachment(s), and {len(findings)} investigation finding(s). Authentication results are evidence, not a standalone safety verdict."
    return jsonify({"risk":risk,"summary":summary,"email":{k:email[k] for k in ("from","to","cc","reply_to","return_path","subject","date","message_id")},"headers":headers,"authentication":auth,"content":content,"html":html,"urls":urls,"domains":domains,"attachments":att,"iocs":iocs,"mitre":map_findings(findings,email,urls_raw),"findings":findings})

@app.post("/api/cases")
def cases():
    d=request.get_json(force=True); return jsonify({"id":save_case(d.get("title","Untitled investigation"),d.get("notes",""))})
@app.get("/api/cases")
def get_cases(): return jsonify(list_cases())

@app.post("/api/report")
def report():
    result=request.get_json(force=True); pdf=make_pdf(result)
    return send_file(pdf,mimetype="application/pdf",as_attachment=True,download_name="phishlens-report.pdf")

if __name__=="__main__":
    app.run(host="0.0.0.0",port=5000)
