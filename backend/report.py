from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO
def make_pdf(result):
    b=BytesIO(); doc=SimpleDocTemplate(b,pagesize=A4); s=getSampleStyleSheet(); story=[]
    story.append(Paragraph("PhishLens Security Investigation Report",s["Title"]))
    story.append(Spacer(1,12))
    r=result["risk"]; story.append(Paragraph(f"Risk: {r['label']} — {r['score']}/100",s["Heading2"]))
    e=result["email"]; story.append(Paragraph(f"Subject: {e.get('subject','')}",s["BodyText"]))
    story.append(Paragraph(f"From: {e.get('from','')}",s["BodyText"]))
    story.append(Spacer(1,10))
    story.append(Paragraph("Findings",s["Heading2"]))
    for f in result["findings"]:
        story.append(Paragraph(f"[{f['severity']}] {f['title']} — {f['detail']}",s["BodyText"]))
    story.append(Spacer(1,10)); story.append(Paragraph("URLs",s["Heading2"]))
    for u in result["urls"]:
        story.append(Paragraph(f"{u['type']}: {u['url']} — score {u['score']}",s["BodyText"]))
    doc.build(story); b.seek(0); return b
