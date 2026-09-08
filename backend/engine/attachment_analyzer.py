DANGEROUS={".exe",".dll",".scr",".msi",".bat",".cmd",".ps1",".vbs",".js",".jse",".hta",".lnk",".jar",".iso",".img"}
def analyze(items):
    findings=[]; score=0; out=[]
    for a in items:
        name=a["filename"].lower(); dangerous=any(name.endswith(x) for x in DANGEROUS)
        double=any(name.endswith(x) for x in (".pdf.exe",".doc.exe",".docx.exe",".xls.exe",".xlsx.exe",".jpg.exe",".png.exe"))
        if double:
            score+=35; findings.append({"severity":"CRITICAL","title":"Double-extension attachment","detail":a["filename"]})
        elif dangerous:
            score+=25; findings.append({"severity":"HIGH","title":"Potentially executable attachment","detail":a["filename"]})
        out.append({**a,"dangerous":dangerous,"double_extension":double})
    return {"score":score,"attachments":out,"findings":findings}
