from bs4 import BeautifulSoup
from urllib.parse import urlparse
def analyze(html):
    soup=BeautifulSoup(html or "","html.parser"); findings=[]; score=0; links=[]
    for a in soup.find_all("a",href=True):
        text=a.get_text(" ",strip=True)
        links.append({"text":text[:180],"href":a.get("href","")})
    forms=len(soup.find_all("form")); iframes=len(soup.find_all("iframe")); scripts=len(soup.find_all("script"))
    if forms: score+=15; findings.append({"severity":"MEDIUM","title":"HTML form detected","detail":f"{forms} form(s) found."})
    if iframes: score+=15; findings.append({"severity":"HIGH","title":"Iframe detected","detail":f"{iframes} iframe(s) found."})
    if scripts: score+=8; findings.append({"severity":"LOW","title":"JavaScript detected","detail":f"{scripts} script(s) found."})
    for x in links:
        try:
            u=urlparse(x["href"]); visible=urlparse(x["text"]).hostname
            if visible and u.hostname and visible.lower()!=u.hostname.lower():
                score+=20; findings.append({"severity":"HIGH","title":"Visible link/domain mismatch","detail":f"Text suggests {visible}, destination is {u.hostname}."})
        except Exception: pass
    return {"score":score,"links":links,"forms":forms,"iframes":iframes,"scripts":scripts,"findings":findings}
