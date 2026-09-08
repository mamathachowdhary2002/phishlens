import re
from urllib.parse import unquote
PAT=re.compile(r'https?://[^\s<>"\']+')
def extract(*texts):
    out=[]
    for text in texts:
        for u in PAT.findall(text or ""):
            u=unquote(u).rstrip(".,);]}>")
            if u not in out: out.append(u)
    return out
