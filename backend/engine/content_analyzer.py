GROUPS={
"credential":["password","verify your account","login","sign in","credential","otp","one-time password"],
"financial":["invoice","payment","bank","refund","transaction","card","billing"],
"urgency":["urgent","immediately","act now","within 24 hours","suspended","final warning"],
"reward":["gift","reward","prize","winner","bonus","free"],
"threat":["locked","terminated","legal action","security alert"]
}
def analyze(text):
    t=(text or "").lower(); findings=[]; score=0; matches={}
    for group,words in GROUPS.items():
        hit=[w for w in words if w in t]
        if hit:
            matches[group]=hit
            add={"credential":18,"financial":12,"urgency":10,"reward":6,"threat":10}[group]
            sev="HIGH" if group=="credential" else "MEDIUM"
            score+=add
            findings.append({"severity":sev,"title":f"{group.title()} language detected","detail":", ".join(hit)})
    if t.count("!")>=10:
        score+=3; findings.append({"severity":"LOW","title":"Excessive punctuation","detail":"Message contains many exclamation marks."})
    return {"score":score,"matches":matches,"findings":findings}
