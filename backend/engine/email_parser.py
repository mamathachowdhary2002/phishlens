from email import policy
from email.parser import BytesParser
from hashlib import sha256

def parse_eml(data: bytes):
    msg = BytesParser(policy=policy.default).parsebytes(data)
    headers = {k: str(v) for k, v in msg.items()}
    plain, html, attachments = [], [], []
    for part in msg.walk():
        ctype = part.get_content_type()
        disp = part.get_content_disposition()
        if disp == "attachment" or part.get_filename():
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": part.get_filename() or "unnamed",
                "mime": ctype,
                "size": len(payload),
                "sha256": sha256(payload).hexdigest()
            })
        elif ctype == "text/plain":
            try: plain.append(part.get_content())
            except Exception: pass
        elif ctype == "text/html":
            try: html.append(part.get_content())
            except Exception: pass
    return {
        "from": headers.get("From",""), "to": headers.get("To",""),
        "cc": headers.get("Cc",""), "bcc": headers.get("Bcc",""),
        "reply_to": headers.get("Reply-To",""), "return_path": headers.get("Return-Path",""),
        "subject": headers.get("Subject",""), "date": headers.get("Date",""),
        "message_id": headers.get("Message-ID",""),
        "authentication_results": headers.get("Authentication-Results",""),
        "received": msg.get_all("Received", []),
        "headers": headers,
        "plain_body": "\n".join(plain), "html_body": "\n".join(html),
        "attachments": attachments
    }
