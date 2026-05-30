from fastapi import FastAPI
from pydantic import BaseModel
from twilio.rest import Client
import re

app = FastAPI()

TWILIO_ACCOUNT_SID = "AC23db384539e45271bf0d29459e3156ce"
TWILIO_AUTH_TOKEN  = "e92a658e3c3249dcac3ad2cfb9b062b8"
TWILIO_WHATSAPP_NUMBER = "whatsapp:+14155238886"

client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

class ScanRequest(BaseModel):
    url: str
    source_app: str = "unknown"
    unknown_sender: bool = False

class GuardianAlertRequest(BaseModel):
    blocked_url: str
    threat_score: int
    guardian_phone: str

@app.get("/")
def root():
    return {"status": "ShieldNetX backend running"}

@app.post("/scan")
def scan_url(req: ScanRequest):
    score = 0
    reason = "Clean link"
    url = req.url.lower()

bad_keywords = ["login", "verify", "account", "secure", "update",
                "banking", "free", "winner", "click", "confirm", "prize"]
keyword_hits = 0
for keyword in bad_keywords:
    if keyword in url:
        score += 15
        keyword_hits += 1
        reason = f"Suspicious keyword: {keyword}"
if keyword_hits > 1:
    score += 20

    if re.search(r'https?://\d+\.\d+\.\d+\.\d+', req.url):
        score += 30
        reason = "IP address URL — no domain"

    if req.unknown_sender:
        score += 10

    suspicious_tlds = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".click"]
    for tld in suspicious_tlds:
        if tld in url:
            score += 20
            reason = f"Suspicious domain extension: {tld}"
            break

    if len(req.url) > 100:
        score += 10

    shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "short.io"]
    for s in shorteners:
        if s in url:
            score += 15
            reason = "URL shortener detected"
            break

    score = min(score, 100)
    return {"threat_score": score, "reason": reason, "signals": {"url": req.url}}

@app.post("/guardian-alert")
def guardian_alert(req: GuardianAlertRequest):
    try:
        phone = req.guardian_phone.strip()
        if not phone.startswith("+"):
            phone = "+" + phone

        message = (
            f"🚨 ShieldNetX Alert!\n"
            f"A dangerous link was blocked on your contact's device.\n"
            f"Threat Score: {req.threat_score}/100\n"
            f"Blocked URL: {req.blocked_url}\n"
            f"They are safe. ShieldNetX intercepted the attack."
        )

        client.messages.create(
            body=message,
            from_=TWILIO_WHATSAPP_NUMBER,
            to=f"whatsapp:{phone}"
        )
        return {"status": "alert sent"}

    except Exception as e:
        return {"status": "error", "detail": str(e)}
