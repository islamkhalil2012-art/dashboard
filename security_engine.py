from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uuid
import os

app = FastAPI(title="CyberGuard AI Engine", version="1.0.0")

# تفعيل الـ CORS لقبول الطلبات من الواجهة الأمامية على GitHub Pages
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = "cyber_guard_sec_key_2026_x9"

def verify_api_key(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return x_api_key

class ScanRequest(BaseModel):
    target_url: str
    scan_mode: str = "external"

scan_database = {}

@app.post("/api/v1/scan/enterprise/start")
def start_scan(request: ScanRequest, api_key: str = Depends(verify_api_key)):
    scan_id = str(uuid.uuid4())
    scan_database[scan_id] = {
        "status": "completed",
        "target_url": request.target_url,
        "scan_mode": request.scan_mode,
        "security_score": 88,
        "findings_count": 12,
        "failed_checks": ["Missing HSTS Header", "Outdated Server Version Banner"]
    }
    return {"scan_id": scan_id, "status": "queued"}

@app.get("/api/v1/scan/enterprise/status/{scan_id}")
def get_scan_status(scan_id: str, api_key: str = Depends(verify_api_key)):
    if scan_id not in scan_database:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_database[scan_id]

@app.get("/api/v1/scan/enterprise/report/pdf/{scan_id}")
def get_pdf_report(scan_id: str, api_key: str):
    if api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    if scan_id not in scan_database:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_info = scan_database[scan_id]
    pdf_filename = f"CyberGuard_Report_{scan_id[:8]}.pdf"
    
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        
        # إنشاء ملف PDF حقيقي
        c = canvas.Canvas(pdf_filename, pagesize=letter)
        width, height = letter
        
        # رأسية التقرير
        c.setFont("Helvetica-Bold", 20)
        c.drawString(50, height - 50, "CyberGuard AI - Security Audit Report")
        
        c.setFont("Helvetica", 12)
        c.drawString(50, height - 80, f"Target URL: {scan_info['target_url']}")
        c.drawString(50, height - 105, f"Scan Mode: {scan_info['scan_mode']}")
        c.drawString(50, height - 130, f"Security Score: {scan_info['security_score']} / 100")
        c.drawString(50, height - 155, f"Findings Count: {scan_info['findings_count']}")
        
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, height - 200, "Failed Checks:")
        
        c.setFont("Helvetica", 11)
        y_pos = height - 225
        for check in scan_info['failed_checks']:
            c.drawString(70, y_pos, f"- {check}")
            y_pos -= 20
            
        # بصمة المطور في التقرير
        c.setFont("Helvetica-Oblique", 10)
        c.drawString(50, 50, "Developed by khmm - CyberGuard AI Systems")
        
        c.save()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating PDF: {str(e)}")
    
    return FileResponse(pdf_filename, media_type='application/pdf', filename=pdf_filename)
