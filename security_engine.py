from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uuid
import requests

app = FastAPI(title="CyberGuard AI Engine", version="5.0.0")

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
    target = request.target_url.rstrip('/')
    if not target.startswith("http"):
        target = "https://" + target

    failed_checks = []
    extracted_data_samples = []
    score = 100

    try:
        # 1. فحص الترويسات الأمنية الأساسية
        response = requests.get(target, timeout=10, verify=True, headers={"User-Agent": "CyberGuard-AI-Scanner/5.0"})
        headers = response.headers

        if 'Strict-Transport-Security' not in headers:
            failed_checks.append("Missing HSTS Header (Strict-Transport-Security)")
            score -= 15

        if 'Content-Security-Policy' not in headers:
            failed_checks.append("Missing Content-Security-Policy (CSP)")
            score -= 20

        if 'X-Frame-Options' not in headers:
            failed_checks.append("Missing X-Frame-Options Header (Clickjacking Risk)")
            score -= 15

        if 'Server' in headers:
            failed_checks.append(f"Server Information Disclosure: Server: {headers['Server']}")
            score -= 10

        # 2. فحص الملفات الحساسة
        sensitive_paths = ["/.env", "/config.json", "/backup.sql"]
        exposed_paths = []
        for path in sensitive_paths:
            try:
                test_url = target + path
                res = requests.get(test_url, timeout=3, verify=True)
                if res.status_code == 200 and len(res.text) > 10:
                    exposed_paths.append(path)
            except:
                pass

        if exposed_paths:
            failed_checks.append(f"Critical: Sensitive files or paths exposed: {', '.join(exposed_paths)}")
            score -= 30
        else:
            failed_checks.append("Pass: No critical sensitive configuration files (.env, backup.sql) publicly exposed.")

        # 3. الفحص المتقدم ونقاط الـ API مع التقاط عينات البيانات المستخرجة (PoC)
        api_endpoints = ["/api/v1/users", "/api/v1/admin", "/api/v1/config"]
        unprotected_apis = []
        for endpoint in api_endpoints:
            try:
                api_url = target + endpoint
                api_res = requests.get(api_url, timeout=4, verify=True)
                # إذا استجابت الـ API بنجاح وأرجعت بيانات حقيقية (JSON)
                if api_res.status_code == 200 and 'application/json' in api_res.headers.get('Content-Type', ''):
                    unprotected_apis.append(endpoint)
                    # حفظ مقتطف مختصر من البيانات المستخرجة كدليل فحص
                    snippet = api_res.text[:120].replace('\n', ' ')
                    extracted_data_samples.append(f"Data Extracted from {endpoint}: {snippet}...")
            except:
                pass

        if unprotected_apis:
            failed_checks.append(f"Vulnerability: Unprotected API Endpoints exposing data: {', '.join(unprotected_apis)}")
            score -= 25
        else:
            failed_checks.append("Pass: Standard API endpoints are properly guarded.")

        if score < 10:
            score = 10

    except requests.exceptions.RequestException as e:
        failed_checks.append(f"Connection Error / Target Unreachable: {str(e)}")
        score = 0

    scan_id = str(uuid.uuid4())
    scan_database[scan_id] = {
        "status": "completed",
        "target_url": target,
        "scan_mode": request.scan_mode,
        "security_score": score,
        "findings_count": len(failed_checks) + len(extracted_data_samples),
        "failed_checks": failed_checks,
        "extracted_data_samples": extracted_data_samples
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
    pdf_filename = f"CyberGuard_PoC_Report_{scan_id[:8]}.pdf"
    
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        
        c = canvas.Canvas(pdf_filename, pagesize=letter)
        width, height = letter
        
        # رأسية التقرير
        c.setFont("Helvetica-Bold", 16)
        c.drawString(40, height - 35, "CyberGuard AI - Security Audit & PoC Data Report")
        
        c.setFont("Helvetica", 10)
        c.drawString(40, height - 60, f"Target URL: {scan_info['target_url']}")
        c.drawString(40, height - 78, f"Scan Mode: {scan_info['scan_mode']}")
        c.drawString(40, height - 96, f"Security Score: {scan_info['security_score']} / 100")
        c.drawString(40, height - 114, f"Total Findings: {scan_info['findings_count']}")
        
        # النتائج الشاملة
        c.setFont("Helvetica-Bold", 12)
        c.drawString(40, height - 145, "Audit & Vulnerability Results:")
        
        c.setFont("Helvetica", 9)
        y_pos = height - 165
        for check in scan_info['failed_checks']:
            if y_pos < 100:
                c.showPage()
                y_pos = height - 40
            c.drawString(55, y_pos, f"- {check}")
            y_pos -= 18

        # قسم أدلة استخراج البيانات (PoC Samples)
        if scan_info.get('extracted_data_samples'):
            if y_pos < 120:
                c.showPage()
                y_pos = height - 40
            y_pos -= 10
            c.setFont("Helvetica-Bold", 12)
            c.drawString(40, y_pos, "Proof of Concept (PoC) - Extracted Data Samples:")
            y_pos -= 20
            c.setFont("Helvetica", 8)
            for sample in scan_info['extracted_data_samples']:
                if y_pos < 60:
                    c.showPage()
                    y_pos = height - 40
                c.drawString(55, y_pos, f"> {sample}")
                y_pos -= 16
            
        # بصمة المطور
        c.setFont("Helvetica-Oblique", 8)
        c.drawString(40, 25, "Developed by khmm - CyberGuard AI Systems")
        
        c.save()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating PDF: {str(e)}")
    
    return FileResponse(pdf_filename, media_type='application/pdf', filename=pdf_filename)
