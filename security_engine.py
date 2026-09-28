from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uuid
import requests
from bs4 import BeautifulSoup

app = FastAPI(title="CyberGuard AI Engine", version="7.0.0")

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
        response = requests.get(target, timeout=10, verify=True, headers={"User-Agent": "CyberGuard-AI-Scanner/7.0"})
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
                test_url = target.split('/Admin/')[0] + path if '/Admin/' in target else target + path
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

        # 3. الفحص المتقدم وتفريغ محتوى الجداول الحقيقية (HTML Table Parsing & Data Extraction)
        base_domain = target.split('/Admin/')[0] if '/Admin/' in target else target
        ibn_endpoints = [
            "/Admin/IbnAlHaithamReports",
            "/api/v1/students",
            "/api/reports/data",
            "/Admin/GetReportsData",
            "/Home/GetStudentData"
        ]
        
        unprotected_apis = []
        for endpoint in ibn_endpoints:
            try:
                api_url = base_domain + endpoint if endpoint.startswith('/') else base_domain + '/' + endpoint
                api_res = requests.get(api_url, timeout=6, verify=True, headers={"User-Agent": "CyberGuard-DataExtractor/7.0"})
                
                if api_res.status_code == 200:
                    body_text = api_res.text
                    content_type = api_res.headers.get('Content-Type', '')
                    
                    # استخدام BeautifulSoup لتحليل الصفحة واستخراج البيانات الفعلية من الجداول أو النصوص التنظيمية
                    soup = BeautifulSoup(body_text, 'html.parser')
                    
                    # البحث عن أي جداول بيانات (Tables) داخل الصفحة
                    tables = soup.find_all('table')
                    if tables:
                        unprotected_apis.append(endpoint)
                        for t_idx, table in enumerate(tables):
                            rows = table.find_all('tr')
                            row_count = len(rows)
                            # استخراج عينة من صفوف الجدول (مثل اسماء الأعمدة أو أول صفين من البيانات)
                            sample_rows = []
                            for r in rows[:3]:  # أول 3 صفوف كعينة حقيقية
                                cols = [c.get_text(strip=True) for c in r.find_all(['th', 'td']) if c.get_text(strip=True)]
                                if cols:
                                    sample_rows.append(" | ".join(cols))
                            
                            snippet = f"Table [{t_idx+1}] Rows: {row_count} | Sample: " + " -- ".join(sample_rows)
                            extracted_data_samples.append(f"Table Data from {endpoint}: {snippet[:180]}...")
                    
                    elif len(body_text) > 200 and ('json' in content_type or 'student' in body_text.lower() or 'report' in body_text.lower()):
                        unprotected_apis.append(endpoint)
                        # استخراج النصوص الصافية بدون أكواد الـ HTML
                        clean_text = soup.get_text(separator=' ', strip=True)
                        extracted_data_samples.append(f"Text Data from {endpoint}: {clean_text[:140]}...")
            except:
                pass

        if unprotected_apis:
            failed_checks.append(f"Vulnerability: Endpoints exposing raw data / tables without auth: {', '.join(unprotected_apis)}")
            score -= 35
        else:
            failed_checks.append("Pass: Report and table endpoints are strictly guarded.")

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
    pdf_filename = f"CyberGuard_Extracted_Data_{scan_id[:8]}.pdf"
    
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        
        c = canvas.Canvas(pdf_filename, pagesize=letter)
        width, height = letter
        
        # رأسية التقرير
        c.setFont("Helvetica-Bold", 15)
        c.drawString(35, height - 35, "CyberGuard AI - Real Table & Data Extraction Report")
        
        c.setFont("Helvetica", 9)
        c.drawString(35, height - 58, f"Target URL: {scan_info['target_url']}")
        c.drawString(35, height - 74, f"Scan Mode: {scan_info['scan_mode']}")
        c.drawString(35, height - 90, f"Security Score: {scan_info['security_score']} / 100")
        c.drawString(35, height - 106, f"Total Findings & Extractions: {scan_info['findings_count']}")
        
        # النتائج الشاملة
        c.setFont("Helvetica-Bold", 11)
        c.drawString(35, height - 135, "Vulnerability Assessment Results:")
        
        c.setFont("Helvetica", 8)
        y_pos = height - 152
        for check in scan_info['failed_checks']:
            if y_pos < 90:
                c.showPage()
                y_pos = height - 40
            c.drawString(45, y_pos, f"- {check}")
            y_pos -= 16

        # قسم تفريغ بيانات الجداول الحقيقية (Extracted Table Data)
        if scan_info.get('extracted_data_samples'):
            if y_pos < 110:
                c.showPage()
                y_pos = height - 40
            y_pos -= 8
            c.setFont("Helvetica-Bold", 11)
            c.drawString(35, y_pos, "Extracted Table Records & Student Data Samples:")
            y_pos -= 18
            c.setFont("Helvetica", 7)
            for sample in scan_info['extracted_data_samples']:
                if y_pos < 55:
                    c.showPage()
                    y_pos = height - 40
                c.drawString(45, y_pos, f">> {sample}")
                y_pos -= 15
            
        # بصمة المطور
        c.setFont("Helvetica-Oblique", 8)
        c.drawString(35, 20, "Developed by khmm - CyberGuard AI Systems")
        
        c.save()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating PDF: {str(e)}")
    
    return FileResponse(pdf_filename, media_type='application/pdf', filename=pdf_filename)
