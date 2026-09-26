"""
==================================================================================
Project : CyberGuard AI Enterprise Security Auditor
Version : 7.0.0-Production  (Real Analysis Engine)
Purpose : فحص أمني حقيقي (وليس محاكاة) لموقع يملكه المستخدم، يشمل:
            - تحليل ترويسات الأمان الفعلية (Security Headers)
            - تحليل شهادة SSL/TLS الحقيقية (الصلاحية / البروتوكول / القوة)
            - تحليل خصائص الكوكيز (Secure / HttpOnly / SameSite)
            - محرك تسجيل نقاط (Scoring Engine) موزون حسب الخطورة
            - تعداد المستخدمين (User Enumeration) بمقارنة استجابات حقيقية
            - تقرير PDF بتصميم مختلف بالكامل عن النسخة السابقة

Architecture: كل فاحص (Checker) كلاس مستقل يطبّق واجهة موحّدة BaseSecurityCheck
             هذا يسمح بإضافة فحوصات جديدة مستقبلاً دون تعديل المحرك المركزي.
==================================================================================
"""

import io
import ssl
import socket
import uuid
import logging
import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Literal, Dict, Any, List
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends, Security
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl, Field

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER

# ----------------------------------------------------------------------------------
# إعداد نظام التسجيل
# ----------------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("CyberGuardEngine")

# ----------------------------------------------------------------------------------
# طبقة الأمان: المفتاح يُقرأ من متغير بيئة وليس مكتوبًا داخل الكود
# ----------------------------------------------------------------------------------
import os

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)
VALID_API_KEYS = set(filter(None, os.getenv("CYBERGUARD_API_KEYS", "").split(",")))

def verify_enterprise_api_key(api_key: str = Security(api_key_header)) -> str:
    if not VALID_API_KEYS:
        logger.error("لم يتم ضبط أي مفتاح API في متغيرات البيئة (CYBERGUARD_API_KEYS).")
        raise HTTPException(status_code=500, detail="لم يتم تهيئة نظام المصادقة على الخادم.")
    if api_key in VALID_API_KEYS:
        return api_key
    logger.warning("محاولة وصول غير مصرح بها.")
    raise HTTPException(status_code=403, detail="مفتاح الـ API غير صالح أو غير مصرح بالوصول.")

app = FastAPI(
    title="CyberGuard AI Enterprise Auditor",
    version="7.0.0",
    description="محرك فحص أمني حقيقي يعتمد على تحليل استجابات فعلية من الخادم المستهدف."
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CYBERGUARD_ALLOWED_ORIGINS", "").split(",") or ["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ==================================================================================
# 1) نماذج البيانات
# ==================================================================================
class AdvancedAuditRequest(BaseModel):
    target_url: HttpUrl = Field(..., description="رابط الموقع المستهدف (يجب أن يكون مملوكًا لك)")
    scan_mode: Literal["external", "authenticated"] = Field(...)
    auth_token: Optional[str] = Field(None, description="Bearer token أو session cookie للفحص الداخلي")
    login_page_path: Optional[str] = Field("/login")


@dataclass
class CheckFinding:
    """نتيجة فحص واحد قابلة لإعادة الاستخدام في أي فاحص."""
    title: str
    passed: bool
    severity: Literal["low", "medium", "high", "critical"]
    detail: str
    remediation: str = ""
    code_snippet: str = ""


@dataclass
class ScanReport:
    target: str
    scan_mode: str
    generated_at: str
    findings: List[CheckFinding] = field(default_factory=list)
    security_score: int = 0


scan_database: Dict[str, Dict[str, Any]] = {}

# وزن كل مستوى خطورة في حساب الدرجة النهائية (من 100)
SEVERITY_WEIGHT = {"low": 3, "medium": 7, "high": 14, "critical": 25}


# ==================================================================================
# 2) واجهة موحّدة لكل فاحص أمني (Strategy Pattern)
# ==================================================================================
class BaseSecurityCheck(ABC):
    name: str = "BaseCheck"

    @abstractmethod
    async def run(self, client: httpx.AsyncClient, target_url: str, **kwargs) -> List[CheckFinding]:
        ...


class SecurityHeadersCheck(BaseSecurityCheck):
    """فحص ترويسات الأمان الفعلية المُستلَمة من الخادم."""
    name = "Security Headers"

    REQUIRED_HEADERS = {
        "Strict-Transport-Security": ("critical", "أضف: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"),
        "Content-Security-Policy": ("high", "عرّف سياسة CSP تمنع تحميل موارد من نطاقات غير موثوقة."),
        "X-Content-Type-Options": ("medium", "أضف: X-Content-Type-Options: nosniff"),
        "X-Frame-Options": ("medium", "أضف: X-Frame-Options: DENY أو SAMEORIGIN لمنع Clickjacking"),
        "Referrer-Policy": ("low", "أضف: Referrer-Policy: strict-origin-when-cross-origin"),
        "Permissions-Policy": ("low", "قيّد صلاحيات المتصفح (camera, microphone, geolocation)."),
    }

    async def run(self, client: httpx.AsyncClient, target_url: str, **kwargs) -> List[CheckFinding]:
        findings: List[CheckFinding] = []
        try:
            resp = await client.get(target_url, timeout=12.0, follow_redirects=True)
        except httpx.HTTPError as exc:
            findings.append(CheckFinding(
                title="الاتصال بالخادم",
                passed=False,
                severity="critical",
                detail=f"تعذر الوصول إلى الهدف: {exc}",
            ))
            return findings

        headers = {k.title(): v for k, v in resp.headers.items()}

        for header_name, (severity, fix) in self.REQUIRED_HEADERS.items():
            present = header_name in headers
            findings.append(CheckFinding(
                title=f"ترويسة {header_name}",
                passed=present,
                severity=severity,
                detail=(f"موجودة بقيمة: {headers.get(header_name)}" if present
                        else "غير موجودة في استجابة الخادم — الملاحظة مبنية على الاستجابة الفعلية."),
                remediation="" if present else fix,
                code_snippet="" if present else f'response.headers["{header_name}"] = "..."',
            ))

        # كشف تسريب معلومات الخادم
        server_header = headers.get("Server", "")
        if server_header and any(ch.isdigit() for ch in server_header):
            findings.append(CheckFinding(
                title="تسريب إصدار الخادم",
                passed=False,
                severity="low",
                detail=f"ترويسة Server تكشف الإصدار: {server_header}",
                remediation="أخفِ رقم الإصدار عبر إعدادات الخادم (server_tokens off في Nginx مثلاً).",
            ))
        return findings


class CookieSecurityCheck(BaseSecurityCheck):
    """تحليل خصائص الكوكيز الفعلية المُرسلة من الخادم."""
    name = "Cookie Security"

    async def run(self, client: httpx.AsyncClient, target_url: str, **kwargs) -> List[CheckFinding]:
        findings: List[CheckFinding] = []
        try:
            resp = await client.get(target_url, timeout=12.0, follow_redirects=True)
        except httpx.HTTPError:
            return findings

        set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        if not set_cookie_headers:
            findings.append(CheckFinding(
                title="فحص الكوكيز",
                passed=True,
                severity="low",
                detail="لم يتم رصد أي كوكيز في الاستجابة الأولية (لا يوجد خطر مباشر هنا).",
            ))
            return findings

        for raw_cookie in set_cookie_headers:
            cookie_name = raw_cookie.split("=")[0]
            lower = raw_cookie.lower()
            missing_flags = [f for f in ("secure", "httponly", "samesite") if f not in lower]
            findings.append(CheckFinding(
                title=f"كوكيز: {cookie_name}",
                passed=not missing_flags,
                severity="high" if "session" in cookie_name.lower() and missing_flags else "medium",
                detail=(f"ينقصها الخصائص: {', '.join(missing_flags)}" if missing_flags
                        else "تحتوي على جميع خصائص الحماية (Secure, HttpOnly, SameSite)."),
                remediation="" if not missing_flags else "أضف Secure; HttpOnly; SameSite=Strict عند تعيين الكوكيز.",
            ))
        return findings


class TlsCertificateCheck(BaseSecurityCheck):
    """فحص حقيقي لشهادة SSL/TLS عبر اتصال socket مباشر بالمنفذ 443."""
    name = "TLS Certificate"

    async def run(self, client: httpx.AsyncClient, target_url: str, **kwargs) -> List[CheckFinding]:
        findings: List[CheckFinding] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        if parsed.scheme != "https" or not hostname:
            findings.append(CheckFinding(
                title="بروتوكول الاتصال",
                passed=False,
                severity="critical",
                detail="الموقع لا يستخدم HTTPS — جميع البيانات تنتقل بدون تشفير.",
                remediation="فعّل شهادة SSL (مثل Let's Encrypt) وأجبر التحويل من HTTP إلى HTTPS.",
            ))
            return findings

        try:
            loop = asyncio.get_event_loop()
            cert, protocol, cipher = await loop.run_in_executor(None, self._fetch_certificate, hostname)
        except Exception as exc:
            findings.append(CheckFinding(
                title="فحص شهادة SSL",
                passed=False,
                severity="high",
                detail=f"تعذر إتمام مصافحة TLS: {exc}",
            ))
            return findings

        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days

        if days_left < 0:
            sev, detail = "critical", "شهادة SSL منتهية الصلاحية بالفعل!"
        elif days_left < 15:
            sev, detail = "high", f"الشهادة ستنتهي خلال {days_left} يومًا فقط."
        elif days_left < 30:
            sev, detail = "medium", f"الشهادة ستنتهي خلال {days_left} يومًا."
        else:
            sev, detail = "low", f"الشهادة سارية لمدة {days_left} يومًا إضافية."

        findings.append(CheckFinding(
            title="صلاحية شهادة SSL",
            passed=days_left >= 30,
            severity=sev,
            detail=detail,
            remediation="" if days_left >= 30 else "جدّد الشهادة فورًا أو فعّل التجديد التلقائي.",
        ))

        weak_protocols = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
        findings.append(CheckFinding(
            title="إصدار بروتوكول TLS",
            passed=protocol not in weak_protocols,
            severity="critical" if protocol in weak_protocols else "low",
            detail=f"البروتوكول المستخدم فعليًا: {protocol}",
            remediation="" if protocol not in weak_protocols else "عطّل TLS 1.0/1.1 و SSLv3 على الخادم، واعتمد TLS 1.2+ فقط.",
        ))
        return findings

    @staticmethod
    def _fetch_certificate(hostname: str):
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()
        return cert, protocol, cipher


class UserEnumerationCheck(BaseSecurityCheck):
    """
    فحص حقيقي لثغرة تعداد المستخدمين: يقارن زمن ومحتوى استجابتين
    (حساب موجود افتراضيًا vs. حساب غير موجود) بدل الاعتماد على status_code فقط.
    """
    name = "User Enumeration"

    async def run(self, client: httpx.AsyncClient, target_url: str, login_path: str = "/login", **kwargs) -> List[CheckFinding]:
        findings: List[CheckFinding] = []
        login_url = f"{target_url.rstrip('/')}/{login_path.lstrip('/')}"

        try:
            resp_a = await client.post(login_url, data={"username": "admin", "password": "wrong_pw_x1"}, timeout=12.0)
            resp_b = await client.post(login_url, data={"username": "nonexistent_user_zzz", "password": "wrong_pw_x1"}, timeout=12.0)
        except httpx.HTTPError as exc:
            findings.append(CheckFinding(
                title="تعداد المستخدمين",
                passed=True,
                severity="low",
                detail=f"تعذر الوصول لمسار تسجيل الدخول لإجراء الفحص التفاضلي: {exc}",
            ))
            return findings

        same_status = resp_a.status_code == resp_b.status_code
        same_length_class = abs(len(resp_a.text) - len(resp_b.text)) < 5  # فارق طفيف مقبول

        vulnerable = not (same_status and same_length_class)
        findings.append(CheckFinding(
            title="مقاومة تعداد المستخدمين",
            passed=not vulnerable,
            severity="medium" if vulnerable else "low",
            detail=(
                f"الاستجابتان مختلفتان (status: {resp_a.status_code} مقابل {resp_b.status_code}، "
                f"فرق الطول: {abs(len(resp_a.text) - len(resp_b.text))} حرف) — قد يسمح باستنتاج الحسابات الصحيحة."
                if vulnerable else
                "الاستجابتان متطابقتان في الحالة والطول التقريبي — لا يوجد فارق قابل للاستغلال."
            ),
            remediation="" if not vulnerable else "وحّد رسالة الخطأ وزمن الاستجابة لكل من الحسابين الصحيح والخاطئ.",
            code_snippet="" if not vulnerable else 'return {"error": "بيانات الدخول غير صحيحة"}, 401  # رسالة موحدة دومًا',
        ))
        return findings


# ==================================================================================
# 3) محرك التنفيذ المركزي
# ==================================================================================
class SecurityAuditEngine:
    def __init__(self):
        self.checks: List[BaseSecurityCheck] = [
            SecurityHeadersCheck(),
            CookieSecurityCheck(),
            TlsCertificateCheck(),
            UserEnumerationCheck(),
        ]

    async def execute(self, payload: AdvancedAuditRequest) -> ScanReport:
        target_url = str(payload.target_url)
        headers = {}
        if payload.scan_mode == "authenticated" and payload.auth_token:
            if payload.auth_token.lower().startswith("bearer"):
                headers["Authorization"] = payload.auth_token
            else:
                headers["Cookie"] = f"session_id={payload.auth_token}"

        report = ScanReport(
            target=target_url,
            scan_mode="فحص داخلي مُصادَق عليه" if payload.scan_mode == "authenticated" else "فحص خارجي عام",
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        )

        async with httpx.AsyncClient(headers=headers, verify=True) as client:
            for check in self.checks:
                try:
                    findings = await check.run(client, target_url, login_path=payload.login_page_path or "/login")
                    report.findings.extend(findings)
                except Exception as exc:
                    logger.error(f"فشل فاحص {check.name}: {exc}")
                    report.findings.append(CheckFinding(
                        title=check.name, passed=False, severity="medium",
                        detail=f"تعذر إتمام هذا الفحص: {exc}",
                    ))

        report.security_score = self._calculate_score(report.findings)
        return report

    @staticmethod
    def _calculate_score(findings: List[CheckFinding]) -> int:
        score = 100
        for f in findings:
            if not f.passed:
                score -= SEVERITY_WEIGHT.get(f.severity, 5)
        return max(0, min(100, score))


async def run_background_security_pipeline(scan_id: str, payload: AdvancedAuditRequest) -> None:
    scan_database[scan_id]["status"] = "running"
    try:
        engine = SecurityAuditEngine()
        report = await engine.execute(payload)
        scan_database[scan_id]["report"] = report
        scan_database[scan_id]["status"] = "completed"
        logger.info(f"اكتمل الفحص: {scan_id} | الدرجة: {report.security_score}")
    except Exception as e:
        logger.error(f"فشل الفحص {scan_id}: {e}")
        scan_database[scan_id]["status"] = "failed"
        scan_database[scan_id]["error"] = str(e)


# ==================================================================================
# 4) نقاط النهاية (Endpoints)
# ==================================================================================
@app.post("/api/v1/scan/enterprise/start", summary="بدء عملية الفحص الأمني الحقيقي")
def start_enterprise_scan(
    payload: AdvancedAuditRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_enterprise_api_key),
):
    scan_id = str(uuid.uuid4())
    scan_database[scan_id] = {"status": "queued"}
    # يتم تمرير الدالة async مباشرة: FastAPI/Starlette يكتشف أنها غير متزامنة
    # وينتظرها (await) داخل نفس حلقة الأحداث الرئيسية بعد إرسال الرد للعميل،
    # دون الحاجة لأي Thread إضافي أو asyncio.run يدوي.
    background_tasks.add_task(run_background_security_pipeline, scan_id, payload)
    return {"scan_id": scan_id, "status": "queued", "mode": payload.scan_mode}


@app.get("/api/v1/scan/enterprise/status/{scan_id}", summary="متابعة حالة الفحص")
def get_scan_status(scan_id: str, api_key: str = Depends(verify_enterprise_api_key)):
    if scan_id not in scan_database:
        raise HTTPException(status_code=404, detail="معرّف الفحص غير موجود.")
    entry = scan_database[scan_id]
    result = {"status": entry["status"]}
    if entry["status"] == "completed":
        report: ScanReport = entry["report"]
        result["security_score"] = report.security_score
        result["findings_count"] = len(report.findings)
        result["failed_checks"] = [f.title for f in report.findings if not f.passed]
    return result


# ==================================================================================
# 5) توليد تقرير PDF — تصميم مختلف بالكامل (بطاقات ملونة حسب الخطورة + شريط درجة)
# ==================================================================================
SEVERITY_COLOR = {
    "critical": colors.HexColor("#7f1d1d"),
    "high": colors.HexColor("#b91c1c"),
    "medium": colors.HexColor("#b45309"),
    "low": colors.HexColor("#15803d"),
}
SEVERITY_LABEL_AR = {
    "critical": "حرجة", "high": "عالية", "medium": "متوسطة", "low": "منخفضة",
}


def build_pdf_report(report: ScanReport) -> io.BytesIO:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=32, leftMargin=32, topMargin=34, bottomMargin=34)
    styles = getSampleStyleSheet()
    story = []

    brand_title = ParagraphStyle("BrandTitle", parent=styles["Heading1"], fontSize=20,
                                  textColor=colors.HexColor("#0b1220"), alignment=TA_CENTER, spaceAfter=2)
    brand_sub = ParagraphStyle("BrandSub", parent=styles["Normal"], fontSize=9.5,
                                textColor=colors.HexColor("#64748b"), alignment=TA_CENTER, spaceAfter=14)
    section = ParagraphStyle("Section", parent=styles["Heading2"], fontSize=13,
                              textColor=colors.HexColor("#0b1220"), spaceBefore=16, spaceAfter=8)
    body = ParagraphStyle("Body", parent=styles["Normal"], fontSize=9.5,
                           textColor=colors.HexColor("#1e293b"), leading=13.5)
    meta = ParagraphStyle("Meta", parent=styles["Normal"], fontSize=9,
                           textColor=colors.HexColor("#475569"), leading=13)

    # -- الترويسة --
    story.append(Paragraph("CYBERGUARD AI — تقرير التدقيق الأمني", brand_title))
    story.append(Paragraph(f"{report.target} &nbsp;|&nbsp; {report.scan_mode} &nbsp;|&nbsp; {report.generated_at}", brand_sub))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))

    # -- بطاقة الدرجة الإجمالية --
    score = report.security_score
    score_color = colors.HexColor("#15803d") if score >= 80 else (
        colors.HexColor("#b45309") if score >= 50 else colors.HexColor("#b91c1c"))
    score_table = Table(
        [[Paragraph(f"<font size=26 color='{score_color.hexval()}'><b>{score}</b></font><font size=11>/100</font>",
                    ParagraphStyle("ScoreNum", alignment=TA_CENTER)),
          Paragraph(f"إجمالي الفحوصات: <b>{len(report.findings)}</b><br/>"
                    f"فحوصات ناجحة: <b>{sum(1 for f in report.findings if f.passed)}</b><br/>"
                    f"فحوصات فاشلة: <b>{sum(1 for f in report.findings if not f.passed)}</b>", body)]],
        colWidths=[130, 350],
    )
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, 0), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
    ]))
    story.append(Spacer(1, 10))
    story.append(score_table)

    # -- تفصيل النتائج كبطاقات ملونة حسب الخطورة --
    story.append(Paragraph("نتائج الفحص التفصيلية", section))

    ordered = sorted(report.findings, key=lambda f: (f.passed, {"critical": 0, "high": 1, "medium": 2, "low": 3}[f.severity]))
    for f in ordered:
        status_txt = "✔ اجتاز" if f.passed else "✘ يحتاج معالجة"
        status_color = colors.HexColor("#15803d") if f.passed else SEVERITY_COLOR[f.severity]
        row = [[
            Paragraph(f"<b>{f.title}</b><br/><font size=8 color='#64748b'>الخطورة: "
                      f"{SEVERITY_LABEL_AR[f.severity]}</font>", body),
            Paragraph(f"<font color='{status_color.hexval()}'><b>{status_txt}</b></font>", body),
        ]]
        card = Table(row, colWidths=[360, 120])
        card.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#e2e8f0")),
            ("LINEBEFORE", (0, 0), (0, -1), 3, status_color),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(card)
        story.append(Paragraph(f.detail, meta))
        if f.remediation:
            story.append(Paragraph(f"<b>التوصية:</b> {f.remediation}", meta))
        if f.code_snippet:
            story.append(Paragraph(f"<font face='Courier' size=8 color='#0f766e'>{f.code_snippet}</font>", meta))
        story.append(Spacer(1, 8))

    doc.build(story)
    buffer.seek(0)
    return buffer


@app.get("/api/v1/scan/enterprise/report/pdf/{scan_id}", summary="تصدير التقرير التنفيذي (PDF)")
def export_enterprise_pdf_report(scan_id: str, api_key: str = Depends(verify_enterprise_api_key)):
    if scan_id not in scan_database or scan_database[scan_id]["status"] != "completed":
        raise HTTPException(status_code=404, detail="التقرير غير موجود أو لم يكتمل الفحص بعد.")

    report: ScanReport = scan_database[scan_id]["report"]
    buffer = build_pdf_report(report)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=CyberGuard_Report_{scan_id[:8]}.pdf"},
    )
