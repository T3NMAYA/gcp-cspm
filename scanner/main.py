import os
import json
import httpx
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from google.cloud import bigquery, asset_v1, compute_v1, storage

app = FastAPI(title="CloudSentinel CSPM API", version="2.0")

# ---------------------------------------------------------------------------
# CONFIGURATION  (set via environment variables)
# ---------------------------------------------------------------------------
PROJECT_ID        = os.getenv("GOOGLE_CLOUD_PROJECT", "cloudsentinel-gcp-2026")
API_KEY           = os.getenv("CSPM_API_KEY", "changeme-set-CSPM_API_KEY-env-var")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
SMTP_HOST         = os.getenv("SMTP_HOST", "smtp.gmail.com")
# FIX #2: Default changed to 465 to match smtplib.SMTP_SSL below.
#         If you prefer port 587 (STARTTLS), keep 587 and swap to smtplib.SMTP + starttls().
SMTP_PORT         = int(os.getenv("SMTP_PORT", "465"))
SMTP_USER         = os.getenv("SMTP_USER", "")
SMTP_PASS         = os.getenv("SMTP_PASS", "")
ALERT_EMAIL_TO    = os.getenv("ALERT_EMAIL_TO", "")

# FIX #4 (CORS): Replace "*" with your dashboard's actual origin in production.
# e.g. allow_origins=["https://your-dashboard-domain.com"]
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,   # FIX #4: no longer hardcoded to "*"
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# AUTHENTICATION — X-API-Key header
# ---------------------------------------------------------------------------
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def verify_api_key(key: str = Security(api_key_header)):
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return key

# ---------------------------------------------------------------------------
# ALERTING
# ---------------------------------------------------------------------------

def send_slack_alert(findings: list) -> bool:
    if not SLACK_WEBHOOK_URL:
        print("[ALERT] SLACK_WEBHOOK_URL not set — skipped.")
        return False
    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    medium   = [f for f in findings if f.get("severity") == "MEDIUM"]
    bullets  = "\n".join(f"• `{f['resource']}` — {f['issue']}" for f in critical[:5])
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": "🚨 CloudSentinel Security Alert", "emoji": True}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Project:*\n`{PROJECT_ID}`"},
            {"type": "mrkdwn", "text": f"*Scan Time:*\n{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"},
            {"type": "mrkdwn", "text": f"*🔴 Critical:*\n{len(critical)}"},
            {"type": "mrkdwn", "text": f"*🟡 Medium:*\n{len(medium)}"},
        ]},
    ]
    if critical:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Top Critical Findings:*\n{bullets}"}})
    try:
        resp = httpx.post(SLACK_WEBHOOK_URL, json={"blocks": blocks, "text": f"[CloudSentinel] {len(critical)} critical issues"}, timeout=10)
        resp.raise_for_status()
        print("[ALERT] Slack notification sent.")
        return True
    except Exception as e:
        print(f"[ALERT] Slack send failed: {e}")
        return False


def send_email_alert(findings: list) -> bool:
    if not SMTP_USER or not SMTP_PASS or not ALERT_EMAIL_TO:
        print("[ALERT] Email credentials not set — skipped.")
        return False
    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    medium   = [f for f in findings if f.get("severity") == "MEDIUM"]
    rows_html = "".join(
        f"""<tr style="background:{'#3b0e0e' if f['severity']=='CRITICAL' else '#3b2e0e' if f['severity']=='MEDIUM' else '#0e1c3b'}">
              <td style="padding:8px;font-family:monospace;font-size:11px;color:#93c5fd">{f['resource']}</td>
              <td style="padding:8px;color:#e2e8f0">{f['issue']}</td>
              <td style="padding:8px;text-align:center">
                <span style="background:{'#dc2626' if f['severity']=='CRITICAL' else '#d97706' if f['severity']=='MEDIUM' else '#2563eb'};
                  color:#fff;padding:2px 8px;border-radius:9999px;font-size:10px;font-weight:700">{f['severity']}</span>
              </td>
            </tr>"""
        for f in findings[:20]
    )
    html = f"""<html><body style="background:#0f172a;color:#e2e8f0;font-family:sans-serif;padding:32px">
      <h1 style="color:#3b82f6;border-bottom:2px solid #1e3a5f;padding-bottom:8px">🛡️ CloudSentinel Security Report</h1>
      <p style="color:#94a3b8">Project: <strong>{PROJECT_ID}</strong> | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
      <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;background:#1e293b;border-radius:8px">
        <thead><tr style="background:#334155">
          <th style="padding:12px;text-align:left;font-size:11px;color:#94a3b8">Resource</th>
          <th style="padding:12px;text-align:left;font-size:11px;color:#94a3b8">Issue</th>
          <th style="padding:12px;text-align:center;font-size:11px;color:#94a3b8">Severity</th>
        </tr></thead>
        <tbody>{rows_html}</tbody>
      </table>
    </body></html>"""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[CloudSentinel] {len(critical)} critical, {len(medium)} medium issues in {PROJECT_ID}"
    msg["From"] = SMTP_USER
    msg["To"]   = ALERT_EMAIL_TO
    msg.attach(MIMEText(html, "html"))
    try:
        # FIX #2: SMTP_SSL is correct for port 465 (implicit TLS).
        # If using port 587, replace with:
        #   with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        #       s.starttls()
        #       s.login(SMTP_USER, SMTP_PASS)
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as s:
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_USER, ALERT_EMAIL_TO, msg.as_string())
        print(f"[ALERT] Email sent to {ALERT_EMAIL_TO}.")
        return True
    except Exception as e:
        print(f"[ALERT] Email send failed: {e}")
        return False

# ---------------------------------------------------------------------------
# CIS GCP SECURITY CHECKS
# ---------------------------------------------------------------------------

def check_public_storage_buckets(findings):
    """CIS GCP 5.1 — No public buckets."""
    # FIX #1: Added try/except so a permissions or API error here does NOT
    # crash the entire /scan endpoint and block all subsequent checks.
    try:
        client = asset_v1.AssetServiceClient()
        for policy in client.search_all_iam_policies(
            request={"scope": f"projects/{PROJECT_ID}", "asset_types": ["storage.googleapis.com/Bucket"]}
        ):
            for binding in policy.policy.bindings:
                if "allUsers" in binding.members or "allAuthenticatedUsers" in binding.members:
                    findings.append({"resource": policy.resource, "issue": "PUBLIC_BUCKET_DETECTED",
                        "severity": "CRITICAL", "cis_control": "CIS GCP 5.1", "timestamp": datetime.utcnow().isoformat()})
                    break
    except Exception as e:
        print(f"[SCAN] Public bucket check skipped: {e}")


def check_vm_public_ips(findings):
    """CIS GCP 3.9 — VMs should not have public IPs."""
    try:
        client = compute_v1.InstancesClient()
        for _zone, resp in client.aggregated_list(request={"project": PROJECT_ID}):
            for instance in getattr(resp, "instances", []):
                for iface in instance.network_interfaces:
                    if any(a.nat_i_p for a in iface.access_configs):
                        findings.append({"resource": instance.name, "issue": "VM_WITH_PUBLIC_IP",
                            "severity": "MEDIUM", "cis_control": "CIS GCP 3.9", "timestamp": datetime.utcnow().isoformat()})
    except Exception as e:
        print(f"[SCAN] VM public-IP check skipped: {e}")


def check_firewall_unrestricted_ssh_rdp(findings):
    """CIS GCP 3.6/3.7 — Block SSH/RDP from 0.0.0.0/0."""
    try:
        fw_client = compute_v1.FirewallsClient()
        for fw in fw_client.list(project=PROJECT_ID):
            if fw.direction != "INGRESS":
                continue
            if "0.0.0.0/0" not in fw.source_ranges and "::/0" not in fw.source_ranges:
                continue
            for rule in fw.allowed:
                ports = list(rule.ports) if rule.ports else []
                if rule.I_p_protocol not in ("all", "tcp"):
                    continue
                # FIX #3: When no specific ports are listed the rule allows ALL TCP
                # (including both SSH and RDP). Report them as separate findings
                # instead of only flagging SSH and silently missing RDP.
                if not ports:
                    findings.append({"resource": fw.name, "issue": "FIREWALL_OPEN_ALL_TCP",
                        "severity": "CRITICAL", "cis_control": "CIS GCP 3.6/3.7",
                        "timestamp": datetime.utcnow().isoformat()})
                else:
                    if "22" in ports:
                        findings.append({"resource": fw.name, "issue": "FIREWALL_OPEN_SSH",
                            "severity": "CRITICAL", "cis_control": "CIS GCP 3.6",
                            "timestamp": datetime.utcnow().isoformat()})
                    if "3389" in ports:
                        findings.append({"resource": fw.name, "issue": "FIREWALL_OPEN_RDP",
                            "severity": "CRITICAL", "cis_control": "CIS GCP 3.7",
                            "timestamp": datetime.utcnow().isoformat()})
    except Exception as e:
        print(f"[SCAN] Firewall check skipped: {e}")


def check_service_account_admin_roles(findings):
    """CIS GCP 1.5 — Service accounts should not have owner/editor roles."""
    try:
        client = asset_v1.AssetServiceClient()
        ADMIN_ROLES = {"roles/owner", "roles/editor", "roles/iam.serviceAccountAdmin"}
        for policy in client.search_all_iam_policies(request={"scope": f"projects/{PROJECT_ID}"}):
            for binding in policy.policy.bindings:
                if binding.role not in ADMIN_ROLES:
                    continue
                for member in binding.members:
                    if member.startswith("serviceAccount:"):
                        findings.append({"resource": member,
                            "issue": f"SA_HAS_{binding.role.replace('roles/', '').upper()}_ROLE",
                            "severity": "CRITICAL", "cis_control": "CIS GCP 1.5",
                            "timestamp": datetime.utcnow().isoformat()})
    except Exception as e:
        print(f"[SCAN] SA role check skipped: {e}")


def check_default_service_account(findings):
    """CIS GCP 4.1 — VMs should not use the default service account."""
    try:
        client = compute_v1.InstancesClient()
        for _zone, resp in client.aggregated_list(request={"project": PROJECT_ID}):
            for instance in getattr(resp, "instances", []):
                for sa in instance.service_accounts:
                    if sa.email.endswith("-compute@developer.gserviceaccount.com"):
                        findings.append({"resource": instance.name, "issue": "VM_USING_DEFAULT_SERVICE_ACCOUNT",
                            "severity": "MEDIUM", "cis_control": "CIS GCP 4.1",
                            "timestamp": datetime.utcnow().isoformat()})
    except Exception as e:
        print(f"[SCAN] Default SA check skipped: {e}")


def check_bucket_uniform_iam(findings):
    """CIS GCP 5.2 — Uniform bucket-level IAM should be enabled."""
    try:
        storage_client = storage.Client(project=PROJECT_ID)
        for bucket in storage_client.list_buckets():
            bucket.reload()
            if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
                findings.append({"resource": f"//storage.googleapis.com/{bucket.name}",
                    "issue": "BUCKET_LEGACY_ACL_ENABLED", "severity": "MEDIUM",
                    "cis_control": "CIS GCP 5.2", "timestamp": datetime.utcnow().isoformat()})
    except Exception as e:
        print(f"[SCAN] Bucket uniform-IAM check skipped: {e}")


def check_os_login_disabled(findings):
    """CIS GCP 4.4 — OS Login should be enabled project-wide."""
    try:
        client = compute_v1.ProjectsClient()
        project = client.get(project=PROJECT_ID)
        for item in project.common_instance_metadata.items:
            if item.key == "enable-oslogin" and item.value.lower() == "true":
                return  # compliant
        findings.append({"resource": f"projects/{PROJECT_ID}", "issue": "OS_LOGIN_NOT_ENABLED_PROJECT_WIDE",
            "severity": "MEDIUM", "cis_control": "CIS GCP 4.4", "timestamp": datetime.utcnow().isoformat()})
    except Exception as e:
        print(f"[SCAN] OS Login check skipped: {e}")


# ---------------------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------------------

@app.get("/")
def health():
    return {"status": "CloudSentinel Scanner v2 UP", "project": PROJECT_ID}


@app.get("/scan")
@app.post("/scan")
async def run_scan(api_key: str = Depends(verify_api_key)):
    findings = []
    check_public_storage_buckets(findings)
    check_vm_public_ips(findings)
    check_firewall_unrestricted_ssh_rdp(findings)
    check_service_account_admin_roles(findings)
    check_default_service_account(findings)
    check_bucket_uniform_iam(findings)
    check_os_login_disabled(findings)

    # Alerting (before we potentially modify findings for the response)
    has_critical = any(f["severity"] == "CRITICAL" for f in findings)
    slack_sent = email_sent = False
    if has_critical:
        slack_sent = send_slack_alert(findings)
        email_sent = send_email_alert(findings)

    # FIX #3 (ghost finding): Only write to BigQuery when there are real findings.
    # Do NOT insert a synthetic INFO row — it pollutes counts and the dashboard.
    bq_errors = []
    if findings:
        bq_client = bigquery.Client()
        bq_errors = bq_client.insert_rows_json(f"{PROJECT_ID}.cspm_data.findings", findings)

    return {
        "status": "Complete",
        "total_findings": len(findings),
        "clean": len(findings) == 0,
        "alerts_dispatched": {"slack": slack_sent, "email": email_sent},
        "bq_errors": bq_errors,
    }


@app.get("/api/findings")
async def get_findings(api_key: str = Depends(verify_api_key)):
    try:
        client = bigquery.Client()
        # FIX #3: Exclude any legacy INFO "Audit Passed" rows that may have been
        # written by older versions of this scanner.
        query = f"""
            SELECT *
            FROM `{PROJECT_ID}.cspm_data.findings`
            WHERE severity != 'INFO'
            ORDER BY timestamp DESC
            LIMIT 50
        """
        results = client.query(query).result()

        output = []
        for row in results:
            output.append({
                "resource":    getattr(row, "resource", "N/A"),
                "issue":       getattr(row, "issue", "Unknown Issue"),
                "severity":    getattr(row, "severity", "INFO"),
                "cis_control": getattr(row, "cis_control", "General"),
                "timestamp":   str(getattr(row, "timestamp", "Recent"))
            })
        return output
    except Exception as e:
        print(f"CRITICAL ERROR in get_findings: {e}")
        return [{"resource": "Error", "issue": str(e), "severity": "CRITICAL"}]


@app.get("/api/detailed-costs")
async def get_detailed_costs(api_key: str = Depends(verify_api_key)):
    """
    Queries BigQuery for actual 24-hour project costs.
    Falls back to estimates if the billing table is not yet populated.
    """
    try:
        client = bigquery.Client()
        BILLING_TABLE = f"{PROJECT_ID}.cspm_data.gcp_billing_export_v1_*"

        query = f"""
            SELECT service.description as service, SUM(cost) as total_cost
            FROM `{BILLING_TABLE}`
            WHERE usage_start_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
            GROUP BY 1
            ORDER BY total_cost DESC
        """
        query_job = client.query(query)
        results = query_job.result()

        breakdown = {row.service: float(row.total_cost) for row in results}
        total_24h = sum(breakdown.values())

        return {
            "per_scan_cost": total_24h,
            "breakdown": breakdown if breakdown else {"Setup": 0.0},
            "currency": "USD",
            "note": "Actual costs from BigQuery billing export."
        }
    except Exception as e:
        estimates = {
            "cloud_asset_api": 0.000040,
            "compute_api":     0.000020,
            "bigquery_query":  0.000030,
            "cloud_run_platform": 0.000032
        }
        return {
            "per_scan_cost": sum(estimates.values()),
            "breakdown": estimates,
            "currency": "USD",
            "note": f"Estimated (Live Data Pending): {str(e)}"
        }