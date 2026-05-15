import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone, timedelta

import httpx
from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from google.cloud import bigquery, asset_v1, compute_v1, storage

app = FastAPI(title="CloudSentinel CSPM API", version="2.1")

# ── Config ──────────────────────────────────────────────────────────────────
PROJECT_ID        = os.getenv("GOOGLE_CLOUD_PROJECT", "cloudsentinel-gcp-2026")
API_KEY           = os.getenv("CSPM_API_KEY", "changeme-set-CSPM_API_KEY-env-var")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
SMTP_HOST         = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT         = int(os.getenv("SMTP_PORT", "465"))
SMTP_USER         = os.getenv("SMTP_USER", "")
SMTP_PASS         = os.getenv("SMTP_PASS", "")
ALERT_EMAIL_TO    = os.getenv("ALERT_EMAIL_TO", "")
ALLOWED_ORIGINS   = os.getenv("ALLOWED_ORIGINS", "*").split(",")

IST = timezone(timedelta(hours=5, minutes=30))

def now_ist() -> str:
    """Return current timestamp in IST as ISO string."""
    return datetime.now(IST).isoformat()

# ── CORS ────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Auth ─────────────────────────────────────────────────────────────────────
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def verify_api_key(key: str = Security(api_key_header)):
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return key

# ── Email helper ─────────────────────────────────────────────────────────────
def _build_email_html(findings: list) -> str:
    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    medium   = [f for f in findings if f.get("severity") == "MEDIUM"]
    info     = [f for f in findings if f.get("severity") == "INFO"]
    rows = "".join(
        f"""<tr style="background:{'#3b0e0e' if f['severity']=='CRITICAL' else '#3b2e0e' if f['severity']=='MEDIUM' else '#0e1c3b'}">
              <td style="padding:8px;font-family:monospace;font-size:11px;color:#93c5fd">{f['resource']}</td>
              <td style="padding:8px;color:#e2e8f0">{f['issue'].replace('_',' ')}</td>
              <td style="padding:8px;font-family:monospace;font-size:10px;color:#7dd3fc">{f.get('cis_control','')}</td>
              <td style="padding:8px;text-align:center">
                <span style="background:{'#dc2626' if f['severity']=='CRITICAL' else '#d97706' if f['severity']=='MEDIUM' else '#059669'};
                  color:#fff;padding:2px 8px;border-radius:9999px;font-size:10px;font-weight:700">{f['severity']}</span>
              </td>
            </tr>"""
        for f in findings[:30]
    )
    scan_time = datetime.now(IST).strftime('%d %b %Y, %I:%M %p IST')
    return f"""<html><body style="background:#0f172a;color:#e2e8f0;font-family:sans-serif;padding:32px;margin:0">
      <h1 style="color:#3b82f6;border-bottom:2px solid #1e3a5f;padding-bottom:12px;margin-bottom:18px">
        🛡️ CloudSentinel Security Report
      </h1>
      <p style="color:#94a3b8;margin-bottom:22px">
        Project: <strong style="color:#e2e8f0">{PROJECT_ID}</strong> &nbsp;|&nbsp; {scan_time}
      </p>
      <div style="display:flex;gap:16px;margin-bottom:28px;flex-wrap:wrap">
        <div style="background:#3b0e0e;border-left:4px solid #dc2626;padding:14px 22px;border-radius:8px;min-width:120px">
          <p style="margin:0;font-size:11px;color:#f87171;text-transform:uppercase;font-weight:700">Critical</p>
          <p style="margin:6px 0 0;font-size:32px;font-weight:900;color:#fff;line-height:1">{len(critical)}</p>
        </div>
        <div style="background:#3b2e0e;border-left:4px solid #d97706;padding:14px 22px;border-radius:8px;min-width:120px">
          <p style="margin:0;font-size:11px;color:#fbbf24;text-transform:uppercase;font-weight:700">Medium</p>
          <p style="margin:6px 0 0;font-size:32px;font-weight:900;color:#fff;line-height:1">{len(medium)}</p>
        </div>
        <div style="background:#0e2a1e;border-left:4px solid #059669;padding:14px 22px;border-radius:8px;min-width:120px">
          <p style="margin:0;font-size:11px;color:#34d399;text-transform:uppercase;font-weight:700">Info</p>
          <p style="margin:6px 0 0;font-size:32px;font-weight:900;color:#fff;line-height:1">{len(info)}</p>
        </div>
      </div>
      <table width="100%" cellpadding="0" cellspacing="0"
        style="border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden">
        <thead><tr style="background:#334155">
          <th style="padding:12px 8px;text-align:left;font-size:11px;color:#94a3b8">Resource</th>
          <th style="padding:12px 8px;text-align:left;font-size:11px;color:#94a3b8">Issue</th>
          <th style="padding:12px 8px;text-align:left;font-size:11px;color:#94a3b8">CIS Control</th>
          <th style="padding:12px 8px;text-align:center;font-size:11px;color:#94a3b8">Severity</th>
        </tr></thead>
        <tbody>{rows}</tbody>
      </table>
      <p style="margin-top:24px;font-size:11px;color:#475569">
        This is an automated alert from CloudSentinel. Do not reply to this email.
      </p>
    </body></html>"""


def send_email_alert(findings: list, subject_override: str = None) -> bool:
    if not SMTP_USER or not SMTP_PASS or not ALERT_EMAIL_TO:
        print("[ALERT] Email credentials not set — skipped.")
        return False
    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    medium   = [f for f in findings if f.get("severity") == "MEDIUM"]
    subject  = subject_override or f"[CloudSentinel] {len(critical)} critical, {len(medium)} medium issues in {PROJECT_ID}"
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = SMTP_USER
    msg["To"]      = ALERT_EMAIL_TO
    msg.attach(MIMEText(_build_email_html(findings), "html"))
    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as s:
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_USER, ALERT_EMAIL_TO, msg.as_string())
        print(f"[ALERT] Email sent to {ALERT_EMAIL_TO}.")
        return True
    except Exception as e:
        print(f"[ALERT] Email send failed: {e}")
        raise


def send_slack_alert(findings: list) -> bool:
    if not SLACK_WEBHOOK_URL:
        return False
    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    medium   = [f for f in findings if f.get("severity") == "MEDIUM"]
    bullets  = "\n".join(f"• `{f['resource']}` — {f['issue']}" for f in critical[:5])
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": "🚨 CloudSentinel Security Alert", "emoji": True}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Project:*\n`{PROJECT_ID}`"},
            {"type": "mrkdwn", "text": f"*Scan Time (IST):*\n{datetime.now(IST).strftime('%d %b %Y, %I:%M %p')}"},
            {"type": "mrkdwn", "text": f"*🔴 Critical:*\n{len(critical)}"},
            {"type": "mrkdwn", "text": f"*🟡 Medium:*\n{len(medium)}"},
        ]},
    ]
    if critical:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Top Critical Findings:*\n{bullets}"}})
    try:
        resp = httpx.post(SLACK_WEBHOOK_URL,
            json={"blocks": blocks, "text": f"[CloudSentinel] {len(critical)} critical issues in {PROJECT_ID}"},
            timeout=10)
        resp.raise_for_status()
        return True
    except Exception as e:
        print(f"[ALERT] Slack failed: {e}")
        return False


# ── CIS Checks ───────────────────────────────────────────────────────────────

def check_public_storage_buckets(findings):
    """CIS GCP 5.1 — No public buckets."""
    try:
        client = asset_v1.AssetServiceClient()
        for policy in client.search_all_iam_policies(
            request={"scope": f"projects/{PROJECT_ID}", "asset_types": ["storage.googleapis.com/Bucket"]}
        ):
            ALLOWED_PUBLIC_BUCKETS = {"cloudsentinel-gcp-2026-dashboard"}
            for binding in policy.policy.bindings:
                bucket_name = policy.resource.split("/")[-1]
                if bucket_name in ALLOWED_PUBLIC_BUCKETS:
                    continue
                if "allUsers" in binding.members or "allAuthenticatedUsers" in binding.members:
                    findings.append({
                        "resource":    policy.resource,
                        "issue":       "PUBLIC_BUCKET_DETECTED",
                        "severity":    "CRITICAL",
                        "cis_control": "CIS GCP 5.1",
                        "timestamp":   now_ist(),
                    })
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
                        findings.append({
                            "resource":    instance.name,
                            "issue":       "VM_WITH_PUBLIC_IP",
                            "severity":    "MEDIUM",
                            "cis_control": "CIS GCP 3.9",
                            "timestamp":   now_ist(),
                        })
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
                if not ports:
                    findings.append({"resource": fw.name, "issue": "FIREWALL_OPEN_ALL_TCP",
                        "severity": "CRITICAL", "cis_control": "CIS GCP 3.6/3.7", "timestamp": now_ist()})
                else:
                    if "22" in ports:
                        findings.append({"resource": fw.name, "issue": "FIREWALL_OPEN_SSH",
                            "severity": "CRITICAL", "cis_control": "CIS GCP 3.6", "timestamp": now_ist()})
                    if "3389" in ports:
                        findings.append({"resource": fw.name, "issue": "FIREWALL_OPEN_RDP",
                            "severity": "CRITICAL", "cis_control": "CIS GCP 3.7", "timestamp": now_ist()})
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
                            "severity": "CRITICAL", "cis_control": "CIS GCP 1.5", "timestamp": now_ist()})
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
                            "severity": "MEDIUM", "cis_control": "CIS GCP 4.1", "timestamp": now_ist()})
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
                    "cis_control": "CIS GCP 5.2", "timestamp": now_ist()})
    except Exception as e:
        print(f"[SCAN] Bucket uniform-IAM check skipped: {e}")


def check_os_login_disabled(findings):
    """CIS GCP 4.4 — OS Login should be enabled project-wide."""
    try:
        client = compute_v1.ProjectsClient()
        project = client.get(project=PROJECT_ID)
        for item in project.common_instance_metadata.items:
            if item.key == "enable-oslogin" and item.value.lower() == "true":
                return
        findings.append({"resource": f"projects/{PROJECT_ID}", "issue": "OS_LOGIN_NOT_ENABLED_PROJECT_WIDE",
            "severity": "MEDIUM", "cis_control": "CIS GCP 4.4", "timestamp": now_ist()})
    except Exception as e:
        print(f"[SCAN] OS Login check skipped: {e}")


# ── Routes ───────────────────────────────────────────────────────────────────

@app.get("/")
def health():
    return {"status": "CloudSentinel Scanner v2.1 UP", "project": PROJECT_ID}


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

    # Add a clean INFO record if no real issues
    if not findings:
        findings.append({
            "resource":    f"projects/{PROJECT_ID}",
            "issue":       "ALL_CONTROLS_COMPLIANT",
            "severity":    "INFO",
            "cis_control": "N/A",
            "timestamp":   now_ist(),
        })

    slack_sent = email_sent = False
    has_critical = any(f["severity"] == "CRITICAL" for f in findings)
    if has_critical:
        slack_sent = send_slack_alert(findings)
        email_sent = send_email_alert(findings)

    bq_client = bigquery.Client()
    bq_errors = bq_client.insert_rows_json(f"{PROJECT_ID}.cspm_data.findings", findings)

    return {
        "status":            "Complete",
        "total_findings":    len([f for f in findings if f["severity"] != "INFO"]),
        "clean":             not has_critical and not any(f["severity"] == "MEDIUM" for f in findings),
        "alerts_dispatched": {"slack": slack_sent, "email": email_sent},
        "bq_errors":         bq_errors,
    }


@app.get("/api/findings")
async def get_findings(api_key: str = Depends(verify_api_key)):
    try:
        client = bigquery.Client()
        # Return ALL severities including INFO so the chart can display them
        query = f"""
            SELECT resource, issue, severity, cis_control, timestamp
            FROM `{PROJECT_ID}.cspm_data.findings`
            ORDER BY timestamp DESC
            LIMIT 100
        """
        return [
            {
                "resource":    getattr(row, "resource", "N/A"),
                "issue":       getattr(row, "issue", "Unknown"),
                "severity":    getattr(row, "severity", "INFO"),
                "cis_control": getattr(row, "cis_control", ""),
                "timestamp":   str(getattr(row, "timestamp", "")),
            }
            for row in client.query(query).result()
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/detailed-costs")
async def get_detailed_costs(api_key: str = Depends(verify_api_key)):
    try:
        client = bigquery.Client()
        query = f"""
            SELECT service.description as service, SUM(cost) as total_cost
            FROM `{PROJECT_ID}.cspm_data.gcp_billing_export_v1_*`
            WHERE usage_start_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
            GROUP BY 1 ORDER BY total_cost DESC
        """
        breakdown = {row.service: float(row.total_cost) for row in client.query(query).result()}
        return {"per_scan_cost": sum(breakdown.values()), "breakdown": breakdown or {"Setup": 0.0},
                "currency": "USD", "note": "Actual costs from BigQuery billing export."}
    except Exception:
        estimates = {"cloud_asset_api": 0.000040, "compute_api": 0.000020,
                     "bigquery_query": 0.000030, "cloud_run_platform": 0.000032}
        return {"per_scan_cost": sum(estimates.values()), "breakdown": estimates,
                "currency": "USD", "note": "Estimated (BQ billing export not configured)."}


@app.post("/api/remediate/bucket")
async def remediate_public_bucket(payload: dict, api_key: str = Depends(verify_api_key)):
    """
    Remove allUsers / allAuthenticatedUsers from a bucket's IAM policy.
    payload: { "bucket_name": "my-bucket" }
    """
    bucket_name = payload.get("bucket_name", "").strip()
    if not bucket_name:
        raise HTTPException(status_code=400, detail="bucket_name is required.")
    try:
        client = storage.Client(project=PROJECT_ID)
        bucket = client.bucket(bucket_name)
        policy = bucket.get_iam_policy(requested_policy_version=3)
        changed = False
        new_bindings = []
        for binding in policy.bindings:
            original = set(binding["members"])
            binding["members"] = [
                m for m in binding["members"]
                if m not in ("allUsers", "allAuthenticatedUsers")
            ]
            if set(binding["members"]) != original:
                changed = True
            if binding["members"]:          # drop empty bindings
                new_bindings.append(binding)
        policy.bindings = new_bindings
        bucket.set_iam_policy(policy)
        return {"success": changed, "bucket": bucket_name,
                "message": "Public access removed." if changed else "Bucket was already private."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/test-email")
async def test_email(payload: dict, api_key: str = Depends(verify_api_key)):
    """
    Send a test email using the server-side SMTP credentials.
    payload: { "to": "optional-override@example.com" }
    """
    recipient = payload.get("to", ALERT_EMAIL_TO)
    if not recipient:
        raise HTTPException(status_code=400, detail="No recipient configured (set ALERT_EMAIL_TO env var or pass 'to' in body).")
    sample = [
        {"resource": f"projects/{PROJECT_ID}", "issue": "TEST_EMAIL_ALERT",
         "severity": "INFO", "cis_control": "N/A", "timestamp": now_ist()},
        {"resource": "//storage.googleapis.com/example-bucket", "issue": "PUBLIC_BUCKET_DETECTED",
         "severity": "CRITICAL", "cis_control": "CIS GCP 5.1", "timestamp": now_ist()},
    ]
    try:
        ok = send_email_alert(sample, subject_override=f"[CloudSentinel] ✅ Test Alert — {PROJECT_ID}")
        return {"success": ok, "sent_to": recipient}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SMTP error: {e}")
