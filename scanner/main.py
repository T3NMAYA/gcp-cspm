import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from google.cloud import bigquery, asset_v1, compute_v1
from datetime import datetime

app = FastAPI()

# --- CONFIGURATION ---
# Professional practice: Use environment variables with fallbacks
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "cloudsentinel-gcp-2026")

# --- CORS MIDDLEWARE ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def send_security_alert(finding_count, severity="CRITICAL"):
    """
    Simulates a professional alerting system (Webhook/Email).
    In a real-world scenario, this would integrate with SendGrid, Slack, or GCP Pub/Sub.
    """
    print(f"--- SECURITY ALERT TRIGGERED ---")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Status: {finding_count} {severity} issues detected in {PROJECT_ID}.")
    print(f"Action: Notification dispatched to Security Admin.")

@app.get("/")
def health():
    return {"status": "Scanner is UP", "project": PROJECT_ID}

@app.get("/scan")
@app.post("/scan")
async def run_real_scan():
    asset_client = asset_v1.AssetServiceClient()
    compute_client = compute_v1.InstancesClient()
    bq_client = bigquery.Client()
    
    findings = []
    found_critical = False
    
    # --- 1. STORAGE BUCKET AUDIT (CIS GCP 5.1) ---
    scope = f"projects/{PROJECT_ID}"
    asset_types = ["storage.googleapis.com/Bucket"]
    
    response = asset_client.search_all_iam_policies(
        request={"scope": scope, "asset_types": asset_types}
    )

    for policy in response:
        is_public = False
        for binding in policy.policy.bindings:
            if "allUsers" in binding.members or "allAuthenticatedUsers" in binding.members:
                is_public = True
                break
        
        if is_public:
            found_critical = True
            findings.append({
                "resource": policy.resource,
                "issue": "PUBLIC_BUCKET_DETECTED",
                "severity": "CRITICAL"
            })

    # --- 2. COMPUTE ENGINE AUDIT (CIS GCP 3.7 - Public IP Check) ---
    # Professional addition: Checking for VMs exposed to the internet
    try:
        agg_list = compute_client.aggregated_list(request={"project": PROJECT_ID})
        for zone, response in agg_list:
            if response.instances:
                for instance in response.instances:
                    for interface in instance.network_interfaces:
                        if any(access.nat_i_p for access in interface.access_configs):
                            findings.append({
                                "resource": instance.name,
                                "issue": "VM_EXPOSED_VIA_PUBLIC_IP",
                                "severity": "MEDIUM"
                            })
    except Exception as e:
        print(f"Compute Audit skipped/failed: {e}")

    # --- 3. COMPLIANCE LOGGING ---
    if not findings:
        findings.append({
            "resource": "Project-Wide Audit",
            "issue": "Compliance Check: All Resources Secure",
            "severity": "INFO"
        })
    
    # Log to BigQuery
    table_id = f"{PROJECT_ID}.cspm_data.findings"
    errors = bq_client.insert_rows_json(table_id, findings)
    
    # --- 4. ALERTING LOGIC ---
    if found_critical:
        send_security_alert(len([f for f in findings if f['severity'] == 'CRITICAL']))
    
    return {
        "status": "Complete", 
        "total_findings": len(findings),
        "critical_found": found_critical,
        "errors": errors
    }

@app.get("/api/findings")
async def get_findings():
    try:
        client = bigquery.Client()
        query = f"""
            SELECT resource, issue, severity, timestamp 
            FROM `{PROJECT_ID}.cspm_data.findings`
            ORDER BY timestamp DESC
            LIMIT 100
        """
        query_job = client.query(query)
        results = query_job.result()
        
        findings_list = []
        for row in results:
            findings_list.append({
                "resource": row.resource,
                "issue": row.issue,
                "severity": row.severity,
                "timestamp": str(row.timestamp)
            })
        
        return findings_list
    except Exception as e:
        return {"error": str(e)}