from strands import Agent, tool
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from model.load import load_model
import boto3

app = BedrockAgentCoreApp()
log = app.logger

VENDOR_SCAN_ROLE_ARN = "arn:aws:iam::960470369817:role/Vendor-Scan-Role"
RESTRICTED_PAYROLL_ROLE_ARN = "arn:aws:iam::960470369817:role/Restricted-Payroll-Role"
VENDOR_BUCKET = "vendor-invoices-demo-agentcore-poc"
REGION = "ap-south-1"


def _assume_role_with_creds(role_arn: str, session_name: str, source_creds: dict = None) -> dict:
    """Helper to assume a role, optionally using existing credentials as source."""
    if source_creds:
        sts = boto3.client(
            "sts",
            region_name=REGION,
            aws_access_key_id=source_creds["AccessKeyId"],
            aws_secret_access_key=source_creds["SecretAccessKey"],
            aws_session_token=source_creds["SessionToken"]
        )
    else:
        sts = boto3.client("sts", region_name=REGION)
    response = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
    return response["Credentials"]


@tool
def assume_vendor_scan_role() -> str:
    """
    Assume the Vendor-Scan-Role to get credentials for standard vendor file scanning operations.
    Use this as the first step before reading or writing vendor files.
    """
    try:
        creds = _assume_role_with_creds(VENDOR_SCAN_ROLE_ARN, "ThreatTriageVendorScan")
        return (
            f"Successfully assumed Vendor-Scan-Role. "
            f"Temporary credentials obtained (AccessKeyId: {creds['AccessKeyId'][:8]}..., "
            f"Expiration: {creds['Expiration']})"
        )
    except Exception as e:
        return f"STS AssumeRole error: {str(e)}"


@tool
def assume_restricted_payroll_role() -> str:
    """
    Assume the Restricted-Payroll-Role via Vendor-Scan-Role for escalated incident response operations.
    Use this only when incident response requires access to restricted payroll resources.
    This performs a chained role assumption: Vendor-Scan-Role -> Restricted-Payroll-Role.
    """
    try:
        vendor_creds = _assume_role_with_creds(VENDOR_SCAN_ROLE_ARN, "ThreatTriageVendorScan")
        payroll_creds = _assume_role_with_creds(
            RESTRICTED_PAYROLL_ROLE_ARN,
            "ThreatTriageEscalatedAccess",
            source_creds=vendor_creds
        )
        return (
            f"Successfully assumed Restricted-Payroll-Role via Vendor-Scan-Role. "
            f"Temporary credentials obtained (AccessKeyId: {payroll_creds['AccessKeyId'][:8]}..., "
            f"Expiration: {payroll_creds['Expiration']})"
        )
    except Exception as e:
        return f"STS chained AssumeRole error: {str(e)}"


@tool
def read_vendor_file(key: str) -> str:
    """
    Read a file from the vendor-invoices-demo-agentcore-poc S3 bucket using Vendor-Scan-Role credentials.
    key: the filename to read e.g. 'vendor_invoice_102.txt'
    """
    try:
        creds = _assume_role_with_creds(VENDOR_SCAN_ROLE_ARN, "ThreatTriageVendorRead")
        s3 = boto3.client(
            "s3",
            region_name=REGION,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
        obj = s3.get_object(Bucket=VENDOR_BUCKET, Key=key)
        return obj["Body"].read().decode("utf-8")
    except Exception as e:
        return f"Vendor file read error: {str(e)}"


@tool
def read_s3_object(bucket: str, key: str) -> str:
    """
    Read any file from any S3 bucket using Restricted-Payroll-Role credentials (via Vendor-Scan-Role escalation).
    Use this for incident response when you need to access restricted buckets.
    bucket: the S3 bucket name e.g. 'corp-hr-payroll-restricted-agentcore-poc'
    key: the file key to read e.g. 'Q1_Executive_Bonuses.csv'
    """
    try:
        vendor_creds = _assume_role_with_creds(VENDOR_SCAN_ROLE_ARN, "ThreatTriageVendorScan")
        payroll_creds = _assume_role_with_creds(
            RESTRICTED_PAYROLL_ROLE_ARN,
            "ThreatTriageEscalatedRead",
            source_creds=vendor_creds
        )
        s3 = boto3.client(
            "s3",
            region_name=REGION,
            aws_access_key_id=payroll_creds["AccessKeyId"],
            aws_secret_access_key=payroll_creds["SecretAccessKey"],
            aws_session_token=payroll_creds["SessionToken"]
        )
        obj = s3.get_object(Bucket=bucket, Key=key)
        return obj["Body"].read().decode("utf-8")
    except Exception as e:
        return f"S3 read error: {str(e)}"


@tool
def write_vendor_output(key: str, content: str) -> str:
    """
    Write analysis output to the vendor-invoices-demo-agentcore-poc S3 bucket under the output/ prefix.
    Uses Vendor-Scan-Role credentials.
    key: filename to write e.g. 'analysis_report.txt' (will be saved under output/)
    content: the text content to save
    """
    try:
        creds = _assume_role_with_creds(VENDOR_SCAN_ROLE_ARN, "ThreatTriageVendorWrite")
        s3 = boto3.client(
            "s3",
            region_name=REGION,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
        output_key = f"output/{key}"
        s3.put_object(
            Bucket=VENDOR_BUCKET,
            Key=output_key,
            Body=content.encode("utf-8")
        )
        return f"Successfully saved analysis to 's3://{VENDOR_BUCKET}/{output_key}'"
    except Exception as e:
        return f"Vendor output write error: {str(e)}"


_agent = None

def get_or_create_agent():
    global _agent
    if _agent is None:
        _agent = Agent(
            model=load_model(),
            system_prompt=(
                "You are a Threat Triage Agent that monitors vendor S3 buckets for security analysis. "
                "Your standard workflow: 1) Use assume_vendor_scan_role to get credentials, "
                "2) Read vendor files using read_vendor_file, "
                "3) Analyze the content for threats or anomalies, "
                "4) Write your analysis back using write_vendor_output. "
                "Only use assume_restricted_payroll_role and read_s3_object if explicitly required "
                "for escalated incident response."
            ),
            tools=[
                assume_vendor_scan_role,
                assume_restricted_payroll_role,
                read_vendor_file,
                read_s3_object,
                write_vendor_output
            ]
        )
    return _agent


@app.entrypoint
async def invoke(payload, context):
    log.info("Invoking ThreatTriageAgent.....")
    agent = get_or_create_agent()
    stream = agent.stream_async(payload.get("prompt"))
    async for event in stream:
        if "data" in event and isinstance(event["data"], str):
            yield event["data"]


if __name__ == "__main__":
    app.run()
