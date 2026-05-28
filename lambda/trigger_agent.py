"""
Lambda function: S3 event trigger for ThreatTriageAgent

Triggered when a .txt file is uploaded to vendor-invoices-demo-agentcore-poc.
Calls the AgentCore HTTP gateway with a prompt referencing the uploaded file.
"""

import json
import uuid
import urllib.request
import urllib.error
import os

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

GATEWAY_URL = "https://threat-triage-gateway-rq5slglhwy.gateway.bedrock-agentcore.ap-south-1.amazonaws.com/target-quick-start-d31811/invocations"
REGION = "ap-south-1"
SERVICE = "bedrock-agentcore"


def handler(event, context):
    print(f"S3 event received: {json.dumps(event)}")

    # Extract the S3 object key from the event
    record = event["Records"][0]
    bucket = record["s3"]["bucket"]["name"]
    key = record["s3"]["object"]["key"]

    print(f"New file uploaded: s3://{bucket}/{key}")

    # Skip agent-written output files to prevent recursive loop
    if key.startswith("output/"):
        print(f"Skipping output file to prevent recursive trigger: {key}")
        return {"statusCode": 200, "body": f"Skipped output file: {key}"}

    # Build the prompt — agent will read this specific file
    prompt = (
        f"Read {key} from the vendor bucket, analyze it for threats, "
        f"and write your analysis report."
    )

    session_id = str(uuid.uuid4())
    body = json.dumps({"prompt": prompt}).encode("utf-8")

    # Get Lambda execution role credentials for SigV4 signing
    session = boto3.Session()
    creds = session.get_credentials().get_frozen_credentials()
    credentials = Credentials(
        access_key=creds.access_key,
        secret_key=creds.secret_key,
        token=creds.token
    )

    # Sign the request with SigV4
    aws_request = AWSRequest(
        method="POST",
        url=GATEWAY_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": session_id,
        }
    )
    SigV4Auth(credentials, SERVICE, REGION).add_auth(aws_request)

    # Build urllib request with signed headers
    req = urllib.request.Request(
        GATEWAY_URL,
        data=body,
        headers=dict(aws_request.headers),
        method="POST"
    )

    print(f"Invoking ThreatTriageAgent gateway for file: {key}")
    print(f"Session ID: {session_id}")

    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            response_body = resp.read().decode("utf-8")
            print(f"Agent response received ({len(response_body)} bytes)")
            print(response_body[:2000])  # Log first 2000 chars
            return {
                "statusCode": 200,
                "body": f"Agent invoked successfully for file: {key}"
            }
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        print(f"HTTP error {e.code}: {error_body}")
        raise
    except Exception as e:
        print(f"Error invoking agent: {str(e)}")
        raise
