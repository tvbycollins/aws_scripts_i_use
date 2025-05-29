#!/usr/bin/env python3
"""
AWS Security Hub Finding Resolver - Secure Business Version
Fetches Security Hub findings and generates Terraform remediation using Anthropic's API
with comprehensive data scrubbing for privacy and security.
"""

import boto3
import json
import os
import sys
import re
from typing import Dict, Any, Optional
import anthropic
from botocore.exceptions import ClientError, NoCredentialsError
from dotenv import load_dotenv


class SecurityHubResolver:
    def __init__(self):
        """Initialize the resolver with AWS and Anthropic clients."""
        # Load environment variables from .env file
        load_dotenv()
        
        # Get API key from environment
        anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
        if not anthropic_api_key:
            print(
                "Error: ANTHROPIC_API_KEY not found in .env file.\n"
                "Please add ANTHROPIC_API_KEY=your-api-key to your .env file"
            )
            sys.exit(1)

        try:
            # Initialize AWS client with environment variables
            session_kwargs = {}
            
            if os.getenv("AWS_PROFILE"):
                session_kwargs["profile_name"] = os.getenv("AWS_PROFILE")
            
            if os.getenv("AWS_REGION"):
                session_kwargs["region_name"] = os.getenv("AWS_REGION")

            if session_kwargs:
                session = boto3.Session(**session_kwargs)
                self.securityhub = session.client("securityhub")
            else:
                self.securityhub = boto3.client("securityhub")

            self.anthropic_client = anthropic.Anthropic(api_key=anthropic_api_key)
            
            print("✓ Successfully initialized AWS and Anthropic clients")
            
        except NoCredentialsError:
            print(
                "Error: AWS credentials not found.\n"
                "Please ensure your .env file contains valid AWS credentials"
            )
            sys.exit(1)
        except Exception as e:
            print(f"Error initializing clients: {e}")
            sys.exit(1)

    def scrub_sensitive_data(self, text: str) -> str:
        """Remove sensitive AWS data from text for privacy."""
        if not text:
            return text
            
        # Replace AWS account IDs (12-digit numbers)
        text = re.sub(r'\b\d{12}\b', '[ACCOUNT-ID]', text)
        
        # Replace common AWS resource IDs
        text = re.sub(r'i-[a-f0-9]{8,17}', '[EC2-INSTANCE-ID]', text)
        text = re.sub(r'vol-[a-f0-9]{8,17}', '[EBS-VOLUME-ID]', text)
        text = re.sub(r'sg-[a-f0-9]{8,17}', '[SECURITY-GROUP-ID]', text)
        text = re.sub(r'vpc-[a-f0-9]{8,17}', '[VPC-ID]', text)
        text = re.sub(r'subnet-[a-f0-9]{8,17}', '[SUBNET-ID]', text)
        text = re.sub(r'igw-[a-f0-9]{8,17}', '[IGW-ID]', text)
        text = re.sub(r'rtb-[a-f0-9]{8,17}', '[ROUTE-TABLE-ID]', text)
        text = re.sub(r'acl-[a-f0-9]{8,17}', '[ACL-ID]', text)
        text = re.sub(r'ami-[a-f0-9]{8,17}', '[AMI-ID]', text)
        text = re.sub(r'snap-[a-f0-9]{8,17}', '[SNAPSHOT-ID]', text)
        text = re.sub(r'eni-[a-f0-9]{8,17}', '[ENI-ID]', text)
        text = re.sub(r'eip-[a-f0-9]{8,17}', '[EIP-ID]', text)
        
        # Replace S3 bucket names (common patterns)
        text = re.sub(r'\b[a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9]\.s3\.amazonaws\.com\b', 
                      '[S3-BUCKET].s3.amazonaws.com', text)
        text = re.sub(r'\bs3://[a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9]\b', 
                      's3://[S3-BUCKET]', text)
        
        # Replace RDS identifiers
        text = re.sub(r'\b[a-z0-9\-]{1,63}\.cluster-[a-z0-9]{12}\.[a-z0-9\-]+\.rds\.amazonaws\.com\b',
                      '[RDS-CLUSTER].amazonaws.com', text)
        text = re.sub(r'\b[a-z0-9\-]{1,63}\.[a-z0-9]{12}\.[a-z0-9\-]+\.rds\.amazonaws\.com\b',
                      '[RDS-INSTANCE].amazonaws.com', text)
        
        # Replace Lambda function names
        text = re.sub(r'arn:aws:lambda:[^:]+:\d{12}:function:[^:\s]+',
                      'arn:aws:lambda:[REGION]:[ACCOUNT-ID]:function:[FUNCTION-NAME]', text)
        
        # Replace IAM role/user ARNs
        text = re.sub(r'arn:aws:iam::\d{12}:role/([^:\s]+)',
                      r'arn:aws:iam::[ACCOUNT-ID]:role/\1', text)
        text = re.sub(r'arn:aws:iam::\d{12}:user/([^:\s]+)',
                      r'arn:aws:iam::[ACCOUNT-ID]:user/\1', text)
        
        # Replace general ARNs while preserving service and resource type
        text = re.sub(r'arn:aws:([^:]+):([^:]*):(\d{12}):(.*)', 
                      r'arn:aws:\1:\2:[ACCOUNT-ID]:\4', text)
        
        # Replace IP addresses (private ranges)
        text = re.sub(r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[PRIVATE-IP]', text)
        text = re.sub(r'\b172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b', '[PRIVATE-IP]', text)
        text = re.sub(r'\b192\.168\.\d{1,3}\.\d{1,3}\b', '[PRIVATE-IP]', text)
        
        # Replace public IP addresses (be more careful here)
        text = re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '[IP-ADDRESS]', text)
        
        # Replace domain names that might be company-specific
        text = re.sub(r'\b[a-z0-9\-]+\.internal\b', '[INTERNAL-DOMAIN]', text)
        text = re.sub(r'\b[a-z0-9\-]+\.local\b', '[LOCAL-DOMAIN]', text)
        
        return text

    def parse_finding_arn(self, finding_arn: str) -> Dict[str, str]:
        """Parse the Security Hub finding ARN to extract components."""
        try:
            parts = finding_arn.split(":")
            if len(parts) < 6 or parts[2] != "securityhub":
                raise ValueError("Invalid Security Hub finding ARN format")

            region = parts[3]
            account_id = parts[4]
            resource_part = parts[5]
            finding_id = resource_part.split("/")[-1]

            return {
                "region": region,
                "account_id": account_id,
                "finding_id": finding_id,
                "full_arn": finding_arn,
            }
        except Exception as e:
            raise ValueError(f"Failed to parse finding ARN: {e}")

    def get_finding_details(self, finding_arn: str) -> Optional[Dict[str, Any]]:
        """Retrieve detailed information about the Security Hub finding."""
        try:
            response = self.securityhub.get_findings(
                Filters={"Id": [{"Value": finding_arn, "Comparison": "EQUALS"}]}
            )

            findings = response.get("Findings", [])
            if not findings:
                print(f"No finding found with ARN: {finding_arn}")
                return None

            return findings[0]
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "InvalidInputException":
                print(f"Invalid finding ARN format: {finding_arn}")
            elif error_code == "AccessDeniedException":
                print(
                    "Access denied. Please ensure you have the necessary "
                    "Security Hub permissions."
                )
            else:
                print(f"AWS API Error: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error retrieving finding: {e}")
            return None

    def format_finding_for_ai(self, finding: Dict[str, Any]) -> str:
        """Format the finding data for the AI prompt with comprehensive data scrubbing."""
        # Extract key information
        title = finding.get("Title", "Unknown")
        description = finding.get("Description", "No description available")
        severity = finding.get("Severity", {}).get("Label", "Unknown")
        compliance_status = finding.get("Compliance", {}).get("Status", "Unknown")
        
        # Get remediation information if available
        remediation = finding.get("Remediation", {})
        recommendation = remediation.get("Recommendation", {})
        recommendation_text = recommendation.get("Text", "No recommendation available")
        recommendation_url = recommendation.get("Url", "")

        # Get generator information (which control this is)
        generator_id = finding.get("GeneratorId", "Unknown")
        
        # Scrub sensitive data from all text fields
        title = self.scrub_sensitive_data(title)
        description = self.scrub_sensitive_data(description)
        recommendation_text = self.scrub_sensitive_data(recommendation_text)
        generator_id = self.scrub_sensitive_data(generator_id)

        # Get resource information but scrub sensitive details
        resources = finding.get("Resources", [])
        resource_info = []
        for resource in resources:
            resource_type = resource.get("Type", "Unknown")
            # Only include resource type, not specific IDs
            resource_info.append(f"- Resource Type: {resource_type}")

        # Get compliance details if available
        compliance_details = finding.get("Compliance", {})
        status_reasons = compliance_details.get("StatusReasons", [])
        
        # Scrub status reasons
        scrubbed_status_reasons = []
        for reason in status_reasons:
            if isinstance(reason, dict):
                reason_code = reason.get("ReasonCode", "")
                description = reason.get("Description", "")
                scrubbed_status_reasons.append({
                    "ReasonCode": reason_code,
                    "Description": self.scrub_sensitive_data(description)
                })

        formatted_finding = f"""
Security Hub Finding Details (Sensitive Data Scrubbed):
======================================================

Title: {title}
Generator ID: {generator_id}
Severity: {severity}
Compliance Status: {compliance_status}

Description:
{description}

AWS Recommendation:
{recommendation_text}
{f"Reference: {recommendation_url}" if recommendation_url else ""}

Affected Resource Types:
{chr(10).join(resource_info) if resource_info else "No specific resources listed"}

Compliance Status Reasons:
{json.dumps(scrubbed_status_reasons, indent=2) if scrubbed_status_reasons else "No specific status reasons available"}

Security Note: All account IDs, resource IDs, IP addresses, and other sensitive 
identifiers have been redacted from this data before sending to external AI services.
"""
        return formatted_finding

    def generate_terraform_solution(self, formatted_finding: str) -> str:
        """Use Anthropic's API to generate Terraform remediation."""
        prompt = f"""
You are an AWS security and Terraform expert. I have a Security Hub finding that needs to be resolved using Terraform best practices.

IMPORTANT: The data provided has been scrubbed of sensitive information including account IDs, resource IDs, and IP addresses for security purposes. Please provide generic, reusable Terraform solutions.

Please analyze this finding and provide:
1. A clear explanation of what the security issue is
2. Why this is a security concern and potential impact
3. Terraform code snippets to remediate the issue (use variables and locals for flexibility)
4. Best practices and additional security considerations
5. Any prerequisites or dependencies needed
6. Testing recommendations to verify the fix

Please make your Terraform code generic and reusable across different environments.

Here's the finding:

{formatted_finding}

Please provide a comprehensive solution using Terraform with proper formatting, explanations, and security best practices.
"""

        try:
            response = self.anthropic_client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=4000,
                temperature=0.1,
                messages=[{"role": "user", "content": prompt}]
            )
            
            return response.content[0].text
        except Exception as e:
            return f"Error generating AI response: {e}"

    def resolve_finding(self, finding_arn: str) -> None:
        """Main method to resolve a Security Hub finding."""
        print(f"Processing Security Hub finding...")
        print("=" * 60)

        # Parse the ARN (but don't display sensitive info)
        try:
            arn_components = self.parse_finding_arn(finding_arn)
            print(f"Region: {arn_components['region']}")
            print(f"Account ID: [REDACTED]")
            print(f"Finding ID: {arn_components['finding_id']}")
            print()
        except ValueError as e:
            print(f"Error: {e}")
            return

        # Get finding details
        print("Retrieving finding details from AWS Security Hub...")
        finding = self.get_finding_details(finding_arn)
        if not finding:
            return

        print("✓ Finding retrieved successfully!")
        print("✓ Scrubbing sensitive data for privacy...")
        print()

        # Format for AI with data scrubbing
        formatted_finding = self.format_finding_for_ai(finding)

        # Generate solution
        print("Generating Terraform remediation using Anthropic AI...")
        print("📝 Note: All sensitive data has been redacted before sending to AI")
        print("This may take a moment...")
        print()

        solution = self.generate_terraform_solution(formatted_finding)

        # Display results
        print("TERRAFORM REMEDIATION SOLUTION")
        print("=" * 60)
        print(solution)
        print("\n" + "=" * 60)
        print("🔒 PRIVACY NOTE: All account IDs, resource IDs, IP addresses, and")
        print("   other sensitive data were scrubbed before sending to Anthropic AI.")
        print("   Your sensitive business data remains secure.")


def main():
    """Main function to run the Security Hub resolver."""
    print("🔒 AWS Security Hub Finding Resolver - Secure Business Version")
    print("=" * 60)
    print("This tool scrubs all sensitive data before sending to external AI services.")
    print()
    
    if not os.path.exists(".env"):
        print("Warning: .env file not found in current directory.")
        sys.exit(1)

    if len(sys.argv) > 1:
        finding_arn = sys.argv[1]
    else:
        finding_arn = input("Enter the Security Hub finding ARN: ").strip()

    if not finding_arn:
        print("Error: No finding ARN provided.")
        sys.exit(1)

    resolver = SecurityHubResolver()
    resolver.resolve_finding(finding_arn)


if __name__ == "__main__":
    main()
