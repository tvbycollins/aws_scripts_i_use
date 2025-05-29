# AWS Security Hub Finding Resolver - Secure Business Version

A secure Python tool that fetches AWS Security Hub findings and generates Terraform remediation solutions using Anthropic's Claude AI. This tool prioritizes data privacy by scrubbing all sensitive information before sending to external AI services.

## 🔒 Security Features

- **Comprehensive Data Scrubbing**: All account IDs, resource IDs, IP addresses, and sensitive identifiers are redacted before sending to AI
- **Privacy-First Design**: No sensitive business data leaves your environment
- **Audit Trail**: Clear indication of what data is processed and scrubbed
- **Business-Safe**: Designed for enterprise use with security compliance in mind

## 📋 Prerequisites

- Python 3.7 or higher
- AWS Access Key and Secret Key with appropriate permissions
- Anthropic API key
- AWS Security Hub enabled in your account

## 📦 Required Files

### requirements.txt
Create this file with the following dependencies:

```txt
boto3>=1.34.0
anthropic>=0.25.0
botocore>=1.34.0
python-dotenv>=1.0.0
```

### .env file
Create this file in the same directory as the script:

```env
# Required: Anthropic API Key
ANTHROPIC_API_KEY=your-anthropic-api-key-here

# Required: AWS Credentials
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=your-secret-access-key
AWS_REGION=us-east-1
```

## 🔑 Getting Your API Keys

### Anthropic API Key
1. Go to [Anthropic Console](https://console.anthropic.com/)
2. Sign up or log in
3. Navigate to API Keys
4. Create a new API key
5. Copy the key (starts with `sk-ant-api03-`)

### AWS Credentials
1. Go to AWS Console → IAM → Users → Your User
2. Security Credentials tab
3. Create Access Key → Command Line Interface
4. Download or copy the Access Key ID and Secret Access Key

## 🛡️ Required AWS Permissions

Your AWS user/role needs these minimum permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "securityhub:GetFindings",
                "securityhub:DescribeHub"
            ],
            "Resource": "*"
        }
    ]
}
```
