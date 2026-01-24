# Enhanced Security Testing Guide

## Overview

The threat model tool now supports in-depth security testing documentation directly in your threat models. This feature allows you to:

- **Document detailed replication steps** - Step-by-step instructions to reproduce the threat
- **Include test scripts** - Automated scripts in bash, Python, PowerShell, or other languages
- **Define prerequisites** - What's needed before testing can begin
- **Specify expected behaviors** - What happens when vulnerable vs. mitigated
- **List recommended tools** - Security tools useful for testing

## Why Enhanced Testing?

This enhancement prepares your threat models for:
- **Automated security validation** - Scripts can be extracted and executed
- **LLM integration** - Future integration with Meta Llama or other LLMs to generate test content
- **Penetration testing** - Provides pentesters with actionable test cases
- **Security training** - Teaches teams how to validate threats
- **Continuous testing** - Scripts can be integrated into CI/CD pipelines

## YAML Schema Extensions

### New Fields in Threats

```yaml
threats:
  - ID: "T1"
    title: "Threat Title"
    # ... existing fields ...
    
    # Enhanced Testing Fields (all optional)
    testPrerequisites:
      - "First prerequisite (e.g., 'AWS account with S3 buckets')"
      - "Second prerequisite (e.g., 'AWS CLI configured')"
    
    testSteps:
      - "Step 1: Detailed instruction"
      - "Step 2: Another instruction"
      - "Step N: Final step"
    
    testScripts:
      - language: "bash"  # or python, powershell, curl, etc.
        description: "What this script does"
        code: |
          #!/bin/bash
          # Your script here
          echo "Testing..."
        requirements:
          - "bash"
          - "curl"
          - "jq"
      
      - language: "python"
        description: "Python alternative"
        code: |
          import boto3
          # Your Python code
        requirements:
          - "boto3"
          - "python3"
    
    testTools:
      - "Burp Suite"
      - "AWS CLI"
      - "Custom tool name"
    
    expectedBehavior: "Description of what happens when the system is vulnerable to this threat"
    
    expectedMitigation: "Description of what happens when mitigations are properly implemented"
```

## Example: S3 Bucket Misconfiguration

```yaml
  - ID: "T1"
    title: "Misconfigured Public Access"
    threatType: "Information Disclosure"
    attack: "Attacker discovers the bucket allows 'Principal: *'"
    impactDesc: "Breach of customer PII"
    impactedSecObj: ["Confidentiality"]
    CVSS:
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
      score: 7.5
      severity: "High"
    
    # Enhanced Testing
    testPrerequisites:
      - "AWS account with S3 buckets"
      - "AWS CLI configured with appropriate credentials"
      - "Target bucket name"
    
    testSteps:
      - "Identify the target S3 bucket name through reconnaissance"
      - "Check bucket ACL: aws s3api get-bucket-acl --bucket BUCKET_NAME"
      - "Check bucket policy: aws s3api get-bucket-policy --bucket BUCKET_NAME"
      - "Attempt unauthenticated access: aws s3 ls s3://BUCKET_NAME --no-sign-request"
      - "Document findings including exposed files"
    
    testScripts:
      - language: "bash"
        description: "Quick script to test for public S3 bucket access"
        code: |
          #!/bin/bash
          BUCKET_NAME="$1"
          echo "[*] Testing bucket: $BUCKET_NAME"
          aws s3 ls s3://$BUCKET_NAME --no-sign-request 2>&1
          aws s3api get-bucket-acl --bucket $BUCKET_NAME 2>&1
        requirements:
          - "aws-cli"
          - "bash"
    
    testTools:
      - "AWS CLI"
      - "s3scanner"
      - "bucket-stream"
    
    expectedBehavior: "If publicly accessible, AWS CLI will list and download objects without authentication"
    
    expectedMitigation: "Access should be denied with 'AccessDenied' error. Block Public Access should be enabled."
```

## Report Features

The generated HTML reports will display:

### 1. Prerequisites Section
- Orange-highlighted box with required setup
- Bullet list of prerequisites
- Helps testers prepare their environment

### 2. Expected Behavior Cards
- **Vulnerable Behavior** (red card) - What happens if the threat is exploitable
- **Expected When Mitigated** (green card) - What happens when protections work
- Side-by-side comparison

### 3. Detailed Replication Steps
- Numbered step-by-step instructions
- Falls back to generic STRIDE-based steps if not provided
- Clear, actionable guidance

### 4. Test Scripts Section
- Syntax-highlighted code blocks
- Language badge (bash, python, powershell, etc.)
- One-click copy button
- Requirements listed below each script
- Script description explaining purpose

### 5. Recommended Tools
- Visual tags for each tool
- Custom tools or standard security tools
- Falls back to STRIDE-based tool recommendations

## Best Practices

### Writing Test Steps
- **Be specific**: Include exact commands, parameters, and expected outputs
- **Include variations**: Show different ways to test (manual + automated)
- **Document errors**: What error messages indicate success/failure
- **Safety first**: Include warnings about destructive actions

### Writing Test Scripts
- **Keep them focused**: One script per test approach
- **Make them portable**: Use parameters, avoid hardcoded values
- **Include error handling**: Check prerequisites, handle failures gracefully
- **Comment thoroughly**: Explain what each section does
- **Test them**: Actually run your scripts before committing

### Choosing Languages
- **bash**: Quick CLI-based tests, file operations, pipe processing
- **python**: Complex logic, API interactions, data processing
- **powershell**: Windows environments, Azure, Active Directory
- **curl**: Simple HTTP/API tests, webhook testing
- **javascript/node**: Web application testing, browser automation

## Future LLM Integration

This structure is designed for LLM enhancement:

```yaml
# Minimal threat definition
  - ID: "T1"
    title: "SQL Injection in Login Form"
    attack: "Attacker submits malicious SQL in username field"
    
# LLM (Meta Llama) will generate:
# - testPrerequisites
# - testSteps
# - testScripts (in multiple languages)
# - testTools
# - expectedBehavior
# - expectedMitigation
```

### LLM Prompt Template
```
Given this threat:
- Title: {threat.title}
- Attack: {threat.attack}
- Impact: {threat.impactDesc}
- STRIDE Category: {threat.impactedSecObj}

Generate:
1. List of prerequisites needed to test this threat
2. Detailed step-by-step replication instructions
3. A bash script to automate testing
4. A python script as an alternative
5. Expected behavior when vulnerable
6. Expected behavior when properly mitigated
7. List of recommended security testing tools
```

## Migration Guide

### Converting Existing Threat Models

Your existing threat models will continue to work without changes. The new fields are optional.

To enhance an existing threat:
1. Open your threat-model.yaml
2. Find a threat you want to enhance
3. Add the new fields (see examples above)
4. Regenerate the report: `python -m src.cli report path/to/model`

### Gradual Adoption

You can enhance threats incrementally:
- Start with high-severity or frequently-tested threats
- Add testSteps first (easiest)
- Add testScripts for threats that benefit from automation
- Add full details for threats used in training/documentation

## Examples

See these files for complete examples:
- `threat-models/public-cloud-storage/threat-model.yaml` - S3 security tests
- `examples/enhanced-testing-example.yaml` - Comprehensive examples

## Troubleshooting

### Scripts not displaying
- Check YAML indentation (use spaces, not tabs)
- Ensure `code:` field uses `|` for multi-line strings
- Verify the language field matches your code

### Copy button not working
- Modern browsers required (Chrome, Firefox, Edge)
- HTTPS or localhost required for clipboard API
- Check browser console for JavaScript errors

### Prerequisites not showing
- Ensure `testPrerequisites` is a list (use `-` for each item)
- Check YAML syntax with a validator

## Contributing

To propose new testing-related features:
1. Consider the LLM integration use case
2. Keep the schema simple and intuitive
3. Ensure backward compatibility
4. Test with real threat models
5. Update this documentation

## Schema Reference

### TestScript Object
```yaml
language: string        # Required: bash, python, powershell, curl, etc.
description: string     # Optional: What the script does
code: string           # Required: The actual script code
requirements: [string] # Optional: List of dependencies
```

### Threat Testing Fields
```yaml
testPrerequisites: [string]   # Optional: List of prerequisites
testSteps: [string]            # Optional: Ordered list of steps
testScripts: [TestScript]      # Optional: List of test scripts
testTools: [string]            # Optional: Recommended tools
expectedBehavior: string       # Optional: Vulnerable behavior
expectedMitigation: string     # Optional: Mitigated behavior
```

All fields are optional and fall back to sensible defaults based on STRIDE categories.
