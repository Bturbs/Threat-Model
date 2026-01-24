# Threat Model Tool

A streamlined threat modeling platform that stores threat model data as YAML files and generates professional security reports with interactive visualizations.

## Features

- **YAML-based threat model definitions** with Pydantic schema validation
- **Automatic CVSS 3.1 score calculation** from vector strings
- **Interactive HTML reports** with multi-model navigation
- **Attack tree visualization** using Mermaid.js with threat-to-mitigation mapping
- **PlantUML Data Flow Diagrams** with component and sequence views
- **Batch report generation** for multiple threat models
- **Enhanced Security Testing** - Detailed replication steps, test scripts, and automation-ready test cases
- **Clean, production-ready output** - No deprecated code or unused features

## Installation

### Prerequisites

- Python 3.11 or higher

### Install Dependencies

```bash
pip install -r requirements.txt
```

Or install the package in development mode:

```bash
pip install -e .
```

### Required Python Packages

- PyYAML - YAML parsing
- Jinja2 - HTML template rendering
- Pydantic - Schema validation
- Click - Command line interface
- cvss - CVSS score calculation

## Project Structure

```
threat-model-tool/
    src/
        schemas.py          # Pydantic models with enhanced testing support
        parser.py           # YAML parsing and validation
        report_generator.py # HTML report generation
        dfd_generator.py    # PlantUML diagram generation
        attack_tree.py      # Mermaid.js attack tree generation
        cvss_calculator.py  # CVSS score calculation
        cli.py              # Command line interface
        templates/
            report.html     # Main HTML report template
            macros/
                diagrams.html  # Reusable diagram components
    threat-models/
        <model-name>/
            threat-model.yaml   # Single-file YAML format
            reports/
                threat-model.html
    examples/
        enhanced-testing-guide.md      # Testing documentation
        enhanced-testing-examples.yaml # Example threat models
```

## Usage

### Validate a Threat Model

Check that your YAML file is correctly structured:

```bash
python -m src.cli validate threat-models/my-app
```

### Generate an HTML Report

Generate a single HTML report:

```bash
python -m src.cli report threat-models/my-app
```

### Generate Reports for All Models

Generate reports for all threat models in a directory:

```bash
python -m src.cli batch threat-models/
```

This will discover all threat models and generate reports with cross-navigation.

## Threat Model YAML Format

### Complete Example

Create a `threat-model.yaml` file with this structure:

```yaml
meta:
  title: "E-Commerce Platform"
  modelId: "ecommerce"
  version: "1.0"
  scope: "Customer-facing web application and backend services"
  owner: "Security Team"
  lastUpdated: "2026-01-24"

assets:
  - ID: WEB_APP
    name: "Web Application"
    type: Client
    description: "Frontend web application"
    trustZone: DMZ
    dataFlows:
      - ID: DF_WEB_TO_API
        name: "API Requests"
        source: WEB_APP
        destination: API_SERVICE
        protocol: "HTTPS"
        dataClassification: "Internal"
        crossesTrustBoundary: true

  - ID: API_SERVICE
    name: "API Service"
    type: Serverless Service
    description: "Backend API service"
    trustZone: Internal
    dataFlows:
      - ID: DF_API_TO_DB
        name: "Database Queries"
        source: API_SERVICE
        destination: DATABASE
        protocol: "PostgreSQL/TLS"
        dataClassification: "Confidential"
        crossesTrustBoundary: false

  - ID: DATABASE
    name: "PostgreSQL Database"
    type: Database
    description: "Primary data store"
    trustZone: Internal
    dataFlows: []

attackers:
  - REFID: EXTERNAL_ATTACKER
    name: "External Attacker"
    description: "Malicious actor with no prior system access"
    motivation: "Financial gain, data theft"
    capability: "High"

securityObjectives:
  - ID: SO_CONF
    name: "Data Confidentiality"
    description: "Sensitive data must not be disclosed to unauthorized parties"
    category: "CIA"

  - ID: SO_INT
    name: "Data Integrity"
    description: "Data must not be modified without authorization"
    category: "CIA"

threats:
  - ID: T-01
    title: "SQL Injection Attack"
    attack: "Attacker injects malicious SQL through user input fields"
    threatType: "Injection"
    impactDesc: "Database compromise, data exfiltration"
    impactedSecObj:
      - SO_CONF
      - SO_INT
    attackers:
      - EXTERNAL_ATTACKER
    CVSS:
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
      score: 8.2
      severity: "High"
    fullyMitigated: false
    
    # Enhanced Security Testing Fields
    testPrerequisites:
      - "Access to application login/search forms"
      - "Burp Suite or SQLMap installed"
    testSteps:
      - "Identify input fields that query the database"
      - "Submit payload: ' OR '1'='1"
      - "Observe if SQL error messages are returned"
      - "Attempt to extract data using UNION-based injection"
    testTools:
      - "Burp Suite"
      - "SQLMap"
    expectedBehavior: "Application returns SQL error or bypasses authentication"
    expectedMitigation: "Input rejected, parameterized queries prevent execution"
    
    countermeasures:
      - ID: CM_01
        title: "Parameterized Queries"
        description: "Use parameterized queries for all database operations"
        status: in_place

      - ID: CM_02
        title: "Input Validation"
        description: "Validate and sanitize all user inputs"
        status: planned
```

### Key Schema Fields

**Countermeasure Status:**
- `in_place` - Control is implemented
- `planned` - Control is planned
- `not_started` - Control not yet started

**CVSS Scoring:**
- Provide CVSS 3.1 vector string
- Tool auto-calculates score (0.0-10.0) and severity (Low/Medium/High/Critical)

**Enhanced Testing Fields (Optional):**
- `testPrerequisites` - Required setup before testing
- `testSteps` - Step-by-step replication instructions
- `testScripts` - Executable code (bash, Python, PowerShell, curl)
- `testTools` - Recommended security tools
- `expectedBehavior` - What happens when vulnerable
- `expectedMitigation` - What happens when mitigated

## HTML Reports

Generated reports include:

- **Overview** - Model metadata, statistics, and CVSS severity breakdown
- **Attack Tree** - Interactive Mermaid.js visualization with color-coded severity
- **Data Flow Diagrams** - PlantUML component and sequence views
- **Threat Details** - Comprehensive threat listings with testing documentation
- **Countermeasures** - Status tracking and implementation roadmap
- **Multi-Model Navigation** - Sidebar for switching between threat models

Reports are responsive, print-friendly, and saved to `<model-path>/reports/threat-model.html`.

## Included Threat Models

The repository includes several example threat models:

- **AI Cloud Native Estate** - Cloud-based AI platform security
- **BYOD Architecture** - Bring Your Own Device access controls
- **BYOD Remote Work** - Remote work security scenarios
- **Public Cloud Storage** - S3 bucket security with testing examples
- **Serverless Upload Platform** - Event-driven file processing security

Use these as templates or learning examples.

## Command Reference

| Command | Description |
|---------|-------------|
| `validate <path>` | Validate threat model YAML structure and schema |
| `report <path>` | Generate HTML report for a single threat model |
| `batch <root>` | Generate reports for all threat models in directory |

### Common Options

- `-o, --output` - Specify output file path for reports
- `-v, --verbose` - Enable verbose logging (detailed validation messages)

## Creating Threat Models with AI

You can use cloud-based AI (ChatGPT, Claude, Copilot) or run Llama locally in VS Code for completely private threat modeling.

### Option 1: Using Llama Locally in VS Code (Private & Free)

Run Meta's Llama models directly on your machine for complete privacy when working with sensitive architecture documents.

#### 1. Install Ollama

**Windows:**
1. Download Ollama from [ollama.com/download](https://ollama.com/download)
2. Run the installer
3. Verify installation:
   ```powershell
   ollama --version
   ```

**macOS/Linux:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

#### 2. Download Llama Model

Pull a Llama model (recommend Llama 3.2 3B for speed or Llama 3.1 8B for quality):

```powershell
# Fast, runs on most hardware (3GB)
ollama pull llama3.2

# Higher quality, needs 8GB+ RAM
ollama pull llama3.1:8b

# Best quality, needs 16GB+ RAM
ollama pull llama3.1:70b
```

Test the model:
```powershell
ollama run llama3.2
```

Type a message to verify it works, then use `/bye` to exit.

#### 3. Install Continue Extension in VS Code

1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "Continue"
4. Install "Continue - Codestral, Claude, and more"
5. Restart VS Code

#### 4. Configure Continue to Use Ollama

1. Open Continue sidebar (Ctrl+L or click the Continue icon)
2. Click the gear icon (⚙️) to open config
3. This opens `~/.continue/config.json`
4. Replace the content with:

```json
{
  "models": [
    {
      "title": "Llama 3.2 (Local)",
      "provider": "ollama",
      "model": "llama3.2"
    }
  ],
  "tabAutocompleteModel": {
    "title": "Llama 3.2",
    "provider": "ollama",
    "model": "llama3.2"
  },
  "embeddingsProvider": {
    "provider": "ollama",
    "model": "nomic-embed-text"
  }
}
```

5. Save and close

#### 5. Generate Threat Models with Llama

**From Design Document:**

1. Open your architecture document in VS Code
2. Select the entire document
3. Press Ctrl+L to open Continue
4. Use this prompt:

```
@README.md Using the YAML schema in this README, create a threat-model.yaml for the selected architecture document.

Generate a complete threat model with:
- Assets with realistic data flows
- Trust zones and boundaries
- Security objectives
- 8-12 threats with CVSS 3.1 vectors
- Countermeasures with status
- Testing steps (testPrerequisites, testSteps, expectedBehavior)

Focus on STRIDE threats appropriate for this architecture.
```

**From Teams Transcript:**

1. Save your Teams transcript as `.txt` file
2. Open it in VS Code
3. Select all (Ctrl+A)
4. Press Ctrl+L
5. Use this prompt:

```
@README.md Analyze this Teams meeting transcript and create a threat-model.yaml using the schema in README.

Extract:
- System components discussed → Assets
- Technology stack mentioned
- Security concerns raised
- Existing controls mentioned

Generate realistic threats with CVSS scores and testing steps.
```

**Tips for Better Results:**

- **Use @README.md** to give Llama access to the YAML schema
- **Be specific about technology stack** - "React + Node.js + PostgreSQL" vs "web app"
- **Mention compliance** - "Must be PCI-DSS compliant" helps with relevant threats
- **Ask for explanations** - "Explain why each CVSS score is appropriate"
- **Iterate** - First generate threats, then ask "Add 5 more threats for the database layer"

#### 6. Save and Validate

1. Copy Llama's output
2. Save as `threat-models/my-system/threat-model.yaml`
3. Validate:
   ```bash
   python -m src.cli validate threat-models/my-system
   ```
4. Fix any validation errors (Llama may need guidance on exact format)
5. Generate report:
   ```bash
   python -m src.cli report threat-models/my-system
   ```

**Privacy Note:** With Ollama + Continue, everything runs locally. Your architecture documents and threat models never leave your machine.

### Option 2: Cloud AI (ChatGPT, Claude, Copilot)

If you prefer cloud AI or need higher quality outputs:

### Quick Workflow

1. **Gather Context**
   - System design document
   - Architecture diagrams
   - Meeting transcripts about security requirements

2. **Use AI with This Prompt Template**

   ```
   I have a threat modeling tool using this YAML schema:
   
   [Copy the YAML format example from this README]
   
   Please create a threat-model.yaml for this system:
   
   [Paste your design document or transcript]
   
   Generate a complete threat model with:
   - Assets with data flows and trust zones
   - Security objectives (Confidentiality, Integrity, Availability)
   - Threats with CVSS 3.1 vectors (calculate realistic scores)
   - Countermeasures with implementation status
   - Testing steps for each threat (testPrerequisites, testSteps, expectedBehavior)
   ```

3. **Save and Generate**
   ```bash
   # Create directory
   mkdir -p threat-models/my-system
   
   # Save AI output as threat-model.yaml
   # Validate
   python -m src.cli validate threat-models/my-system
   
   # Generate report
   python -m src.cli report threat-models/my-system
   ```

### Example AI Prompts

**For Cloud Architecture:**
```
Create a threat model for a serverless file upload platform using:
- React SPA (frontend)
- API Gateway + Lambda (backend)
- S3 (storage)
- DynamoDB (metadata)

Include threats like: malware upload, unauthorized access, DoS, data leakage.
Add testSteps for each threat.
```

**For BYOD/Zero Trust:**
```
Create a threat model for enterprise BYOD architecture with:
- Personal devices accessing corporate resources
- Azure AD (identity)
- Intune (device management)
- Conditional access policies

Focus on: credential theft, device spoofing, data leakage, compliance bypass.
```

### Tips for Better AI Output

- **Be specific about technology stack** - Naming actual products helps AI suggest realistic threats
- **Mention compliance needs** - GDPR, PCI-DSS, HIPAA context improves threat relevance
- **List existing controls** - AI will mark them as `in_place` status
- **Request CVSS scores** - Ask AI to calculate and justify scores
- **Ask for testing content** - Explicitly request testSteps and expectedBehavior fields

## Enhanced Security Testing

The tool supports comprehensive security testing documentation for penetration testing, security automation, and training.

### Testing Schema

```yaml
threats:
  - ID: "T-01"
    title: "SQL Injection in Login"
    # ... standard fields ...
    
    # Testing fields
    testPrerequisites:
      - "Burp Suite installed"
      - "Access to login form"
    
    testSteps:
      - "Intercept POST request to /login"
      - "Modify username parameter to: admin' OR '1'='1"
      - "Observe authentication bypass"
    
    testScripts:
      - language: "bash"
        description: "Automated SQLi test"
        code: |
          curl -X POST https://target/login \
            -d "user=admin' OR '1'='1&pass=x"
        requirements: ["curl"]
    
    testTools:
      - "Burp Suite"
      - "SQLMap"
    
    expectedBehavior: "Authentication succeeds without valid password"
    expectedMitigation: "Request blocked, error logged"
```

### Use Cases

- **Pen Testing** - Exact replication steps for security assessments
- **CI/CD Integration** - Extract testScripts for automated security testing
- **Training** - Teach teams to validate threats hands-on
- **Documentation** - Maintain runbooks for security verification

### Resources

- [Enhanced Testing Guide](examples/enhanced-testing-guide.md) - Complete documentation
- [Testing Examples](examples/enhanced-testing-examples.yaml) - SQL injection, XSS, rate limiting examples
- [Public Cloud Storage Model](threat-models/public-cloud-storage/threat-model.yaml) - S3 security testing


---

**Questions or Issues?** Open an issue on GitHub or consult the example threat models in `threat-models/` directory.

