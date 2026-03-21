# Threat Model Generation Prompt

You are an expert security architect tasked with generating a comprehensive threat model YAML file. 

**IMPORTANT:** Assets have been provided separately. Your task is to generate:
1. Security objectives
2. Attackers/threat actors
3. Threats (with detailed testing information)
4. All countermeasures with implementation guidance

---

## Input: System Context

You will be provided with:
- System/application name, description, and scope
- Key architectural components and data flows
- Assumptions and constraints
- Stakeholders and business context
- A list of assets (DO NOT REGENERATE THESE - they are provided separately)

---

## Output: Complete YAML Threat Model

Generate a `threat-model.yaml` file with the following structure:

### 1. Meta Information
```yaml
meta:
  title: "{{ System Name }}"
  modelId: "{{ Auto-generate: TM-<INITIALS>-<DATE> }}"
  version: "1.0"
  scope: "{{ From input, or synthesize from context }}"
  owner: "Security Team"
  lastUpdated: "{{ Today's date }}"
```

### 2. Diagrams (Optional)
If the context mentions architecture diagrams, PlantUML flows, or sequence diagrams AND you have verified the diagram files exist:
```yaml
diagrams:
  - id: "{{ DIAGRAM_01 }}"
    title: "{{ Descriptive name }}"
    file: "assets/{{ filename.puml }}"
    type: "{{ activity | sequence | component }}"
    placement: "before_attack_tree"
    description: "{{ What the diagram shows }}"
```

**Important:** Only include diagram entries if the referenced files actually exist in the project. If diagram files are mentioned but not provided, omit the diagrams section entirely or set `diagrams: []`. Missing diagram file references cause report generation warnings.

### 3. Assets (PROVIDED SEPARATELY - DO NOT GENERATE)
The `assets:` section is provided separately. Include it as-is in the output.

**Critical:** Assets include `dataFlows`. Ensure ALL dataFlow objects have the following required fields:
```yaml
dataFlows:
  - ID: "DF_EXAMPLE"
    name: "Client to Application"
    source: "A_CLIENT"          # Asset ID that originates the flow (REQUIRED)
    destination: "A_APP"        # Asset ID that receives the flow (REQUIRED)
    trustBoundary: false
    description: "{{ Description of data flow }}"
```

Every dataFlow **must** have:
- `source:` — The asset ID (e.g., A_CLIENT, A_AUTH0) that sends data
- `destination:` — The asset ID (e.g., A_APP, A_DB) that receives data

Missing source/destination fields will cause YAML validation errors. Always verify completeness when including the assets section.

### 4. Attackers / Threat Actors
Identify 3-5 distinct attacker personas relevant to the system:
```yaml
attackers:
  - REFID: "ATT_{{ ID }}"
    name: "{{ Descriptive name }}"
    description: "{{ Who they are and what they want }}"
    motivation: "{{ Why they target this system: financial gain, espionage, sabotage, etc. }}"
    capability: "{{ Low | Medium | High }}"
    
  - REFID: "ATT_INSIDER"
    name: "Malicious Insider"
    description: "{{ An employee or contractor with legitimate access }}"
    motivation: "{{ Sabotage, data theft, competitive intelligence }}"
    capability: "High"
```

### 5. Security Objectives
Define 4-6 security objectives aligned with CIA triad + Architecture/Governance:
```yaml
securityObjectives:
  - ID: "SO-CONF"
    name: "Confidentiality"
    description: "{{ Sensitive data is only accessible to authorized users }}"
    category: "CIA"
  
  - ID: "SO-INT"
    name: "Integrity"
    description: "{{ Data and system state cannot be tampered with }}"
    category: "CIA"
  
  - ID: "SO-AVAIL"
    name: "Availability"
    description: "{{ System remains operational and responsive }}"
    category: "CIA"
  
  - ID: "SO-AUTH"
    name: "Authentication & Authorization"
    description: "{{ Only authenticated and authorized users can access resources }}"
    category: "Access Control"
  
  - ID: "SO-AUDIT"
    name: "Auditability"
    description: "{{ All security-relevant actions are logged and traceable }}"
    category: "Governance"
  
  - ID: "SO-COMPLIANCE"
    name: "Regulatory Compliance"
    description: "{{ System meets applicable regulations (GDPR, HIPAA, SOC2, etc.) }}"
    category: "Governance"
```

### 6. Threats (Comprehensive)

For each significant threat to the system, generate:

```yaml
threats:
  - ID: "T_{{ NUMBER }}_{{ SHORT_CODE }}"
    title: "{{ Clear, concise threat title }}"
    threatType: "{{ STRIDE category: Spoofing | Tampering | Repudiation | Info Disclosure | DoS | Elevation of Privilege }}"
    
    attack: "{{ 2-3 sentence description of HOW the attack works }}"
    
    impactDesc: "{{ Concrete impact if successful: data breach, service outage, revenue loss, compliance violation, reputational damage }}"
    
    impactedSecObj:
      - "SO-CONF"
      - "SO-INT"
    
    attackers:
      - "ATT_EXTERNAL"
      - "ATT_INSIDER"
    
    CVSS:
      vector: "CVSS:3.1/AV:{{ N|A|L|P }}/AC:{{ L|H }}/PR:{{ N|L|H }}/UI:{{ N|R }}/S:{{ U|C }}/C:{{ N|L|H }}/I:{{ N|L|H }}/A:{{ N|L|H }}"
      score: {{ 0.0-10.0 }}
      severity: "{{ Critical | High | Medium | Low }}"
    
    fullyMitigated: false
    alwaysPresent: false
    
    # Enhanced Testing Fields (optional but highly recommended)
    testPrerequisites:
      - "{{ Prerequisite 1: test account, network access, tool setup, etc. }}"
      - "{{ Prerequisite 2 }}"
    
    testSteps:
      - "{{ Step 1: detailed, actionable replication step }}"
      - "{{ Step 2 }}"
      - "{{ Step N: verification step }}"
    
    testScripts:
      - language: "bash"
        description: "{{ What this script tests }}"
        code: |
          #!/bin/bash
          {{ Script code here }}
        requirements:
          - "{{ Required tool or package }}"
      
      - language: "python"
        description: "{{ Alternative or more detailed test }}"
        code: |
          {{ Python code }}
        requirements:
          - "{{ Required package }}"
    
    testTools:
      - "{{ Tool 1: Burp Suite, SQLMap, OWASP ZAP, etc. }}"
      - "{{ Tool 2 }}"
    
    expectedBehavior: "{{ What happens when the system is VULNERABLE to this threat }}"
    
    expectedMitigation: "{{ What should happen when proper MITIGATIONS are in place }}"
    
    # Countermeasures
    countermeasures:
      - ID: "CM_{{ ID }}_{{ NUMBER }}"
        title: "{{ Control name }}"
        description: "{{ How the control mitigates the threat }}"
        status: "{{ in_place | planned | not_started }}"
        effort: "{{ Low | Medium | High }}"
        why: "{{ Why this specific control addresses the threat }}"
        implementation:
          - "{{ Step 1: specific, actionable implementation step }}"
          - "{{ Step 2 }}"
          - "{{ Step 3 }}"
```

---

## Key Rules for Threat Generation

### Validation & Completeness
- **DataFlows:** Every dataFlow object must have `source:` and `destination:` fields pointing to valid asset IDs. Missing fields cause validation errors.
- **Diagrams:** Only include diagram references if files are confirmed to exist. Omit the section rather than reference non-existent files.
- **YAML syntax:** Validate proper indentation (2 spaces, no tabs) and correct YAML structure before delivery.

### Threat Identification
- **Scope to assets provided.** Only generate threats relevant to the provided assets.
- **Use STRIDE as a framework**, not a checklist. Not all STRIDE categories apply equally.
- **Prioritize by impact.** Generate 8-15 threats covering the highest-risk scenarios.
- **Avoid duplicates.** Each threat should be distinct in attack vector, impact, or asset involved.

### CVSS Scoring
- Use CVSS 3.1 vector format (AV/AC/PR/UI/S/C/I/A).
- Be realistic. Most threats score 4.0-8.5. Critical (9.0+) is rare.
- **AV (Attack Vector):** N=network, A=adjacent, L=local, P=physical.
- **AC (Attack Complexity):** L=low, H=high.
- **PR (Privileges Required):** N=none, L=low, H=high.
- **UI (User Interaction):** N=no, R=required.
- **S (Scope):** U=unchanged, C=changed (can impact other systems).
- **C/I/A (Impact):** N=none, L=low, H=high.

### Countermeasures
- **Be specific.** Generic platitudes (e.g., "improve security") are not acceptable.
- **Include implementation steps.** A control without clear steps is aspirational, not actionable.
- **Vary by effort.** Include quick wins (Low effort), medium-term improvements (Medium), and strategic investments (High).
- **Avoid brand names.** Use principles-based language: "cryptographic binding," not "implement Vault."
- **Link to threat.** Each countermeasure must directly address the threat's root cause.

### Enhanced Testing Fields
- **testPrerequisites:** What setup/permissions/tools are needed before testing begins?
- **testSteps:** Ordered, actionable steps to reproduce the threat. Include expected outputs at each step.
- **testScripts:** Automated test code (bash, python, powershell, curl). Make scripts runnable.
- **testTools:** List recommended security testing tools.
- **expectedBehavior:** What the system does when vulnerable.
- **expectedMitigation:** What the system should do when properly protected.

These fields enable:
- Penetration testers to validate threats
- Security teams to automate testing
- LLMs to generate test code and scripts
- CI/CD integration for continuous security testing

---

## Example Threat (Complete)

```yaml
  - ID: "T_001_IDOR"
    title: "Cross-Tenant Data Exposure via IDOR"
    threatType: "Information Disclosure"
    attack: "An authenticated user from Tenant A manipulates API request parameters to access resources belonging to Tenant B. By changing the tenant_id or resource_id in the request, the API returns data that should be isolated."
    impactDesc: "Complete exposure of customer PII, leads, and proprietary information. Breach notification obligations. GDPR fines. Loss of trust and market share."
    impactedSecObj:
      - "SO-CONF"
      - "SO-AUTH"
    attackers:
      - "ATT_TENANT"
      - "ATT_COMPETITOR"
    CVSS:
      vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
      score: 6.5
      severity: "Medium"
    fullyMitigated: false
    
    testPrerequisites:
      - "Two separate tenant accounts with different data"
      - "API documentation showing resource endpoints"
      - "Burp Suite or similar proxy tool"
      - "Authorization token for first tenant"
    
    testSteps:
      - "Authenticate as Tenant A user and capture the auth token"
      - "Retrieve a resource via API: GET /api/leads/123"
      - "Note the tenant_id in the request or URL"
      - "Modify the request to access Tenant B's resource: GET /api/leads/456"
      - "Observe if Tenant B's data is returned without additional authorization checks"
      - "Try incrementing resource IDs to enumerate other tenants' data"
      - "Check if API enforces row-level security or trusts the client to specify tenant context"
    
    testScripts:
      - language: "bash"
        description: "Quick IDOR enumeration using curl"
        code: |
          #!/bin/bash
          TOKEN="$1"
          BASE_URL="$2"
          START_ID="$3"
          
          for i in $(seq $START_ID $((START_ID+10))); do
            echo "[*] Testing resource ID: $i"
            curl -H "Authorization: Bearer $TOKEN" \
              "$BASE_URL/api/leads/$i" -s | jq '.tenant_id'
          done
      
      - language: "python"
        description: "Automated IDOR detection with tenant enumeration"
        code: |
          import requests
          import sys
          
          token = sys.argv[1]
          base_url = sys.argv[2]
          
          headers = {"Authorization": f"Bearer {token}"}
          
          for resource_id in range(1, 50):
            resp = requests.get(f"{base_url}/api/leads/{resource_id}", headers=headers)
            if resp.status_code == 200:
              data = resp.json()
              if 'tenant_id' in data:
                print(f"[!] Resource {resource_id} belongs to tenant: {data['tenant_id']}")
    
    testTools:
      - "Burp Suite Intruder"
      - "curl"
      - "OWASP ZAP"
      - "Postman"
    
    expectedBehavior: "API returns data from any tenant when the authenticated user modifies the resource_id or tenant_id parameter. No additional authorization checks are performed beyond authentication. User can enumerate and extract all tenant data."
    
    expectedMitigation: "API enforces row-level security: the authenticated user can only access resources for which their tenant_id matches the resource's tenant_id. Attempting to access another tenant's resource returns 403 Forbidden. All data access is validated server-side."
    
    countermeasures:
      - ID: "CM_001_TENANTBOUND"
        title: "Enforce Tenant-Bound Authorization at API Layer"
        description: "The API layer validates that the authenticated user's tenant_id matches the resource's tenant_id before returning data. No resource ID alone is sufficient."
        status: "not_started"
        effort: "Medium"
        why: "IDOR occurs when authorization logic trusts client-supplied identifiers. By enforcing that all data access is scoped to the user's tenant, we ensure cross-tenant boundaries are respected."
        implementation:
          - "In the API middleware, extract the user's tenant_id from the authenticated session/JWT"
          - "For any data retrieval request, append a WHERE clause or filter: WHERE tenant_id = authenticated_user_tenant_id"
          - "Never allow the client to override the tenant context"
          - "Return 403 Forbidden if the resource exists but belongs to a different tenant (not 404, which leaks existence)"
          - "Log all authorization failures for audit purposes"
          - "Test with multiple tenants to ensure cross-tenant access is blocked"
```

---

## Output Format

Return a valid YAML file with:
1. `meta:` block
2. `diagrams:` block (if applicable)
3. `assets:` block (provided separately, include as-is)
4. `attackers:` list (5-7 distinct personas)
5. `securityObjectives:` list (4-6 objectives)
6. `threats:` list (8-15 threats, fully detailed with testing fields)

---

## Important Notes

- **Assets are PROVIDED SEPARATELY.** Do not fabricate or regenerate the asset list. Include it exactly as provided.
- **YAML syntax:** Use proper YAML indentation (2 spaces, no tabs). Multi-line fields use `|` for code blocks and `|` for text.
- **IDs:** Use consistent, descriptive IDs (T_001_IDOR, CM_001_AUTHZ, etc.).
- **Completeness:** Every threat must have countermeasures. Every countermeasure must have implementation steps.
- **Testing:** Enhanced testing fields (testPrerequisites, testSteps, testScripts) are required for high-severity threats (CVSS 7.0+) and recommended for all others.
- **Realism:** Threats and controls should be pragmatic, not theoretical. Avoid security theater.

---

## Usage

1. Provide the system context (description, architecture, assumptions, constraints).
2. Provide the asset list separately (with dataFlows having complete `source:` and `destination:` fields).
3. Include this prompt.
4. The AI generates a complete, actionable threat-model.yaml file.
5. **Validation:** Verify the YAML is syntactically correct and all dataFlow objects have required source/destination fields.
6. Run the report generator: `python -m src.cli report path/to/threat-models/PROJECT_NAME`
7. Review the HTML report and iterate as needed.

**Real-world Example:** The Meetsendai V0 threat model (7 assets, 40+ threats) was successfully generated using this prompt, demonstrating end-to-end functionality from YAML generation to HTML report rendering.

---

## Questions for Clarification

If the context is ambiguous or incomplete, ask:
- "Which assets are most critical to this system?"
- "What compliance frameworks apply (GDPR, HIPAA, SOC2, PCI-DSS)?"
- "What is the threat level (startup, mid-market, enterprise, regulated industry)?"
- "Are there any known vulnerabilities or prior breaches to consider?"
- "What is the acceptable risk tolerance for this system?"
