# Threat Modeling: AI Assist Context & Prompt

When using AI to generate or assist with threat models, you only need to provide:

## 1. AI Assist Context
- The YAML file (examples/AI assist.yaml) describing:
  - The system, architecture, or application being modeled
  - Key assets, attackers, and security objectives
  - Any specific requirements or constraints

## 2. Prompt
- A clear instruction for the AI, such as:
  - "Generate a threat model for the above context."
  - "Identify threats and propose countermeasures for this system."
  - "Provide detailed remediation steps for each threat."

---

## Example AI Assist Workflow

### Context (YAML)
```yaml
meta:
  title: "Serverless File Upload Platform"
  modelId: "TM-SERVERLESS-UPLOAD"
  version: "1.0"
  scope: "Secure file upload and processing in a serverless environment"
assets:
  - ID: "A1"
    name: "API Gateway"
    type: "Service"
    description: "Entry point for file uploads"
attackers:
  - REFID: "ATT-EXT"
    name: "External Attacker"
securityObjectives:
  - ID: "SO-CONF"
    name: "Confidentiality"
```

### Prompt
```
Generate a threat model for the above context. Identify threats, describe their impact, and propose generic, brand-free countermeasures with clear implementation steps.
```

---

## What to Provide
- Only the AI assist YAML context and a concise prompt.
- No need to supply full threat model YAML or HTML templates.
- The AI will generate threats, impacts, and countermeasures based on the context and prompt.

---

## Recommended Prompt Template
```
Using the provided context, generate a threat model:
- Identify relevant threats
- Describe their impact
- Propose countermeasures (no brand names or standards references)
- Include implementation steps and rationale for each countermeasure
```
