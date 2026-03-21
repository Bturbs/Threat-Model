"""Pydantic models for threat model schema validation."""

from typing import Optional
from pydantic import BaseModel, Field, field_validator


class CVSSVector(BaseModel):
    """CVSS 3.1 vector with calculated score and severity."""
    vector: str = Field(..., pattern=r'^CVSS:3\.1/.*')
    score: Optional[float] = None
    severity: Optional[str] = None


class TestScript(BaseModel):
    """A test script to replicate/demonstrate a threat."""
    language: str  # e.g., 'bash', 'python', 'powershell', 'curl'
    code: str
    description: Optional[str] = None
    requirements: Optional[list[str]] = None  # e.g., ['curl', 'jq', 'python3']


class Countermeasure(BaseModel):
    """A countermeasure for mitigating a threat."""
    ID: str
    title: str
    description: str
    status: str = Field(..., pattern=r'^(in_place|planned|not_started)$')
    # Remediation depth fields
    why: Optional[str] = None                        # Why this control addresses the threat
    implementation: Optional[list[str]] = None       # Step-by-step implementation guidance
    effort: Optional[str] = None                     # Low / Medium / High


class Threat(BaseModel):
    """Threat definition with CVSS scoring and countermeasures."""
    ID: str
    title: str
    attack: str
    threatType: str
    impactDesc: str
    impactedSecObj: Optional[list[str]] = None
    attackers: Optional[list[str]] = None
    CVSS: Optional[CVSSVector] = None
    fullyMitigated: bool = False
    alwaysPresent: bool = False
    countermeasures: list[Countermeasure] = Field(default_factory=list)
    
    # Security Testing Fields
    testPrerequisites: Optional[list[str]] = None  # Prerequisites for testing
    testSteps: Optional[list[str]] = None  # Detailed replication steps
    testScripts: Optional[list[TestScript]] = None  # Automated test scripts
    testTools: Optional[list[str]] = None  # Recommended tools
    expectedBehavior: Optional[str] = None  # Expected vulnerable behavior
    expectedMitigation: Optional[str] = None  # Expected behavior when mitigated
    source_aspect: Optional[str] = None  # set by composer at merge-time; not read from YAML

    @field_validator('ID')
    @classmethod
    def validate_threat_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError('Threat ID cannot be empty')
        return v.strip().upper()


class DataFlow(BaseModel):
    """A data flow between assets."""
    ID: str
    name: str
    source: str
    destination: str
    protocol: Optional[str] = None
    dataClassification: Optional[str] = None
    crossesTrustBoundary: bool = False
    trustBoundary: Optional[str] = None


class Asset(BaseModel):
    """An asset in the threat model."""
    ID: str
    name: str
    type: str
    description: Optional[str] = None
    trustZone: Optional[str] = None
    dataFlows: list[DataFlow]
    source_aspect: Optional[str] = None  # set by composer at merge-time; not read from YAML


class Attacker(BaseModel):
    """An attacker profile referenced by threats."""
    REFID: str
    name: str
    description: Optional[str] = None
    motivation: Optional[str] = None
    capability: Optional[str] = None
    source_aspect: Optional[str] = None  # set by composer at merge-time; not read from YAML


class SecurityObjective(BaseModel):
    """A security objective that threats may impact."""
    ID: str
    name: str
    description: str
    category: Optional[str] = None
    source_aspect: Optional[str] = None  # set by composer at merge-time; not read from YAML


# Valid placement slots for diagrams within the generated report.
DIAGRAM_PLACEMENTS = {
    'before_attack_tree',  # default — between the assets table and the attack tree
    'after_attack_tree',   # between the attack tree and the DFD section
    'after_dfd',           # after the auto-generated data flow diagrams
}


class DiagramRef(BaseModel):
    """A reference to an external diagram file (e.g. PlantUML) stored in the assets/ folder.

    The `file` path is relative to the threat model folder, e.g. "assets/Flow.puml".
    The `content` field is NOT stored in the YAML — it is populated at parse time by
    reading the referenced file from disk.

    `placement` controls where the diagram card is injected in the HTML report:
      - before_attack_tree  (default) — holistic architecture view before threat analysis
      - after_attack_tree   — detailed flow context between attack tree and DFD
      - after_dfd           — supplementary diagrams after the auto-generated DFD
    """
    id: str
    title: str
    file: str
    type: Optional[str] = None         # e.g. 'sequence', 'component', 'activity', 'flow'
    description: Optional[str] = None
    placement: str = 'before_attack_tree'  # controls report slot; see DIAGRAM_PLACEMENTS
    content: Optional[str] = None      # populated by parser, not from YAML
    source_aspect: Optional[str] = None  # set by composer at merge-time; not read from YAML

    @field_validator('placement')
    @classmethod
    def validate_placement(cls, v: str) -> str:
        if v not in DIAGRAM_PLACEMENTS:
            raise ValueError(
                f"Invalid placement '{v}'. Must be one of: {sorted(DIAGRAM_PLACEMENTS)}"
            )
        return v


class ComposeEntry(BaseModel):
    """A sub-aspect entry in the compose section pointing to a child model directory.

    The `path` is a directory path relative to the root model folder that contains
    its own `threat-model.yaml`.  At parse time the tool recursively loads each child,
    tags every entity with the `aspect` label, and merges everything into the root model.
    """
    aspect: str               # human-readable label shown in the report, e.g. "Edge & Auth"
    path: str                 # directory path relative to the root model folder
    description: Optional[str] = None


class ThreatModelMeta(BaseModel):
    """Metadata for a threat model."""
    title: str
    modelId: str
    version: str
    scope: str
    owner: Optional[str] = None
    lastUpdated: Optional[str] = None


class ThreatModel(BaseModel):
    """Complete threat model combining all components."""
    meta: ThreatModelMeta
    assets: list[Asset] = Field(default_factory=list)
    attackers: list[Attacker] = Field(default_factory=list)
    securityObjectives: list[SecurityObjective] = Field(default_factory=list)
    threats: list[Threat] = Field(default_factory=list)
    diagrams: list[DiagramRef] = Field(default_factory=list)
    compose: list[ComposeEntry] = Field(default_factory=list)
