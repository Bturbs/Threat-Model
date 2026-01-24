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


class Attacker(BaseModel):
    """An attacker profile referenced by threats."""
    REFID: str
    name: str
    description: Optional[str] = None
    motivation: Optional[str] = None
    capability: Optional[str] = None


class SecurityObjective(BaseModel):
    """A security objective that threats may impact."""
    ID: str
    name: str
    description: str
    category: Optional[str] = None


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
