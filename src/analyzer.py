"""Threat model analyzer - automated extraction from transcripts and documents."""

import re
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path
from datetime import datetime
import yaml


@dataclass
class ExtractedAsset:
    """An asset extracted from source documents."""
    id: str
    name: str
    type: str
    description: str
    trust_zone: str = "internal"
    data_flows: list[dict] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)


@dataclass
class ExtractedThreat:
    """A threat identified from system analysis."""
    id: str
    title: str
    attack: str
    threat_type: str
    impact_desc: str
    impacted_sec_obj: list[str]
    attackers: list[str]
    cvss_vector: Optional[str] = None
    countermeasures: list[dict] = field(default_factory=list)


@dataclass 
class AnalysisResult:
    """Complete analysis result from document processing."""
    title: str
    scope: str
    assets: list[ExtractedAsset]
    attackers: list[dict]
    security_objectives: list[dict]
    threats: list[ExtractedThreat]


class ThreatModelAnalyzer:
    """Analyzes transcripts and documents to generate threat models."""
    
    ASSET_KEYWORDS = {
        'api gateway': ('API Gateway', 'process'),
        'api': ('API Service', 'process'),
        'backend service': ('Backend Service', 'process'),
        'backend': ('Backend Service', 'process'),
        'frontend': ('Frontend Application', 'process'),
        'web application': ('Web Application', 'process'),
        'web app': ('Web Application', 'process'),
        'microservice': ('Microservice', 'process'),
        'worker': ('Worker Service', 'process'),
        'admin panel': ('Admin Panel', 'process'),
        'postgresql': ('PostgreSQL Database', 'datastore'),
        'postgres': ('PostgreSQL Database', 'datastore'),
        'mysql': ('MySQL Database', 'datastore'),
        'database': ('Database', 'datastore'),
        'mongodb': ('MongoDB', 'datastore'),
        'redis': ('Redis Cache', 'datastore'),
        'cache': ('Cache', 'datastore'),
        'elasticsearch': ('Elasticsearch', 'datastore'),
        'rabbitmq': ('RabbitMQ Queue', 'datastore'),
        'kafka': ('Kafka', 'datastore'),
        'message queue': ('Message Queue', 'datastore'),
        's3': ('S3 Storage', 'datastore'),
        'user': ('End User', 'external_entity'),
        'customer': ('Customer', 'external_entity'),
        'browser': ('Web Browser', 'external_entity'),
        'stripe': ('Stripe Payment Service', 'external_entity'),
        'payment service': ('Payment Service', 'external_entity'),
        'third-party': ('Third-Party Service', 'external_entity'),
    }
    
    TRUST_ZONE_KEYWORDS = {
        'external': ['external', 'public', 'internet', 'user', 'customer', 'browser', 'third-party'],
        'dmz': ['gateway', 'api gateway', 'load balancer', 'proxy'],
        'internal': ['internal', 'backend', 'database', 'cache', 'queue', 'worker', 'admin'],
    }
    
    THREAT_TEMPLATES = {
        'XSS_ATTACK': {
            'applies_to': ['process'],
            'keywords': ['frontend', 'web', 'browser', 'user', 'input'],
            'title': 'Cross-Site Scripting (XSS) in {component}',
            'attack': 'Attacker injects malicious JavaScript through user input',
            'impact': 'Session hijacking, credential theft, defacement',
            'sec_obj': ['SO_CONFIDENTIALITY', 'SO_INTEGRITY'],
            'cvss': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
            'countermeasures': [
                {'title': 'Output Encoding', 'description': 'Encode all user-controlled output', 'status': 'planned'},
                {'title': 'Content Security Policy', 'description': 'Implement strict CSP headers', 'status': 'planned'},
            ]
        },
        'SQL_INJECTION': {
            'applies_to': ['process', 'datastore'],
            'keywords': ['database', 'sql', 'postgres', 'mysql', 'query'],
            'title': 'SQL Injection via {component}',
            'attack': 'Attacker injects malicious SQL commands through application input',
            'impact': 'Unauthorized data access, data modification, system takeover',
            'sec_obj': ['SO_CONFIDENTIALITY', 'SO_INTEGRITY'],
            'cvss': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
            'countermeasures': [
                {'title': 'Parameterized Queries', 'description': 'Use parameterized queries for all database operations', 'status': 'planned'},
                {'title': 'Least Privilege DB Access', 'description': 'Database accounts use minimum required permissions', 'status': 'planned'},
            ]
        },
        'AUTHENTICATION_BYPASS': {
            'applies_to': ['process'],
            'keywords': ['login', 'auth', 'jwt', 'token', 'session', 'password'],
            'title': 'Authentication Bypass on {component}',
            'attack': 'Attacker bypasses authentication controls to gain unauthorized access',
            'impact': 'Unauthorized access to user accounts and protected functionality',
            'sec_obj': ['SO_CONFIDENTIALITY', 'SO_INTEGRITY'],
            'cvss': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
            'countermeasures': [
                {'title': 'Multi-Factor Authentication', 'description': 'Implement MFA for sensitive operations', 'status': 'planned'},
                {'title': 'Secure Session Management', 'description': 'Use secure, httpOnly, sameSite cookies', 'status': 'planned'},
            ]
        },
        'BROKEN_ACCESS_CONTROL': {
            'applies_to': ['process'],
            'keywords': ['admin', 'role', 'permission', 'privilege', 'authorization'],
            'title': 'Broken Access Control in {component}',
            'attack': 'Attacker accesses resources beyond their authorized permissions',
            'impact': 'Unauthorized data access, privilege escalation',
            'sec_obj': ['SO_CONFIDENTIALITY', 'SO_INTEGRITY'],
            'cvss': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
            'countermeasures': [
                {'title': 'Server-Side Authorization', 'description': 'Enforce authorization checks on every request', 'status': 'planned'},
                {'title': 'Role-Based Access Control', 'description': 'Implement RBAC with least privilege', 'status': 'planned'},
            ]
        },
        'SENSITIVE_DATA_EXPOSURE': {
            'applies_to': ['datastore', 'process'],
            'keywords': ['pii', 'personal', 'credit card', 'password', 'sensitive', 'encrypt'],
            'title': 'Sensitive Data Exposure in {component}',
            'attack': 'Attacker accesses sensitive data due to insufficient protection',
            'impact': 'Exposure of personal data, financial information, or credentials',
            'sec_obj': ['SO_CONFIDENTIALITY'],
            'cvss': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            'countermeasures': [
                {'title': 'Encryption at Rest', 'description': 'Encrypt all sensitive data at rest using AES-256', 'status': 'planned'},
                {'title': 'Encryption in Transit', 'description': 'Enforce TLS 1.2+ for all data transmission', 'status': 'planned'},
            ]
        },
        'API_ABUSE': {
            'applies_to': ['process'],
            'keywords': ['api', 'endpoint', 'rest', 'webhook'],
            'title': 'API Abuse on {component}',
            'attack': 'Attacker exploits API vulnerabilities or abuses API functionality',
            'impact': 'Data breach, service abuse, denial of service',
            'sec_obj': ['SO_CONFIDENTIALITY', 'SO_INTEGRITY', 'SO_AVAILABILITY'],
            'cvss': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L',
            'countermeasures': [
                {'title': 'API Authentication', 'description': 'Require strong authentication for all endpoints', 'status': 'planned'},
                {'title': 'Rate Limiting', 'description': 'Implement rate limiting per client', 'status': 'planned'},
            ]
        },
        'DENIAL_OF_SERVICE': {
            'applies_to': ['process'],
            'keywords': ['api', 'service', 'server', 'public'],
            'title': 'Denial of Service on {component}',
            'attack': 'Attacker overwhelms system resources making service unavailable',
            'impact': 'Service unavailability, business disruption',
            'sec_obj': ['SO_AVAILABILITY'],
            'cvss': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
            'countermeasures': [
                {'title': 'Rate Limiting', 'description': 'Implement rate limiting on public endpoints', 'status': 'planned'},
                {'title': 'DDoS Protection', 'description': 'Use CDN/WAF with DDoS protection', 'status': 'planned'},
            ]
        },
        'SESSION_HIJACKING': {
            'applies_to': ['process'],
            'keywords': ['session', 'token', 'jwt', 'cookie', 'localstorage'],
            'title': 'Session Hijacking on {component}',
            'attack': 'Attacker steals or forges session tokens to impersonate users',
            'impact': 'Account takeover, unauthorized actions as victim user',
            'sec_obj': ['SO_CONFIDENTIALITY', 'SO_INTEGRITY'],
            'cvss': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N',
            'countermeasures': [
                {'title': 'Secure Cookie Flags', 'description': 'Use httpOnly, secure, and sameSite flags', 'status': 'planned'},
                {'title': 'Token Rotation', 'description': 'Rotate session tokens after authentication', 'status': 'planned'},
            ]
        },
        'DATA_BREACH': {
            'applies_to': ['datastore'],
            'keywords': ['database', 'storage', 'data'],
            'title': 'Data Breach via {component}',
            'attack': 'Attacker gains unauthorized access to data store',
            'impact': 'Mass data exposure, regulatory penalties, reputational damage',
            'sec_obj': ['SO_CONFIDENTIALITY'],
            'cvss': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
            'countermeasures': [
                {'title': 'Network Segmentation', 'description': 'Isolate datastores in private network segments', 'status': 'planned'},
                {'title': 'Access Controls', 'description': 'Implement strict access controls and authentication', 'status': 'planned'},
            ]
        },
        'THIRD_PARTY_RISK': {
            'applies_to': ['external_entity'],
            'keywords': ['third-party', 'external', 'stripe', 'payment', 'vendor'],
            'title': 'Third-Party Compromise via {component}',
            'attack': 'Attacker compromises third-party service to attack main application',
            'impact': 'Supply chain attack, data breach, service disruption',
            'sec_obj': ['SO_CONFIDENTIALITY', 'SO_INTEGRITY'],
            'cvss': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:L',
            'countermeasures': [
                {'title': 'Vendor Assessment', 'description': 'Conduct security assessments of third-party vendors', 'status': 'planned'},
                {'title': 'Input Validation', 'description': 'Validate data from third-party services', 'status': 'planned'},
            ]
        },
        'INSUFFICIENT_LOGGING': {
            'applies_to': ['process'],
            'keywords': ['backend', 'service', 'api'],
            'title': 'Insufficient Logging for {component}',
            'attack': 'Attacker activities go undetected due to inadequate logging',
            'impact': 'Delayed breach detection, inability to investigate incidents',
            'sec_obj': ['SO_ACCOUNTABILITY'],
            'cvss': 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N',
            'countermeasures': [
                {'title': 'Security Event Logging', 'description': 'Log all authentication and authorization events', 'status': 'planned'},
                {'title': 'Centralized Logging', 'description': 'Aggregate logs to SIEM for analysis', 'status': 'planned'},
            ]
        },
    }
    
    DEFAULT_ATTACKERS = [
        {'REFID': 'EXTERNAL_ATTACKER', 'name': 'External Attacker', 'description': 'Malicious actor with no prior system access', 'motivation': 'Financial gain, data theft', 'capability': 'high'},
        {'REFID': 'MALICIOUS_INSIDER', 'name': 'Malicious Insider', 'description': 'Authorized user who abuses privileges', 'motivation': 'Financial gain, revenge', 'capability': 'medium'},
    ]
    
    DEFAULT_SECURITY_OBJECTIVES = [
        {'ID': 'SO_CONFIDENTIALITY', 'name': 'Data Confidentiality', 'description': 'Sensitive data must not be disclosed to unauthorized parties', 'category': 'Confidentiality'},
        {'ID': 'SO_INTEGRITY', 'name': 'Data Integrity', 'description': 'Data must not be modified without authorization', 'category': 'Integrity'},
        {'ID': 'SO_AVAILABILITY', 'name': 'Service Availability', 'description': 'System must remain available for legitimate users', 'category': 'Availability'},
        {'ID': 'SO_ACCOUNTABILITY', 'name': 'Accountability', 'description': 'Actions must be traceable to responsible parties', 'category': 'Non-Repudiation'},
    ]
    
    def __init__(self):
        self._cm_counter = 0
        self._flow_counter = 0
    
    def _generate_asset_id(self, name: str) -> str:
        clean = re.sub(r'[^a-zA-Z0-9]+', '_', name.upper().strip())
        return clean.rstrip('_')
    
    def _extract_assets(self, text: str) -> list[ExtractedAsset]:
        text_lower = text.lower()
        found_assets = {}
        sorted_keywords = sorted(self.ASSET_KEYWORDS.keys(), key=len, reverse=True)
        
        for keyword in sorted_keywords:
            name, asset_type = self.ASSET_KEYWORDS[keyword]
            if keyword in text_lower:
                asset_id = self._generate_asset_id(name)
                if asset_id in found_assets:
                    found_assets[asset_id].keywords.append(keyword)
                    continue
                
                trust_zone = 'internal'
                for zone, zone_keywords in self.TRUST_ZONE_KEYWORDS.items():
                    if any(zk in keyword for zk in zone_keywords):
                        trust_zone = zone
                        break
                
                found_assets[asset_id] = ExtractedAsset(
                    id=asset_id, name=name, type=asset_type,
                    description=f"{name} identified from system documentation",
                    trust_zone=trust_zone, keywords=[keyword]
                )
        
        return list(found_assets.values())
    
    def _extract_data_flows(self, text: str, assets: list[ExtractedAsset]) -> list[dict]:
        flows = []
        asset_keywords_map = {kw: a for a in assets for kw in a.keywords}
        flow_patterns = [r'(\w+(?:\s+\w+)?)\s+(?:sends?|connects?\s+to|calls?|communicates?\s+with)\s+(?:the\s+)?(\w+(?:\s+\w+)?)']
        text_lower = text.lower()
        
        for pattern in flow_patterns:
            for match in re.finditer(pattern, text_lower):
                source_text, dest_text = match.group(1).strip(), match.group(2).strip()
                source_asset = dest_asset = None
                for kw, asset in asset_keywords_map.items():
                    if kw in source_text or source_text in kw:
                        source_asset = asset
                    if kw in dest_text or dest_text in kw:
                        dest_asset = asset
                
                if source_asset and dest_asset and source_asset.id != dest_asset.id:
                    self._flow_counter += 1
                    crosses = source_asset.trust_zone != dest_asset.trust_zone
                    flow = {
                        'ID': f'DF_{self._flow_counter:03d}',
                        'name': f'{source_asset.name} to {dest_asset.name}',
                        'source': source_asset.id,
                        'destination': dest_asset.id,
                        'protocol': 'HTTPS',
                        'dataClassification': 'internal',
                        'crossesTrustBoundary': crosses,
                    }
                    if crosses:
                        flow['trustBoundary'] = f'{source_asset.trust_zone} to {dest_asset.trust_zone}'
                    if not any(f['source'] == flow['source'] and f['destination'] == flow['destination'] for f in flows):
                        flows.append(flow)
        
        return flows
    
    def _identify_threats(self, text: str, assets: list[ExtractedAsset]) -> list[ExtractedThreat]:
        threats = []
        for threat_id, template in self.THREAT_TEMPLATES.items():
            best_asset = None
            best_score = 0
            
            for asset in assets:
                if asset.type not in template['applies_to']:
                    continue
                asset_context = ' '.join(asset.keywords) + ' ' + asset.name.lower()
                score = sum(1 for kw in template['keywords'] if kw in asset_context)
                if score > best_score:
                    best_score = score
                    best_asset = asset
            
            if best_asset and best_score > 0:
                attackers = ['EXTERNAL_ATTACKER']
                if best_asset.trust_zone == 'internal':
                    attackers.append('MALICIOUS_INSIDER')
                
                countermeasures = []
                for cm in template['countermeasures']:
                    self._cm_counter += 1
                    countermeasures.append({
                        'ID': f'CM_{self._cm_counter:03d}',
                        'title': cm['title'],
                        'description': cm['description'],
                        'status': cm['status']
                    })
                
                threats.append(ExtractedThreat(
                    id=threat_id,
                    title=template['title'].format(component=best_asset.name),
                    attack=template['attack'],
                    threat_type=threat_id.replace('_', ' ').title(),
                    impact_desc=template['impact'],
                    impacted_sec_obj=template['sec_obj'],
                    attackers=attackers,
                    cvss_vector=template.get('cvss'),
                    countermeasures=countermeasures
                ))
        
        return threats
    
    def analyze(self, transcript: str, product_context: str, title: str) -> AnalysisResult:
        full_text = f"{product_context}\n\n{transcript}"
        assets = self._extract_assets(full_text)
        flows = self._extract_data_flows(full_text, assets)
        
        flow_by_source = {}
        for flow in flows:
            flow_by_source.setdefault(flow['source'], []).append(flow)
        for asset in assets:
            asset.data_flows = flow_by_source.get(asset.id, [])
        
        threats = self._identify_threats(full_text, assets)
        scope = product_context[:500] + ('...' if len(product_context) > 500 else '') if product_context else "Security analysis of identified system components"
        
        return AnalysisResult(
            title=title, scope=scope, assets=assets,
            attackers=self.DEFAULT_ATTACKERS,
            security_objectives=self.DEFAULT_SECURITY_OBJECTIVES,
            threats=threats
        )


class ThreatModelGenerator:
    """Generates complete threat model YAML files from analysis results."""
    
    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.analyzer = ThreatModelAnalyzer()
    
    def generate_from_input(self, transcript: str, product_context: str, title: str, model_id: str, owner: str = "Security Team") -> Path:
        result = self.analyzer.analyze(transcript, product_context, title)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / 'reports').mkdir(exist_ok=True)
        
        self._write_meta(title, model_id, result.scope, owner)
        self._write_assets(result.assets)
        self._write_attackers(result.attackers)
        self._write_security_objectives(result.security_objectives)
        self._write_threats(result.threats)
        
        return self.output_dir
    
    def _write_meta(self, title: str, model_id: str, scope: str, owner: str) -> None:
        meta = {'title': title, 'modelId': model_id, 'version': '1.0.0', 'scope': scope, 'owner': owner, 'lastUpdated': datetime.now().strftime('%Y-%m-%d')}
        with open(self.output_dir / '_meta.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(meta, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    
    def _write_assets(self, assets: list[ExtractedAsset]) -> None:
        assets_data = {'assets': [{'ID': a.id, 'name': a.name, 'type': a.type, 'description': a.description, 'trustZone': a.trust_zone, **(({'dataFlows': a.data_flows} if a.data_flows else {}))} for a in assets]}
        with open(self.output_dir / 'assets.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(assets_data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    
    def _write_attackers(self, attackers: list[dict]) -> None:
        with open(self.output_dir / 'attackers.yaml', 'w', encoding='utf-8') as f:
            yaml.dump({'attackers': attackers}, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    
    def _write_security_objectives(self, objectives: list[dict]) -> None:
        with open(self.output_dir / 'security-objectives.yaml', 'w', encoding='utf-8') as f:
            yaml.dump({'securityObjectives': objectives}, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    
    def _write_threats(self, threats: list[ExtractedThreat]) -> None:
        with open(self.output_dir / 'threats.yaml', 'w', encoding='utf-8') as f:
            f.write("threats:\n")
            for t in threats:
                f.write(f"  - ID: {t.id}\n")
                f.write(f"    title: \"{t.title}\"\n")
                f.write(f"    attack: \"{t.attack}\"\n")
                f.write(f"    threatType: {t.threat_type}\n")
                f.write(f"    impactDesc: \"{t.impact_desc}\"\n")
                f.write(f"    impactedSecObj:\n")
                for obj in t.impacted_sec_obj:
                    f.write(f"      - {obj}\n")
                f.write(f"    attackers:\n")
                for att in t.attackers:
                    f.write(f"      - {att}\n")
                if t.cvss_vector:
                    f.write(f"    CVSS:\n      vector: \"{t.cvss_vector}\"\n")
                f.write(f"    fullyMitigated: false\n")
                f.write(f"    countermeasures:\n")
                for cm in t.countermeasures:
                    f.write(f"      - ID: {cm['ID']}\n        title: \"{cm['title']}\"\n        description: \"{cm['description']}\"\n        status: {cm['status']}\n")
                f.write("\n")
