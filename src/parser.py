"""YAML parser and validator for threat models."""

from pathlib import Path
from typing import Optional
import yaml
from pydantic import ValidationError

from .schemas import (
    ThreatModel, ThreatModelMeta, Asset, Attacker,
    SecurityObjective, Threat, DataFlow, Countermeasure,
)
from .cvss_calculator import calculate_cvss_score


class ThreatModelParseError(Exception):
    """Raised when threat model parsing or validation fails."""
    pass


class ThreatModelParser:
    """Parser for threat model YAML files. Supports single-file and multi-file formats."""
    
    COMBINED_FILE = 'threat-model.yaml'
    REQUIRED_FILES = ['_meta.yaml', 'threats.yaml']
    OPTIONAL_FILES = ['assets.yaml', 'attackers.yaml', 'security-objectives.yaml']
    
    def __init__(self, model_path: Path):
        self.model_path = Path(model_path)
        self.is_combined = self._check_combined_file()
        self._validate_structure()
    
    def _check_combined_file(self) -> bool:
        return (self.model_path / self.COMBINED_FILE).exists()
    
    def _validate_structure(self) -> None:
        if not self.model_path.exists():
            raise ThreatModelParseError(f"Threat model path does not exist: {self.model_path}")
        if not self.model_path.is_dir():
            raise ThreatModelParseError(f"Threat model path is not a directory: {self.model_path}")
        if self.is_combined:
            return
        for required_file in self.REQUIRED_FILES:
            if not (self.model_path / required_file).exists():
                raise ThreatModelParseError(f"Required file missing: {required_file}")
    
    def _load_yaml(self, filename: str) -> Optional[dict]:
        file_path = self.model_path / filename
        if not file_path.exists():
            return None
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = yaml.safe_load(f)
                return content if content else {}
        except yaml.YAMLError as e:
            raise ThreatModelParseError(f"YAML parse error in {filename}: {e}")
    
    def _calculate_cvss_scores(self, threat_data: dict) -> dict:
        if 'CVSS' in threat_data and threat_data['CVSS']:
            cvss_data = threat_data['CVSS']
            if isinstance(cvss_data, dict) and 'vector' in cvss_data:
                vector = cvss_data['vector']
                score, severity = calculate_cvss_score(vector)
                cvss_data['score'] = score
                cvss_data['severity'] = severity
                threat_data['CVSS'] = cvss_data
        return threat_data
    
    def _validate_attacker_references(self, threats: list[Threat], attackers: list[Attacker]) -> None:
        if not attackers:
            return
        defined_attackers = {a.REFID for a in attackers}
        for threat in threats:
            if threat.attackers:
                for attacker_ref in threat.attackers:
                    if attacker_ref not in defined_attackers:
                        raise ThreatModelParseError(
                            f"Threat '{threat.ID}' references undefined attacker: {attacker_ref}"
                        )
    
    def _validate_security_objective_references(
        self, threats: list[Threat], security_objectives: list[SecurityObjective]
    ) -> None:
        defined_objectives = {so.ID for so in security_objectives}
        for threat in threats:
            if threat.impactedSecObj:
                for obj_ref in threat.impactedSecObj:
                    if obj_ref not in defined_objectives:
                        raise ThreatModelParseError(
                            f"Threat '{threat.ID}' references undefined security objective: {obj_ref}"
                        )
    
    def parse(self) -> ThreatModel:
        if self.is_combined:
            return self._parse_combined()
        return self._parse_multi_file()
    
    def _parse_combined(self) -> ThreatModel:
        data = self._load_yaml(self.COMBINED_FILE)
        if not data:
            raise ThreatModelParseError(f"{self.COMBINED_FILE} is empty or invalid")
        
        meta_data = data.get('meta')
        if not meta_data:
            raise ThreatModelParseError("'meta' section is required in threat-model.yaml")
        
        try:
            meta = ThreatModelMeta(**meta_data)
        except ValidationError as e:
            raise ThreatModelParseError(f"Meta validation error: {e}")
        
        assets = []
        for asset_data in data.get('assets', []):
            try:
                data_flows = [DataFlow(**df) for df in asset_data.get('dataFlows', [])]
                asset_data['dataFlows'] = data_flows
                assets.append(Asset(**asset_data))
            except ValidationError as e:
                raise ThreatModelParseError(f"Asset validation error: {e}")
        
        attackers = []
        for attacker_data in data.get('attackers', []):
            try:
                if 'ID' in attacker_data and 'REFID' not in attacker_data:
                    attacker_data['REFID'] = attacker_data.pop('ID')
                attackers.append(Attacker(**attacker_data))
            except ValidationError as e:
                raise ThreatModelParseError(f"Attacker validation error: {e}")
        
        security_objectives = []
        for obj_data in data.get('securityObjectives', []):
            try:
                security_objectives.append(SecurityObjective(**obj_data))
            except ValidationError as e:
                raise ThreatModelParseError(f"Security objective validation error: {e}")
        
        cm_lookup = {cm['ID']: cm for cm in data.get('countermeasures', [])}
        
        threats = []
        for threat_data in data.get('threats', []):
            threat_id = threat_data.get('ID', 'UNKNOWN')
            expanded_cms = self._expand_countermeasures(threat_data, cm_lookup, threat_id)
            threat_data['countermeasures'] = expanded_cms
            threat_data = self._calculate_cvss_scores(threat_data)
            try:
                threats.append(Threat(**threat_data))
            except ValidationError as e:
                raise ThreatModelParseError(f"Threat '{threat_id}' validation error: {e}")
        
        if attackers:
            self._validate_attacker_references(threats, attackers)
        if security_objectives:
            self._validate_security_objective_references(threats, security_objectives)
        
        return ThreatModel(
            meta=meta, assets=assets, attackers=attackers,
            securityObjectives=security_objectives, threats=threats
        )
    
    def _expand_countermeasures(self, threat_data: dict, cm_lookup: dict, threat_id: str) -> list:
        expanded = []
        for cm_ref in threat_data.get('countermeasures', []):
            if isinstance(cm_ref, dict):
                if 'ID' in cm_ref and len(cm_ref) == 1:
                    cm_id = cm_ref['ID']
                    if cm_id in cm_lookup:
                        expanded.append(cm_lookup[cm_id])
                    else:
                        raise ThreatModelParseError(
                            f"Threat '{threat_id}' references undefined countermeasure: {cm_id}"
                        )
                else:
                    expanded.append(cm_ref)
            elif isinstance(cm_ref, str):
                if cm_ref in cm_lookup:
                    expanded.append(cm_lookup[cm_ref])
                else:
                    raise ThreatModelParseError(
                        f"Threat '{threat_id}' references undefined countermeasure: {cm_ref}"
                    )
        return expanded
    
    def _parse_multi_file(self) -> ThreatModel:
        meta_data = self._load_yaml('_meta.yaml')
        if not meta_data:
            raise ThreatModelParseError("_meta.yaml is empty or invalid")
        
        try:
            meta = ThreatModelMeta(**meta_data)
        except ValidationError as e:
            raise ThreatModelParseError(f"_meta.yaml validation error: {e}")
        
        assets_data = self._load_yaml('assets.yaml') or {}
        assets = []
        for asset_data in assets_data.get('assets', []):
            try:
                data_flows = [DataFlow(**df) for df in asset_data.get('dataFlows', [])]
                asset_data['dataFlows'] = data_flows
                assets.append(Asset(**asset_data))
            except ValidationError as e:
                raise ThreatModelParseError(f"Asset validation error: {e}")
        
        attackers_data = self._load_yaml('attackers.yaml') or {}
        attackers = []
        for attacker_data in attackers_data.get('attackers', []):
            try:
                attackers.append(Attacker(**attacker_data))
            except ValidationError as e:
                raise ThreatModelParseError(f"Attacker validation error: {e}")
        
        objectives_data = self._load_yaml('security-objectives.yaml') or {}
        security_objectives = []
        for obj_data in objectives_data.get('securityObjectives', []):
            try:
                security_objectives.append(SecurityObjective(**obj_data))
            except ValidationError as e:
                raise ThreatModelParseError(f"Security objective validation error: {e}")
        
        cm_data = self._load_yaml('countermeasures.yaml') or {}
        cm_lookup = {cm['ID']: cm for cm in cm_data.get('countermeasures', [])}
        
        threats_data = self._load_yaml('threats.yaml') or {}
        threats = []
        for threat_data in threats_data.get('threats', []):
            threat_id = threat_data.get('ID', 'UNKNOWN')
            expanded_cms = self._expand_countermeasures(threat_data, cm_lookup, threat_id)
            threat_data['countermeasures'] = expanded_cms
            threat_data = self._calculate_cvss_scores(threat_data)
            try:
                threats.append(Threat(**threat_data))
            except ValidationError as e:
                raise ThreatModelParseError(f"Threat '{threat_id}' validation error: {e}")
        
        if attackers:
            self._validate_attacker_references(threats, attackers)
        if security_objectives:
            self._validate_security_objective_references(threats, security_objectives)
        
        return ThreatModel(
            meta=meta, assets=assets, attackers=attackers,
            securityObjectives=security_objectives, threats=threats
        )


def load_threat_model(model_path: str | Path) -> ThreatModel:
    """Load and validate a threat model from a folder path."""
    parser = ThreatModelParser(Path(model_path))
    return parser.parse()


def discover_threat_models(base_path: str | Path, recursive: bool = True) -> list[dict]:
    """
    Discover all threat model folders in a base directory.
    
    Args:
        base_path: Root directory to search for threat models
        recursive: If True, search nested directories recursively
        
    Returns:
        List of dicts with model info: {'path': Path, 'depth': int, 'hierarchy': list[str]}
    """
    base = Path(base_path).resolve()
    models = []
    
    if not base.exists():
        return models
    
    if recursive:
        # Find all threat-model.yaml files recursively
        for yaml_file in base.rglob('threat-model.yaml'):
            model_folder = yaml_file.parent
            rel_path = model_folder.relative_to(base)
            hierarchy = list(rel_path.parts)
            models.append({
                'path': model_folder,
                'rel_path': rel_path,
                'depth': len(hierarchy),
                'hierarchy': hierarchy,
                'name': model_folder.name
            })
        
        # Also check for _meta.yaml based models
        for meta_file in base.rglob('_meta.yaml'):
            model_folder = meta_file.parent
            # Skip if we already found a threat-model.yaml in this folder
            if any(m['path'] == model_folder for m in models):
                continue
            rel_path = model_folder.relative_to(base)
            hierarchy = list(rel_path.parts)
            models.append({
                'path': model_folder,
                'rel_path': rel_path,
                'depth': len(hierarchy),
                'hierarchy': hierarchy,
                'name': model_folder.name
            })
    else:
        # Non-recursive: only immediate children
        for item in base.iterdir():
            if item.is_dir():
                if (item / 'threat-model.yaml').exists() or (item / '_meta.yaml').exists():
                    models.append({
                        'path': item,
                        'rel_path': item.relative_to(base),
                        'depth': 1,
                        'hierarchy': [item.name],
                        'name': item.name
                    })
    
    # Sort by hierarchy for consistent ordering (nested models appear after parents)
    return sorted(models, key=lambda m: (m['hierarchy'], m['name']))


def calculate_relative_path(from_model: Path, to_model: Path, base_path: Path) -> str:
    """
    Calculate the relative path from one model's report to another.
    
    Args:
        from_model: Path to the source model folder
        to_model: Path to the target model folder
        base_path: Common base path for all models
        
    Returns:
        Relative path string from source report to target report
    """
    # Both paths are relative to base_path
    from_rel = from_model.relative_to(base_path)
    to_rel = to_model.relative_to(base_path)
    
    # We're in from_model/reports/threat-model.html
    # We want to get to to_model/reports/threat-model.html
    
    # Go up from reports folder, then up through from_model hierarchy
    ups = ['..'] * (len(from_rel.parts) + 1)  # +1 for 'reports' folder
    
    # Then navigate down to target
    path_parts = list(to_rel.parts) + ['reports', 'threat-model.html']
    
    return '/'.join(ups + path_parts)


def build_model_tree(models: list[dict]) -> dict:
    """
    Build a hierarchical tree structure from flat model list.
    
    Args:
        models: List of model dicts from discover_threat_models
        
    Returns:
        Nested dict representing the folder hierarchy with models
    """
    tree = {'children': {}, 'models': []}
    
    for model in models:
        current = tree
        for part in model['hierarchy'][:-1]:  # Navigate to parent folders
            if part not in current['children']:
                current['children'][part] = {'children': {}, 'models': []}
            current = current['children'][part]
        
        # Add model to its parent folder
        current['models'].append(model)
    
    return tree

