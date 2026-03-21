"""HTML report generator for threat models."""

from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

from .schemas import ThreatModel, DataFlow
from .dfd_generator import DFDGenerator
from .attack_tree import AttackTreeGenerator, generate_per_asset_attack_trees


class ReportGenerator:
    """Generates static HTML reports from threat models."""
    
    def __init__(self, template_dir: Optional[Path] = None):
        if template_dir is None:
            template_dir = Path(__file__).parent / 'templates'
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
    
    def _collect_data_flows(self, model: ThreatModel) -> list[DataFlow]:
        flows = []
        for asset in model.assets:
            flows.extend(asset.dataFlows)
        return flows
    
    def _count_countermeasures(self, model: ThreatModel) -> dict:
        counts = {'in_place': 0, 'planned': 0, 'not_started': 0, 'total': 0}
        for threat in model.threats:
            for cm in threat.countermeasures:
                counts['total'] += 1
                if cm.status in counts:
                    counts[cm.status] += 1
        return counts
    
    def _count_mitigated(self, model: ThreatModel) -> int:
        return sum(1 for t in model.threats if t.fullyMitigated)
    
    def generate(self, model: ThreatModel, all_models: Optional[list[dict]] = None) -> str:
        dfd_generator = DFDGenerator(model)
        data_flows = self._collect_data_flows(model)
        has_data_flows = len(data_flows) > 0
        dfd_mermaid = Markup(dfd_generator.to_mermaid()) if has_data_flows else ''
        
        # Generate PlantUML diagrams with threat risk highlighting
        dfd_plantuml = dfd_generator.to_plantuml(model.threats) if has_data_flows else ''
        dfd_plantuml_sequence = dfd_generator.to_plantuml_sequence(model.threats) if has_data_flows else ''
        
        attack_tree_generator = AttackTreeGenerator(model)
        attack_tree_mermaid = Markup(attack_tree_generator.to_mermaid()) if model.threats else ''
        attack_tree_text = attack_tree_generator.to_text() if model.threats else ''

        attack_tree_html = ''
        if model.threats:
            attack_tree_html = Markup(
                '<div class="diagram-container attack-tree-container">'
                '<div class="mermaid" data-diagram-id="attack-tree-mermaid">'
                f'{attack_tree_mermaid}'
                '</div>'
                '</div>'
            )
        
        cm_counts = self._count_countermeasures(model)
        mitigated_count = self._count_mitigated(model)
        
        unmitigated_threats = []
        for threat in model.threats:
            if not threat.fullyMitigated:
                threat_dict = threat.model_dump()
                cvss_score = threat.CVSS.score if threat.CVSS and threat.CVSS.score else 0.0
                threat_dict['cvss_score'] = cvss_score
                unmitigated_threats.append(threat_dict)
        unmitigated_threats.sort(key=lambda x: x['cvss_score'], reverse=True)
        
        threats_with_scores = []
        for threat in model.threats:
            t = threat.model_dump()
            cvss_score = threat.CVSS.score if threat.CVSS and threat.CVSS.score else 0.0
            t['cvss_score'] = cvss_score
            threats_with_scores.append(t)
        
        # Generate per-asset attack trees and threat mappings
        per_asset_data = generate_per_asset_attack_trees(model)
        
        # Build asset_sections list for template with serialized data
        asset_sections = []
        for asset_id, data in per_asset_data.items():
            asset = data['asset']
            threats = data['threats']
            
            # Build threat details with CVSS scores
            threat_details = []
            mitigated_count = 0
            max_cvss = 0.0
            for threat in threats:
                cvss_score = threat.CVSS.score if threat.CVSS and threat.CVSS.score else 0.0
                if cvss_score > max_cvss:
                    max_cvss = cvss_score
                if threat.fullyMitigated:
                    mitigated_count += 1
                threat_details.append({
                    'threat': threat,
                    'cvss_score': cvss_score,
                })
            # Sort by CVSS score descending
            threat_details.sort(key=lambda x: x['cvss_score'], reverse=True)
            
            asset_sections.append({
                'asset': asset,
                'threats': threat_details,
                'threat_count': len(threats),
                'mitigated_count': mitigated_count,
                'max_cvss': max_cvss,
                'mermaid': data.get('mermaid', ''),
            })
        
        # Build threat-to-assets mapping for display in threat cards
        threat_assets_map = {}
        for asset in model.assets:
            asset_id = asset.ID
            for threat in model.threats:
                # Check if threat targets this asset (simplified - checks ID references)
                threat_id = threat.ID
                if threat_id not in threat_assets_map:
                    threat_assets_map[threat_id] = []
                # Check per_asset_data to see if this threat is associated with this asset
                if asset_id in per_asset_data:
                    asset_threats = per_asset_data[asset_id]['threats']
                    if any(t.ID == threat_id for t in asset_threats):
                        threat_assets_map[threat_id].append({
                            'id': asset_id,
                            'name': asset.name,
                            'type': asset.type
                        })
        
        # Serialise custom (hand-crafted) diagram references for the template.
        # Each dict carries id, title, type, description, file path, placement,
        # and the raw PlantUML source loaded from the assets/ folder at parse time.
        custom_diagrams = [
            {
                'id': d.id,
                'title': d.title,
                'type': d.type or '',
                'description': d.description or '',
                'file': d.file,
                'placement': d.placement,
                'content': d.content or '',
            }
            for d in model.diagrams
        ]

        # Group by placement slot so the template just uses pre-bucketed lists —
        # placement logic lives here in Python, not scattered through Jinja2.
        def _slot(placement: str) -> list:
            return [d for d in custom_diagrams if d['placement'] == placement]

        # ── Composed-model summary ─────────────────────────────────────────────
        # Detect whether this is a composed model (has aspect-tagged entities).
        is_composed = bool(model.compose) or any(
            t.source_aspect for t in model.threats
        )
        aspects_summary: list[dict] = []
        if is_composed:
            aspect_data: defaultdict[str, Any] = defaultdict(lambda: {
                'threats': 0, 'assets': 0,
                'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
                'description': '',
            })
            for threat in model.threats:
                sa = threat.source_aspect or 'Root Model'
                aspect_data[sa]['threats'] += 1
                score = threat.CVSS.score if threat.CVSS and threat.CVSS.score else 0.0
                if score >= 9.0:
                    aspect_data[sa]['critical'] += 1
                elif score >= 7.0:
                    aspect_data[sa]['high'] += 1
                elif score >= 4.0:
                    aspect_data[sa]['medium'] += 1
                elif score > 0:
                    aspect_data[sa]['low'] += 1
            for asset in model.assets:
                sa = asset.source_aspect or 'Root Model'
                aspect_data[sa]['assets'] += 1
            for entry in model.compose:
                if entry.aspect in aspect_data and entry.description:
                    aspect_data[entry.aspect]['description'] = entry.description
            aspects_summary = [
                {'name': aspect_name, **data}
                for aspect_name, data in aspect_data.items()
            ]

        context = {
            'model': model,
            'all_models': all_models or [],
            'generation_timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'has_data_flows': has_data_flows,
            'dfd_mermaid': dfd_mermaid,
            'dfd_plantuml': dfd_plantuml,
            'dfd_plantuml_sequence': dfd_plantuml_sequence,
            'attack_tree_mermaid': attack_tree_mermaid,
            'attack_tree_html': attack_tree_html,
            'attack_tree_text': attack_tree_text,
            'data_flows': data_flows,
            'mitigated_count': mitigated_count,
            'countermeasure_count': cm_counts['total'],
            'cm_in_place': cm_counts['in_place'],
            'cm_planned': cm_counts['planned'],
            'cm_not_started': cm_counts['not_started'],
            'unmitigated_threats': unmitigated_threats,
            'threats_with_scores': threats_with_scores,
            'asset_sections': asset_sections,
            'threat_assets_map': threat_assets_map,
            # Full list used by the JS renderer (encodes all diagrams for PlantUML)
            'custom_diagrams': custom_diagrams,
            # Per-slot lists used by template insertion points
            'diagrams_before_attack_tree': _slot('before_attack_tree'),
            'diagrams_after_attack_tree':  _slot('after_attack_tree'),
            'diagrams_after_dfd':          _slot('after_dfd'),
            # Composed-model context
            'is_composed': is_composed,
            'aspects_summary': aspects_summary,
        }
        
        template = self.env.get_template('report.html')
        return template.render(**context)
    
    def generate_to_file(self, model: ThreatModel, output_path: Path, all_models: Optional[list[dict]] = None) -> Path:
        html_content = self.generate(model, all_models)
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return output_path


def generate_report(model: ThreatModel, output_path: Optional[Path] = None) -> str:
    """Generate an HTML report from a threat model."""
    generator = ReportGenerator()
    if output_path:
        generator.generate_to_file(model, output_path)
    return generator.generate(model)
