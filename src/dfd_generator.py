"""Data Flow Diagram (DFD) generator."""

from dataclasses import dataclass
from graphviz import Digraph

from .schemas import ThreatModel, Asset, DataFlow


@dataclass
class TrustBoundary:
    """A trust boundary grouping assets."""
    name: str
    assets: list[str]


class DFDGenerator:
    """Generates Data Flow Diagrams from threat model data."""
    
    ASSET_SHAPES = {
        'process': 'ellipse',
        'datastore': 'cylinder',
        'external_entity': 'box',
    }
    
    TRUST_ZONE_COLORS = {
        'trusted': '#d4edda',
        'untrusted': '#f8d7da',
        'dmz': '#fff3cd',
        'internal': '#cce5ff',
        'external': '#f5c6cb',
    }
    
    def __init__(self, threat_model: ThreatModel):
        self.model = threat_model
        self._asset_map = {asset.ID: asset for asset in threat_model.assets}
        self._trust_boundaries = self._extract_trust_boundaries()
    
    def _extract_trust_boundaries(self) -> dict[str, TrustBoundary]:
        boundaries: dict[str, list[str]] = {}
        for asset in self.model.assets:
            zone = asset.trustZone or 'default'
            if zone not in boundaries:
                boundaries[zone] = []
            boundaries[zone].append(asset.ID)
        return {name: TrustBoundary(name=name, assets=assets) for name, assets in boundaries.items()}
    
    def _get_all_data_flows(self) -> list[DataFlow]:
        flows = []
        for asset in self.model.assets:
            flows.extend(asset.dataFlows)
        return flows
    
    def _get_asset_shape(self, asset: Asset) -> str:
        return self.ASSET_SHAPES.get(asset.type, 'box')
    
    def _get_zone_color(self, zone: str) -> str:
        return self.TRUST_ZONE_COLORS.get(zone.lower(), '#ffffff')

    def _mermaid_id(self, value: str) -> str:
        safe = ''.join(ch if ch.isalnum() else '_' for ch in value.strip())
        if not safe:
            return 'ZONE'
        if safe[0].isdigit():
            return f'ZONE_{safe}'
        return safe
    
    def generate(self, output_format: str = 'svg') -> tuple[str, Digraph]:
        graph = Digraph(
            name=f'DFD_{self.model.meta.modelId}',
            comment=f'Data Flow Diagram: {self.model.meta.title}',
            format=output_format,
            engine='dot'
        )
        
        graph.attr(rankdir='LR', splines='ortho', nodesep='0.8', ranksep='1.2', fontname='Arial', fontsize='12')
        graph.attr('node', fontname='Arial', fontsize='10')
        graph.attr('edge', fontname='Arial', fontsize='9')
        
        for zone_name, boundary in self._trust_boundaries.items():
            with graph.subgraph(name=f'cluster_{zone_name}') as subgraph:
                subgraph.attr(
                    label=f'Trust Zone: {zone_name}',
                    style='dashed',
                    color='red' if zone_name.lower() == 'untrusted' else 'blue',
                    bgcolor=self._get_zone_color(zone_name),
                    fontsize='11',
                    fontcolor='#333333'
                )
                for asset_id in boundary.assets:
                    asset = self._asset_map.get(asset_id)
                    if asset:
                        subgraph.node(
                            asset.ID,
                            label=f'{asset.name}\n[{asset.type}]',
                            shape=self._get_asset_shape(asset),
                            style='filled',
                            fillcolor='white',
                            tooltip=asset.description or asset.name
                        )
        
        for flow in self._get_all_data_flows():
            edge_attrs = {
                'label': flow.name,
                'tooltip': f'{flow.protocol or "N/A"} - {flow.dataClassification or "unclassified"}',
            }
            if flow.crossesTrustBoundary:
                edge_attrs.update(color='red', penwidth='2.0', style='bold', label=f'{flow.name}\n! CROSSES BOUNDARY')
            else:
                edge_attrs['color'] = '#666666'
            graph.edge(flow.source, flow.destination, **edge_attrs)
        
        return graph.source, graph
    
    def generate_dot(self) -> str:
        source, _ = self.generate()
        return source
    
    def render_to_file(self, output_path: str, output_format: str = 'svg') -> str:
        _, graph = self.generate(output_format)
        return graph.render(output_path, cleanup=True)
    
    def to_mermaid(self) -> str:
        # LR = Left-to-Right (horizontal orientation for better readability)
        lines = ['flowchart LR']
        for zone_name, boundary in self._trust_boundaries.items():
            safe_zone = self._safe_label(zone_name)
            zone_id = self._mermaid_id(zone_name)
            lines.append(f'    subgraph {zone_id}["{safe_zone}"]')
            for asset_id in boundary.assets:
                asset = self._asset_map.get(asset_id)
                if asset:
                    safe_name = self._safe_label(asset.name)
                    safe_asset_id = self._mermaid_id(asset.ID)
                    shape = self._mermaid_shape(asset.type)
                    lines.append(f'        {safe_asset_id}{shape[0]}"{safe_name}"{shape[1]}')
            lines.append('    end')
        for flow in self._get_all_data_flows():
            # Skip flows with undefined source or destination nodes
            if flow.source not in self._asset_map or flow.destination not in self._asset_map:
                continue
            safe_flow_name = self._safe_label(flow.name)
            safe_source = self._mermaid_id(flow.source)
            safe_dest = self._mermaid_id(flow.destination)
            arrow = '-->' if not flow.crossesTrustBoundary else '-.->'
            lines.append(f'    {safe_source} {arrow}|{safe_flow_name}| {safe_dest}')
        lines.append('')
        lines.append('    classDef boundary stroke:#f00,stroke-width:2px')
        return '\n'.join(lines)
    
    def _safe_label(self, text: str) -> str:
        """Escape special characters in Mermaid labels."""
        if not text:
            return ""
        # Remove or replace problematic characters
        return text.replace('"', "'").replace('(', '').replace(')', '').replace('[', '').replace(']', '').replace('|', '-').replace('<', '').replace('>', '')
    
    def _mermaid_shape(self, asset_type: str) -> tuple[str, str]:
        shapes = {
            'process': ('((', '))'),
            'datastore': ('[(', ')]'),
            'external_entity': ('[', ']'),
        }
        return shapes.get(asset_type, ('[', ']'))

    def to_plantuml(self, threats: list = None) -> str:
        """Generate PlantUML sequence/component diagram showing dataflows with risk highlighting.
        
        Args:
            threats: Optional list of Threat objects to correlate with assets for risk highlighting.
        """
        lines = ['@startuml', '']
        
        # Title and styling
        lines.append(f'title {self.model.meta.title} - Data Flow Diagram')
        lines.append('')
        lines.append('!define CRITICAL_COLOR #FF6B6B')
        lines.append('!define HIGH_COLOR #FFA500')
        lines.append('!define MEDIUM_COLOR #FFD93D')
        lines.append('!define LOW_COLOR #6BCB77')
        lines.append('!define TRUST_BOUNDARY_COLOR #E8E8E8')
        lines.append('')
        
        # Skinparam styling
        lines.append('skinparam {')
        lines.append('    BackgroundColor white')
        lines.append('    ArrowColor #333333')
        lines.append('    ArrowFontSize 10')
        lines.append('    ParticipantBorderColor #2c3e50')
        lines.append('    ParticipantBackgroundColor #ecf0f1')
        lines.append('    ParticipantFontColor #2c3e50')
        lines.append('    NoteBackgroundColor #fffde7')
        lines.append('    NoteBorderColor #ffc107')
        lines.append('    RectangleBorderColor #2c3e50')
        lines.append('    RectangleBorderStyle dashed')
        lines.append('}')
        lines.append('')
        
        # Build asset risk scores from threats
        asset_risk_scores = {}
        if threats:
            for threat in threats:
                cvss_score = 0.0
                if threat.CVSS and threat.CVSS.score:
                    cvss_score = threat.CVSS.score
                # Map threat to assets based on title/description
                for asset in self.model.assets:
                    if asset.name.lower() in threat.title.lower() or asset.ID.lower() in threat.title.lower():
                        if asset.ID not in asset_risk_scores:
                            asset_risk_scores[asset.ID] = []
                        asset_risk_scores[asset.ID].append(cvss_score)
        
        # Calculate max risk per asset
        asset_max_risk = {aid: max(scores) if scores else 0.0 for aid, scores in asset_risk_scores.items()}
        
        # Define participants grouped by trust zone
        lines.append("' === TRUST ZONES AND PARTICIPANTS ===")
        
        for zone_name, boundary in self._trust_boundaries.items():
            zone_display = zone_name.replace('_', ' ').title()
            is_untrusted = zone_name.lower() in ['untrusted', 'external', 'external cloud']
            
            lines.append(f'rectangle "{zone_display}" as zone_{self._sanitize_id(zone_name)} <<trust_zone>> {{')
            
            for asset_id in boundary.assets:
                asset = self._asset_map.get(asset_id)
                if asset:
                    participant_type = self._get_puml_participant_type(asset.type)
                    safe_id = self._sanitize_id(asset_id)
                    safe_name = asset.name.replace('"', "'")
                    
                    # Determine color based on risk
                    max_risk = asset_max_risk.get(asset_id, 0.0)
                    if max_risk >= 9.0:
                        color = ' CRITICAL_COLOR'
                    elif max_risk >= 7.0:
                        color = ' HIGH_COLOR'
                    elif max_risk >= 4.0:
                        color = ' MEDIUM_COLOR'
                    elif max_risk > 0:
                        color = ' LOW_COLOR'
                    elif is_untrusted:
                        color = ' #f5c6cb'
                    else:
                        color = ''
                    
                    lines.append(f'    {participant_type} "{safe_name}" as {safe_id}{color}')
            
            lines.append('}')
            lines.append('')
        
        # Data flows
        lines.append("' === DATA FLOWS ===")
        
        # Collect and categorize flows
        critical_flows = []
        boundary_crossing_flows = []
        normal_flows = []
        
        all_flows = self._get_all_data_flows()
        for flow in all_flows:
            if flow.crossesTrustBoundary:
                boundary_crossing_flows.append(flow)
            elif flow.dataClassification and flow.dataClassification.lower() in ['secret', 'confidential']:
                critical_flows.append(flow)
            else:
                normal_flows.append(flow)
        
        # Render flows with appropriate styling
        for flow in normal_flows:
            src = self._sanitize_id(flow.source)
            dst = self._sanitize_id(flow.destination)
            label = flow.name
            protocol = f' ({flow.protocol})' if flow.protocol else ''
            lines.append(f'{src} --> {dst} : {label}{protocol}')
        
        for flow in critical_flows:
            src = self._sanitize_id(flow.source)
            dst = self._sanitize_id(flow.destination)
            label = flow.name
            protocol = f' ({flow.protocol})' if flow.protocol else ''
            classification = flow.dataClassification or 'sensitive'
            lines.append(f'{src} -[#FFA500]-> {dst} : <color:orange>{label}</color>{protocol}\\n[{classification}]')
        
        for flow in boundary_crossing_flows:
            src = self._sanitize_id(flow.source)
            dst = self._sanitize_id(flow.destination)
            label = flow.name
            protocol = f' ({flow.protocol})' if flow.protocol else ''
            boundary = f' [{flow.trustBoundary}]' if flow.trustBoundary else ''
            lines.append(f'{src} -[#FF0000,bold]-> {dst} : <color:red><b>{label}</b></color>{protocol}\\n!! CROSSES BOUNDARY{boundary}')
        
        # Add legend
        lines.append('')
        lines.append("' === LEGEND ===")
        lines.append('legend right')
        lines.append('    |= Color |= Meaning |')
        lines.append('    | <back:CRITICAL_COLOR>    </back> | Critical Risk (CVSS 9.0+) |')
        lines.append('    | <back:HIGH_COLOR>    </back> | High Risk (CVSS 7.0-8.9) |')
        lines.append('    | <back:MEDIUM_COLOR>    </back> | Medium Risk (CVSS 4.0-6.9) |')
        lines.append('    | <back:LOW_COLOR>    </back> | Low Risk (CVSS < 4.0) |')
        lines.append('    | <color:red>——></color> | Crosses Trust Boundary |')
        lines.append('    | <color:orange>——></color> | Sensitive Data Flow |')
        lines.append('endlegend')
        
        # Footer with metadata
        lines.append('')
        lines.append(f'footer Generated from {self.model.meta.modelId} v{self.model.meta.version}')
        lines.append('')
        lines.append('@enduml')
        
        return '\n'.join(lines)
    
    def _sanitize_id(self, id_str: str) -> str:
        """Sanitize an ID for PlantUML (alphanumeric and underscore only)."""
        return ''.join(c if c.isalnum() or c == '_' else '_' for c in id_str)
    
    def _get_puml_participant_type(self, asset_type: str) -> str:
        """Get PlantUML component type for an asset type."""
        type_map = {
            'process': 'component',
            'datastore': 'database',
            'external_entity': 'actor',
            'device': 'node',
            'identity provider': 'component',
            'code repository': 'folder',
            'build system': 'component',
            'artifact store': 'artifact',
            'container runtime': 'node',
            'cloud infrastructure': 'cloud',
            'saas application': 'component',
            'ai service': 'component',
            'external service': 'actor',
            'security service': 'component',
            'physical location': 'rectangle',
            'data asset': 'storage',
        }
        return type_map.get(asset_type.lower(), 'component')

    def to_plantuml_sequence(self, threats: list = None) -> str:
        """Generate PlantUML sequence diagram showing dataflow interactions.
        
        This provides a more action-oriented view of how data flows between components.
        """
        lines = ['@startuml', '']
        
        # Title
        lines.append(f'title {self.model.meta.title} - Dataflow Sequence')
        lines.append('')
        
        # Styling
        lines.append('skinparam {')
        lines.append('    ParticipantBorderColor #2c3e50')
        lines.append('    ParticipantBackgroundColor #ecf0f1')
        lines.append('    SequenceArrowColor #333333')
        lines.append('    SequenceLifeLineBorderColor #bdc3c7')
        lines.append('    NoteBackgroundColor #fff3cd')
        lines.append('    NoteBorderColor #ffc107')
        lines.append('}')
        lines.append('')
        
        # Build threat map for asset risk
        asset_threat_map = {}
        if threats:
            for threat in threats:
                cvss = threat.CVSS.score if threat.CVSS and threat.CVSS.score else 0.0
                for asset in self.model.assets:
                    if asset.name.lower() in threat.title.lower():
                        if asset.ID not in asset_threat_map:
                            asset_threat_map[asset.ID] = []
                        asset_threat_map[asset.ID].append({
                            'title': threat.title,
                            'cvss': cvss,
                            'mitigated': threat.fullyMitigated
                        })
        
        # Group participants by trust zone with box separators
        for zone_name, boundary in self._trust_boundaries.items():
            zone_display = zone_name.replace('_', ' ').title()
            lines.append(f'box "{zone_display}" #{"f8d7da" if zone_name.lower() in ["untrusted", "external"] else "d4edda"}')
            
            for asset_id in boundary.assets:
                asset = self._asset_map.get(asset_id)
                if asset:
                    safe_id = self._sanitize_id(asset_id)
                    safe_name = asset.name.replace('"', "'")
                    participant_type = 'participant'
                    if asset.type.lower() in ['datastore', 'database']:
                        participant_type = 'database'
                    elif asset.type.lower() in ['external_entity', 'external service']:
                        participant_type = 'actor'
                    elif asset.type.lower() in ['device']:
                        participant_type = 'entity'
                    
                    lines.append(f'    {participant_type} "{safe_name}" as {safe_id}')
            
            lines.append('end box')
            lines.append('')
        
        # Define the sequence of dataflows
        lines.append("== Data Flow Interactions ==")
        lines.append('')
        
        all_flows = self._get_all_data_flows()
        
        # Sort flows: boundary-crossing first (highlighted), then by classification
        flows_sorted = sorted(all_flows, key=lambda f: (
            not f.crossesTrustBoundary,
            f.dataClassification != 'Secret',
            f.dataClassification != 'Confidential'
        ))
        
        for flow in flows_sorted:
            src = self._sanitize_id(flow.source)
            dst = self._sanitize_id(flow.destination)
            label = flow.name
            protocol = flow.protocol or 'N/A'
            classification = flow.dataClassification or 'unclassified'
            
            if flow.crossesTrustBoundary:
                # Red arrow for trust boundary crossing
                lines.append(f'{src} -[#FF0000]> {dst}: <color:red><b>{label}</b></color>\\n({protocol})')
                lines.append(f'note right #FFCCCC')
                lines.append(f'    **⚠ CROSSES TRUST BOUNDARY**')
                lines.append(f'    Classification: {classification}')
                if flow.trustBoundary:
                    lines.append(f'    Boundary: {flow.trustBoundary}')
                lines.append('end note')
            elif classification.lower() in ['secret', 'confidential']:
                # Orange arrow for sensitive data
                lines.append(f'{src} -[#FFA500]> {dst}: <color:orange>{label}</color>\\n({protocol})')
                lines.append(f'note right #FFF3CD')
                lines.append(f'    Classification: {classification}')
                lines.append('end note')
            else:
                lines.append(f'{src} -> {dst}: {label}\\n({protocol})')
        
        # Add threat annotations for high-risk assets
        if asset_threat_map:
            lines.append('')
            lines.append('== High-Risk Areas ==')
            for asset_id, threat_list in asset_threat_map.items():
                high_risk = [t for t in threat_list if t['cvss'] >= 7.0 and not t['mitigated']]
                if high_risk:
                    safe_id = self._sanitize_id(asset_id)
                    lines.append(f'note over {safe_id} #FFCCCC')
                    lines.append('    **⚠ HIGH RISK THREATS:**')
                    for t in high_risk[:3]:  # Show top 3
                        lines.append(f'    • {t["title"][:40]}... (CVSS: {t["cvss"]:.1f})')
                    lines.append('end note')
        
        # Footer
        lines.append('')
        lines.append(f'footer Model: {self.model.meta.modelId} | Version: {self.model.meta.version}')
        lines.append('')
        lines.append('@enduml')
        
        return '\n'.join(lines)


def generate_dfd(threat_model: ThreatModel, output_format: str = 'svg') -> str:
    """Generate a DFD DOT source from a threat model."""
    generator = DFDGenerator(threat_model)
    return generator.generate_dot()


def generate_dfd_plantuml(threat_model: ThreatModel, threats: list = None) -> str:
    """Generate a PlantUML DFD diagram from a threat model."""
    generator = DFDGenerator(threat_model)
    return generator.to_plantuml(threats)


def generate_dfd_plantuml_sequence(threat_model: ThreatModel, threats: list = None) -> str:
    """Generate a PlantUML sequence diagram from a threat model."""
    generator = DFDGenerator(threat_model)
    return generator.to_plantuml_sequence(threats)
