"""Attack tree generator for threat models."""

from dataclasses import dataclass, field
from typing import Optional
from graphviz import Digraph

from .schemas import ThreatModel, Threat, Countermeasure


@dataclass
class AttackNode:
    """A node in the attack tree."""
    id: str
    label: str
    node_type: str
    children: list['AttackNode'] = field(default_factory=list)
    mitigated: bool = False
    threat_ref: Optional[str] = None
    cvss_score: float = 0.0
    security_objectives: list[str] = field(default_factory=list)


class AttackTreeGenerator:
    """Generates attack trees from threat model data."""
    
    def __init__(self, threat_model: ThreatModel):
        self.model = threat_model
        self._objective_map = {obj.ID: obj for obj in threat_model.securityObjectives}
        self._asset_map = {asset.ID: asset for asset in threat_model.assets}
    
    def _safe_id(self, value: str) -> str:
        """Convert an ID to a Mermaid-safe node ID (alphanumeric and underscores only)."""
        return ''.join(ch if ch.isalnum() else '_' for ch in value)
    
    def _wrap_text(self, text: str, width: int = 30) -> str:
        """Truncate text to specified width."""
        if not text:
            return ""
        if len(text) <= width:
            return text
        return text[:width-3] + "..."
    
    def _get_cvss_score(self, threat: Threat) -> float:
        if not threat.CVSS:
            return 0.0
        if hasattr(threat.CVSS, 'score') and threat.CVSS.score is not None:
            return float(threat.CVSS.score)
        try:
            cvss_str = str(threat.CVSS)
            if hasattr(threat.CVSS, 'vector'):
                cvss_str = threat.CVSS.vector
            if '/' in cvss_str:
                return 7.0
            return float(cvss_str)
        except (ValueError, AttributeError):
            return 5.0
    
    def _find_asset_for_threat(self, threat: Threat) -> Optional[str]:
        threat_title_lower = threat.title.lower()
        
        for asset in self.model.assets:
            if asset.name.lower() in threat_title_lower:
                return asset.ID
        
        type_asset_map = {
            'xss': ['frontend', 'web', 'ui', 'browser', 'application'],
            'sql': ['database', 'db', 'postgresql', 'mysql', 'sql'],
            'injection': ['database', 'db', 'backend', 'api'],
            'access': ['admin', 'panel', 'auth', 'gateway'],
            'api': ['api', 'gateway', 'service', 'endpoint'],
            'dos': ['api', 'service', 'server', 'backend'],
            'denial': ['api', 'service', 'server', 'backend'],
            'breach': ['database', 'db', 'data', 'store'],
            'third': ['third', 'external', 'payment', 'stripe'],
            'party': ['third', 'external', 'payment', 'vendor'],
            'logging': ['backend', 'service', 'server'],
        }
        
        for keyword, asset_hints in type_asset_map.items():
            if keyword in threat_title_lower:
                for asset in self.model.assets:
                    asset_name_lower = asset.name.lower()
                    for hint in asset_hints:
                        if hint in asset_name_lower:
                            return asset.ID
        
        for asset in self.model.assets:
            if asset.type in ('process', 'datastore'):
                return asset.ID
        
        return self.model.assets[0].ID if self.model.assets else None
    
    def to_mermaid(self) -> str:
        """Generate Mermaid.js graph syntax for attack tree."""
        # LR = Left-to-Right (horizontal orientation like reference image)
        lines = ['graph LR']
        defined_nodes = set()
        defined_edges = set()
        
        asset_threats: dict[str, list[Threat]] = {}
        for threat in self.model.threats:
            asset_id = self._find_asset_for_threat(threat)
            if asset_id:
                if asset_id not in asset_threats:
                    asset_threats[asset_id] = []
                asset_threats[asset_id].append(threat)
        
        safe_title = self.model.meta.title.replace('"', "'").replace('(', '').replace(')', '')
        lines.append('')
        lines.append('    %% Threat Model Root')
        lines.append(f'    ROOT(["{safe_title}"])')
        defined_nodes.add('ROOT')
        
        lines.append('')
        lines.append('    %% Assets')
        for asset_id in asset_threats.keys():
            asset = self._asset_map.get(asset_id)
            if asset:
                safe_name = asset.name.replace('"', "'").replace('(', '').replace(')', '')
                node_id = f'A_{self._safe_id(asset_id)}'
                lines.append(f'    {node_id}["{safe_name}"]')
                lines.append(f'    ROOT --> {node_id}')
                defined_nodes.add(node_id)
        
        lines.append('')
        lines.append('    %% Threats')
        for asset_id, threats in asset_threats.items():
            asset_node_id = f'A_{self._safe_id(asset_id)}'
            for threat in threats:
                threat_id = f'T_{self._safe_id(threat.ID)}'
                if threat_id not in defined_nodes:
                    cvss_score = self._get_cvss_score(threat)
                    safe_threat_title = threat.title.replace('"', "'").replace('(', '').replace(')', '').replace('[', '').replace(']', '')
                    # Truncate title for readability
                    wrapped_title = self._wrap_text(safe_threat_title, 50)
                    # Color-code CVSS severity in label
                    severity = 'High' if cvss_score >= 7.0 else 'Medium' if cvss_score >= 4.0 else 'Low'
                    node_label = f"{wrapped_title} | {cvss_score:.1f} {severity}"
                    lines.append(f'    {threat_id}["{node_label}"]')
                    defined_nodes.add(threat_id)
                edge_key = f'{asset_node_id}->{threat_id}'
                if edge_key not in defined_edges:
                    lines.append(f'    {asset_node_id} --> {threat_id}')
                    defined_edges.add(edge_key)
        
        lines.append('')
        lines.append('    %% Mitigations')
        mitigation_styles = []
        for threat in self.model.threats:
            threat_id = f'T_{self._safe_id(threat.ID)}'
            for cm in threat.countermeasures:
                node_id = f'M_{self._safe_id(threat.ID)}_{self._safe_id(cm.ID)}'
                safe_title = cm.title.replace('"', "'").replace('(', '').replace(')', '').replace('[', '').replace(']', '')
                # Truncate for readability
                wrapped_cm = self._wrap_text(safe_title, 40)
                status_icon = 'DONE' if cm.status == 'in_place' else 'TODO'
                lines.append(f'    {node_id}(["{status_icon}: {wrapped_cm}"])')
                lines.append(f'    {threat_id} -.-> {node_id}')
                mitigation_styles.append({'node_id': node_id, 'status': cm.status})
        
        lines.append('')
        lines.append('    %% Styles')
        lines.append('    style ROOT fill:#2c3e50,stroke:#1a252f,color:#fff,stroke-width:3px')
        for asset_id in asset_threats.keys():
            lines.append(f'    style A_{self._safe_id(asset_id)} fill:#3498db,stroke:#2980b9,color:#fff')
        # Color threats based on CVSS severity (like reference image)
        for threat in self.model.threats:
            cvss_score = self._get_cvss_score(threat)
            if cvss_score >= 7.0:
                # High - Red/Orange
                lines.append(f'    style T_{self._safe_id(threat.ID)} fill:#e74c3c,stroke:#c0392b,color:#fff,stroke-width:2px')
            elif cvss_score >= 4.0:
                # Medium - Orange/Yellow
                lines.append(f'    style T_{self._safe_id(threat.ID)} fill:#f39c12,stroke:#d68910,color:#fff,stroke-width:2px')
            else:
                # Low - Yellow/Green
                lines.append(f'    style T_{self._safe_id(threat.ID)} fill:#f1c40f,stroke:#d4ac0d,color:#2c3e50,stroke-width:2px')
        for cm_style in mitigation_styles:
            node_id = cm_style['node_id']
            if cm_style['status'] == 'in_place':
                lines.append(f'    style {node_id} fill:#27ae60,stroke:#1e8449,color:#fff')
            else:
                lines.append(f'    style {node_id} fill:#f8f9fa,stroke:#7f8c8d,color:#2c3e50')
        
        return '\n'.join(lines)
    
    def _create_threat_subtree(self, threat: Threat) -> AttackNode:
        threat_node = AttackNode(
            id=f'threat_{threat.ID}',
            label=f'{threat.title}',
            node_type='attack',
            threat_ref=threat.ID,
            mitigated=threat.fullyMitigated
        )
        attack_node = AttackNode(
            id=f'attack_{threat.ID}',
            label=threat.attack,
            node_type='attack',
            threat_ref=threat.ID
        )
        for cm in threat.countermeasures:
            cm_node = AttackNode(
                id=f'cm_{cm.ID}',
                label=f'{cm.title}',
                node_type='countermeasure',
                mitigated=(cm.status == 'in_place')
            )
            attack_node.children.append(cm_node)
        threat_node.children.append(attack_node)
        return threat_node
    
    def _group_by_security_objective(self) -> dict[str, list[Threat]]:
        groups: dict[str, list[Threat]] = {'ungrouped': []}
        for threat in self.model.threats:
            if threat.impactedSecObj:
                for obj_id in threat.impactedSecObj:
                    if obj_id not in groups:
                        groups[obj_id] = []
                    groups[obj_id].append(threat)
            else:
                groups['ungrouped'].append(threat)
        if not groups['ungrouped']:
            del groups['ungrouped']
        return groups
    
    def generate_tree(self) -> AttackNode:
        root = AttackNode(
            id='root',
            label=f'Compromise: {self.model.meta.title}',
            node_type='goal'
        )
        groups = self._group_by_security_objective()
        for obj_id, threats in groups.items():
            if obj_id == 'ungrouped':
                obj_label = 'General Threats'
            else:
                obj = self._objective_map.get(obj_id)
                obj_label = obj.name if obj else obj_id
            obj_node = AttackNode(
                id=f'obj_{obj_id}',
                label=f'Impact: {obj_label}',
                node_type='or'
            )
            for threat in threats:
                threat_subtree = self._create_threat_subtree(threat)
                obj_node.children.append(threat_subtree)
            root.children.append(obj_node)
        return root
    
    def to_graphviz(self, output_format: str = 'svg') -> Digraph:
        tree = self.generate_tree()
        graph = Digraph(
            name=f'AttackTree_{self.model.meta.modelId}',
            comment=f'Attack Tree: {self.model.meta.title}',
            format=output_format,
            engine='dot'
        )
        graph.attr(rankdir='TB', splines='ortho', nodesep='0.5', ranksep='0.8', fontname='Arial', bgcolor='white')
        graph.attr('node', fontname='Arial', fontsize='10')
        graph.attr('edge', fontname='Arial', fontsize='8')
        self._add_node_to_graph(graph, tree)
        return graph
    
    def _add_node_to_graph(self, graph: Digraph, node: AttackNode, parent_id: Optional[str] = None) -> None:
        styles = {
            'goal': {'shape': 'invhouse', 'fillcolor': '#ffcccc', 'style': 'filled'},
            'or': {'shape': 'triangle', 'fillcolor': '#ffffcc', 'style': 'filled', 'label': 'OR'},
            'and': {'shape': 'invtriangle', 'fillcolor': '#ccffcc', 'style': 'filled', 'label': 'AND'},
            'attack': {'shape': 'box', 'fillcolor': '#ffdddd', 'style': 'filled,rounded'},
            'countermeasure': {'shape': 'octagon', 'fillcolor': '#ddffdd', 'style': 'filled'},
        }
        style = styles.get(node.node_type, {}).copy()
        if node.mitigated:
            style['fillcolor'] = '#aaffaa'
            style['penwidth'] = '2'
        node_label = style.pop('label', node.label)
        if node.node_type not in ('or', 'and'):
            node_label = node.label
        graph.node(node.id, label=node_label, **style)
        if parent_id:
            edge_style = {}
            if node.node_type == 'countermeasure':
                edge_style = {'style': 'dashed', 'color': 'green', 'label': 'mitigates'}
            graph.edge(parent_id, node.id, **edge_style)
        for child in node.children:
            self._add_node_to_graph(graph, child, node.id)
    
    def render_to_file(self, output_path: str, output_format: str = 'svg') -> str:
        graph = self.to_graphviz(output_format)
        return graph.render(output_path, cleanup=True)
    
    def to_text(self, indent: int = 0) -> str:
        tree = self.generate_tree()
        return self._node_to_text(tree, indent)
    
    def _node_to_text(self, node: AttackNode, indent: int = 0) -> str:
        prefix = '  ' * indent
        icon = {'goal': '[G]', 'or': '[OR]', 'and': '[AND]', 'attack': '[A]', 'countermeasure': '[M]'}.get(node.node_type, '*')
        status = ' [MITIGATED]' if node.mitigated else ''
        line = f'{prefix}{icon} {node.label}{status}'
        lines = [line]
        for child in node.children:
            lines.append(self._node_to_text(child, indent + 1))
        return '\n'.join(lines)


def generate_attack_tree(threat_model: ThreatModel) -> str:
    """Generate attack tree Mermaid syntax from a threat model."""
    generator = AttackTreeGenerator(threat_model)
    return generator.to_mermaid()


def generate_per_asset_attack_trees(threat_model: ThreatModel) -> dict[str, dict]:
    """Generate attack trees and threat lists for each asset.
    
    Returns a dict keyed by asset ID, each containing:
      - 'asset': the Asset object
      - 'threats': list of Threat objects associated with this asset
      - 'mermaid': Mermaid diagram string for this asset's attack tree
    """
    generator = AttackTreeGenerator(threat_model)
    
    # Build asset -> threats mapping
    asset_threats: dict[str, list] = {asset.ID: [] for asset in threat_model.assets}
    
    for threat in threat_model.threats:
        asset_id = generator._find_asset_for_threat(threat)
        if asset_id and asset_id in asset_threats:
            asset_threats[asset_id].append(threat)
    
    result = {}
    for asset in threat_model.assets:
        threats = asset_threats.get(asset.ID, [])
        mermaid_code = _generate_asset_attack_tree_mermaid(asset, threats, generator)
        result[asset.ID] = {
            'asset': asset,
            'threats': threats,
            'mermaid': mermaid_code
        }
    
    return result


def _generate_asset_attack_tree_mermaid(asset, threats: list, generator: AttackTreeGenerator) -> str:
    """Generate a Mermaid attack tree diagram for a single asset."""
    if not threats:
        return ''
    
    lines = ['graph LR']
    
    # Asset as root - use double parentheses for stadium shape
    safe_name = asset.name.replace('"', "'").replace('(', '').replace(')', '')
    asset_node_id = f'ASSET_{asset.ID}'
    lines.append('')
    lines.append('    %% Asset Root')
    lines.append(f'    {asset_node_id}(["{safe_name}"])')
    lines.append(f'    style {asset_node_id} fill:#3498db,stroke:#2980b9,color:#fff,stroke-width:3px')
    
    # Threats
    lines.append('')
    lines.append('    %% Threats')
    for threat in threats:
        threat_id = f'T_{threat.ID}'
        cvss_score = generator._get_cvss_score(threat)
        safe_title = threat.title.replace('"', "'").replace('(', '').replace(')', '')
        wrapped_title = generator._wrap_text(safe_title, 40)
        severity = 'Critical' if cvss_score >= 9.0 else 'High' if cvss_score >= 7.0 else 'Medium' if cvss_score >= 4.0 else 'Low'
        node_label = f"{wrapped_title}<br/>CVSS: {cvss_score:.1f} - {severity}"
        lines.append(f'    {threat_id}["{node_label}"]')
        lines.append(f'    {asset_node_id} --> {threat_id}')
        
        # Style based on CVSS
        if cvss_score >= 9.0:
            lines.append(f'    style {threat_id} fill:#8B0000,stroke:#5c0000,color:#fff,stroke-width:2px')
        elif cvss_score >= 7.0:
            lines.append(f'    style {threat_id} fill:#e74c3c,stroke:#c0392b,color:#fff,stroke-width:2px')
        elif cvss_score >= 4.0:
            lines.append(f'    style {threat_id} fill:#f39c12,stroke:#d68910,color:#fff,stroke-width:2px')
        else:
            lines.append(f'    style {threat_id} fill:#f1c40f,stroke:#d4ac0d,color:#2c3e50,stroke-width:2px')
    
    # Countermeasures
    lines.append('')
    lines.append('    %% Countermeasures')
    for threat in threats:
        threat_id = f'T_{threat.ID}'
        for cm in threat.countermeasures:
            cm_node_id = f'CM_{threat.ID}_{cm.ID}'
            safe_cm_title = cm.title.replace('"', "'").replace('(', '').replace(')', '')
            wrapped_cm = generator._wrap_text(safe_cm_title, 35)
            status_icon = '✓' if cm.status == 'in_place' else '○'
            lines.append(f'    {cm_node_id}(["{status_icon} {wrapped_cm}"])')
            lines.append(f'    {threat_id} -.-> {cm_node_id}')
            
            if cm.status == 'in_place':
                lines.append(f'    style {cm_node_id} fill:#27ae60,stroke:#1e8449,color:#fff')
            else:
                lines.append(f'    style {cm_node_id} fill:#f8f9fa,stroke:#7f8c8d,color:#2c3e50')
    
    return '\n'.join(lines)
