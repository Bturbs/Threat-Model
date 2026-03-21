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
        """Generate global attack tree matching the reference design.

        Layout: graph LR (left-to-right).
        Structure: Model Title → Asset (blue) → Threat (CVSS-coloured) → Countermeasure (grey dashed).
        Threat label format: "Title | score Severity"
        Countermeasures use dashed edges and stadium shape, prefixed TODO/DONE.
        """
        lines = ['graph LR']

        # ── Build asset → threats mapping ────────────────────────────────────
        asset_threats: dict[str, list[Threat]] = {}
        for threat in self.model.threats:
            asset_id = self._find_asset_for_threat(threat)
            if asset_id:
                asset_threats.setdefault(asset_id, []).append(threat)

        # ── Model title root ──────────────────────────────────────────────────
        safe_title = (
            self.model.meta.title
            .replace('"', "'").replace('(', '').replace(')', '')
        )
        lines += [
            '',
            '    %% Model Root',
            f'    ROOT["{safe_title}"]',
        ]

        # ── Assets ────────────────────────────────────────────────────────────
        lines += ['', '    %% Assets']
        for asset_id in asset_threats:
            asset = self._asset_map.get(asset_id)
            if not asset:
                continue
            safe_name = asset.name.replace('"', "'").replace('(', '').replace(')', '')
            a_nid = f'A_{self._safe_id(asset_id)}'
            lines.append(f'    {a_nid}["{safe_name}"]')
            lines.append(f'    ROOT --> {a_nid}')
            lines.append(f'    style {a_nid} fill:#3498db,stroke:#2980b9,color:#fff')

        # ── Threats ───────────────────────────────────────────────────────────
        lines += ['', '    %% Threats']
        seen: set[str] = set()
        for asset_id, threats in asset_threats.items():
            a_nid = f'A_{self._safe_id(asset_id)}'
            for threat in threats:
                t_nid = f'T_{self._safe_id(threat.ID)}'
                cvss = self._get_cvss_score(threat)
                severity = (
                    'Critical' if cvss >= 9.0 else
                    'High'     if cvss >= 7.0 else
                    'Medium'   if cvss >= 4.0 else
                    'Low'
                )
                if t_nid not in seen:
                    safe_title = (
                        threat.title
                        .replace('"', "'")
                        .replace('(', '').replace(')', '')
                        .replace('[', '').replace(']', '')
                    )
                    label = f"{self._wrap_text(safe_title, 45)} | {cvss:.1f} {severity}"
                    lines.append(f'    {t_nid}["{label}"]')
                    if cvss >= 9.0:
                        lines.append(f'    style {t_nid} fill:#8B0000,stroke:#5c0000,color:#fff')
                    elif cvss >= 7.0:
                        lines.append(f'    style {t_nid} fill:#e74c3c,stroke:#c0392b,color:#fff')
                    elif cvss >= 4.0:
                        lines.append(f'    style {t_nid} fill:#f39c12,stroke:#d68910,color:#fff')
                    else:
                        lines.append(f'    style {t_nid} fill:#f1c40f,stroke:#d4ac0d,color:#2c3e50')
                    seen.add(t_nid)
                lines.append(f'    {a_nid} --> {t_nid}')

        # ── Countermeasures (dashed) ───────────────────────────────────────────
        lines += ['', '    %% Countermeasures']
        for threat in self.model.threats:
            t_nid = f'T_{self._safe_id(threat.ID)}'
            if t_nid not in seen:
                continue
            for cm in threat.countermeasures:
                cm_nid = f'CM_{self._safe_id(threat.ID)}_{self._safe_id(cm.ID)}'
                prefix = 'DONE' if cm.status == 'in_place' else 'TODO'
                safe_cm = (
                    cm.title
                    .replace('"', "'")
                    .replace('(', '').replace(')', '')
                    .replace('[', '').replace(']', '')
                )
                lines.append(f'    {cm_nid}(["{prefix}: {self._wrap_text(safe_cm, 38)}"])')
                lines.append(f'    {t_nid} -.-> {cm_nid}')
                if cm.status == 'in_place':
                    lines.append(f'    style {cm_nid} fill:#d5f5e3,stroke:#27ae60,color:#1e8449')
                else:
                    lines.append(f'    style {cm_nid} fill:#f2f3f4,stroke:#aab7b8,color:#555')

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
    """Generate a per-asset attack tree matching the global tree style.

    Layout: graph LR.
    Structure: Asset (blue) → Threat (CVSS-coloured, "Title | score Severity")
               Threat -.-> Countermeasure (grey dashed stadium, "TODO/DONE: title").
    """
    if not threats:
        return ''

    lines = ['graph LR']

    # ── Asset root ────────────────────────────────────────────────────────────
    safe_name = asset.name.replace('"', "'").replace('(', '').replace(')', '')
    asset_nid = f'ASSET_{asset.ID}'
    lines += [
        '',
        '    %% Asset Root',
        f'    {asset_nid}["{safe_name}"]',
        f'    style {asset_nid} fill:#3498db,stroke:#2980b9,color:#fff',
    ]

    # ── Threats ───────────────────────────────────────────────────────────────
    lines += ['', '    %% Threats']
    for threat in threats:
        t_nid = f'T_{threat.ID}'
        cvss = generator._get_cvss_score(threat)
        severity = (
            'Critical' if cvss >= 9.0 else
            'High'     if cvss >= 7.0 else
            'Medium'   if cvss >= 4.0 else
            'Low'
        )
        safe_title = (
            threat.title
            .replace('"', "'")
            .replace('(', '').replace(')', '')
            .replace('[', '').replace(']', '')
        )
        label = f"{generator._wrap_text(safe_title, 45)} | {cvss:.1f} {severity}"
        lines.append(f'    {t_nid}["{label}"]')
        lines.append(f'    {asset_nid} --> {t_nid}')
        if cvss >= 9.0:
            lines.append(f'    style {t_nid} fill:#8B0000,stroke:#5c0000,color:#fff')
        elif cvss >= 7.0:
            lines.append(f'    style {t_nid} fill:#e74c3c,stroke:#c0392b,color:#fff')
        elif cvss >= 4.0:
            lines.append(f'    style {t_nid} fill:#f39c12,stroke:#d68910,color:#fff')
        else:
            lines.append(f'    style {t_nid} fill:#f1c40f,stroke:#d4ac0d,color:#2c3e50')

    # ── Countermeasures (dashed) ──────────────────────────────────────────────────
    lines += ['', '    %% Countermeasures']
    for threat in threats:
        t_nid = f'T_{threat.ID}'
        for cm in threat.countermeasures:
            cm_nid = f'CM_{threat.ID}_{cm.ID}'
            prefix = 'DONE' if cm.status == 'in_place' else 'TODO'
            safe_cm = (
                cm.title
                .replace('"', "'")
                .replace('(', '').replace(')', '')
                .replace('[', '').replace(']', '')
            )
            lines.append(f'    {cm_nid}(["{prefix}: {generator._wrap_text(safe_cm, 38)}"])')
            lines.append(f'    {t_nid} -.-> {cm_nid}')
            if cm.status == 'in_place':
                lines.append(f'    style {cm_nid} fill:#d5f5e3,stroke:#27ae60,color:#1e8449')
            else:
                lines.append(f'    style {cm_nid} fill:#f2f3f4,stroke:#aab7b8,color:#555')

    return '\n'.join(lines)
